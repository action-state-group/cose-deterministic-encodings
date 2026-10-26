// SPDX-License-Identifier: BSD-3-Clause

// Package detenc is a minimal, standard-library-only emitter and verifier for
// the deterministic-encodings Hash Envelope header parameter of
// draft-mih-sokolov-cose-deterministic-encodings.
//
// It builds the protected header and payload of a COSE Hash Envelope (RFC
// 9995) whose preimage is a structured value encoded under the Core
// Deterministic Encoding Requirements (RFC 8949 Section 4.2.1) or under
// cbor-binary64, and checks a content binding, reporting verified, failed or unverified as the draft's
// "Producer and Verifier Behavior" section specifies. Signing is out of scope.
//
// The header label is TBD_1 in the draft; 271 is the value it suggests to
// IANA and is the default here. It is not an assigned value.
package detenc

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// Header labels.
const (
	LabelAlg                    = 1
	LabelPayloadHashAlg         = 258
	LabelPreimageContentType    = 259
	LabelPayloadLocation        = 260
	LabelDeterministicEncodings = 271 // TBD_1, suggested value; not assigned
)

// Values of the COSE Deterministic Encodings registry.
const (
	CoreDeterministic = 1
	CBORBinary64      = 2
)

// Content-binding outcomes.
const (
	Verified   = "verified"
	Failed     = "failed"
	Unverified = "unverified"
)

// The structured value model. A decoded data item is one of: Int, []byte,
// string, []any (array), Map, Tag, bool, nil (null), float64, Simple.

// Int is a CBOR integer: N if !Neg, otherwise -1-N.
type Int struct {
	Neg bool
	N   uint64
}

// I returns the Int for v.
func I(v int64) Int {
	if v < 0 {
		return Int{Neg: true, N: uint64(-1 - v)}
	}
	return Int{N: uint64(v)}
}

// Pair is one map entry.
type Pair struct {
	Key, Value any
}

// Map is a CBOR map, in decoded order.
type Map []Pair

// Get returns the value for an integer key.
func (m Map) Get(key int64) (any, bool) {
	k := I(key)
	for _, p := range m {
		if ki, ok := p.Key.(Int); ok && ki == k {
			return p.Value, true
		}
	}
	return nil, false
}

// Tag is a tagged data item.
type Tag struct {
	Number uint64
	Value  any
}

// Simple is a simple value other than false, true and null.
type Simple uint8

var (
	ErrEncode = errors.New("detenc: cannot encode")
	ErrDecode = errors.New("detenc: malformed CBOR")
)

// --- Core Deterministic Encoding (RFC 8949 Section 4.2.1) ------------------

func head(buf *bytes.Buffer, major byte, arg uint64) {
	mt := major << 5
	switch {
	case arg < 24:
		buf.WriteByte(mt | byte(arg))
	case arg < 1<<8:
		buf.Write([]byte{mt | 24, byte(arg)})
	case arg < 1<<16:
		buf.WriteByte(mt | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(arg))
	case arg < 1<<32:
		buf.WriteByte(mt | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(arg))
	default:
		buf.WriteByte(mt | 27)
		_ = binary.Write(buf, binary.BigEndian, arg)
	}
}

// toHalf returns the binary16 bits of f when binary16 represents f exactly.
func toHalf(f float64) (uint16, bool) {
	f32 := float32(f)
	if float64(f32) != f {
		return 0, false
	}
	b := math.Float32bits(f32)
	sign := uint16(b>>16) & 0x8000
	exp := int((b>>23)&0xff) - 127
	mant := b & 0x7fffff
	switch {
	case math.IsInf(f, 0):
		return sign | 0x7c00, true
	case f == 0:
		return sign, true
	case exp >= -14 && exp <= 15:
		if mant&0x1fff != 0 {
			return 0, false
		}
		return sign | uint16(exp+15)<<10 | uint16(mant>>13), true
	case exp >= -24 && exp < -14:
		full := mant | 1<<23
		shift := uint(-(exp + 1))
		if full&(1<<shift-1) != 0 {
			return 0, false
		}
		return sign | uint16(full>>shift), true
	}
	return 0, false
}

func fromHalf(h uint16) float64 {
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1
	}
	exp := int(h>>10) & 0x1f
	mant := float64(h & 0x3ff)
	switch exp {
	case 0:
		return sign * math.Ldexp(mant, -24)
	case 31:
		if mant == 0 {
			return sign * math.Inf(1)
		}
		return math.NaN()
	}
	return sign * math.Ldexp(1+mant/1024, exp-15)
}

// encodeBinary64 is the float rule of cbor-binary64: every float as binary64,
// with NaN, the infinities and -0.0 outside the encoding.
func encodeBinary64(buf *bytes.Buffer, f float64) error {
	switch {
	case math.IsNaN(f), math.IsInf(f, 0):
		return fmt.Errorf("%w: NaN and the infinities are outside cbor-binary64", ErrEncode)
	case f == 0 && math.Signbit(f):
		return fmt.Errorf("%w: negative zero is outside cbor-binary64", ErrEncode)
	}
	buf.WriteByte(0xfb)
	return binary.Write(buf, binary.BigEndian, math.Float64bits(f))
}

func encodeFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) {
		return fmt.Errorf("%w: NaN is outside what this reference encodes", ErrEncode)
	}
	if h, ok := toHalf(f); ok {
		buf.WriteByte(0xf9)
		return binary.Write(buf, binary.BigEndian, h)
	}
	if f32 := float32(f); float64(f32) == f {
		buf.WriteByte(0xfa)
		return binary.Write(buf, binary.BigEndian, math.Float32bits(f32))
	}
	buf.WriteByte(0xfb)
	return binary.Write(buf, binary.BigEndian, math.Float64bits(f))
}

// floatRule encodes one floating-point value; it is what distinguishes the
// encodings this package implements.
type floatRule func(*bytes.Buffer, float64) error

// EncodeCoreDeterministic encodes v under RFC 8949 Section 4.2.1.
func EncodeCoreDeterministic(v any) ([]byte, error) {
	return encodeWith(v, encodeFloat)
}

// EncodeCBORBinary64 encodes v under cbor-binary64 (value 2): RFC 8949
// Section 4.2.1, except that every floating-point value is encoded as
// binary64, and NaN, the infinities and negative zero are rejected.
func EncodeCBORBinary64(v any) ([]byte, error) {
	return encodeWith(v, encodeBinary64)
}

// Encoder returns the encoder for a registry value, or nil.
func Encoder(encoding int64) func(any) ([]byte, error) {
	switch encoding {
	case CoreDeterministic:
		return EncodeCoreDeterministic
	case CBORBinary64:
		return EncodeCBORBinary64
	}
	return nil
}

func encodeWith(v any, fr floatRule) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, fr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any, fr floatRule) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xf6)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case Int:
		if x.Neg {
			head(buf, 1, x.N)
		} else {
			head(buf, 0, x.N)
		}
	case int:
		return encode(buf, I(int64(x)), fr)
	case float64:
		return fr(buf, x)
	case []byte:
		head(buf, 2, uint64(len(x)))
		buf.Write(x)
	case string:
		head(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []any:
		head(buf, 4, uint64(len(x)))
		for _, e := range x {
			if err := encode(buf, e, fr); err != nil {
				return err
			}
		}
	case Map:
		type kv struct{ k, v []byte }
		items := make([]kv, len(x))
		for i, p := range x {
			k, err := encodeWith(p.Key, fr)
			if err != nil {
				return err
			}
			val, err := encodeWith(p.Value, fr)
			if err != nil {
				return err
			}
			items[i] = kv{k, val}
		}
		// Bytewise lexicographic order of the encoded keys.
		sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].k, items[j].k) < 0 })
		for i := 1; i < len(items); i++ {
			if bytes.Equal(items[i-1].k, items[i].k) {
				return fmt.Errorf("%w: duplicate map key", ErrEncode)
			}
		}
		head(buf, 5, uint64(len(items)))
		for _, it := range items {
			buf.Write(it.k)
			buf.Write(it.v)
		}
	case Tag:
		head(buf, 6, x.Number)
		return encode(buf, x.Value, fr)
	case Simple:
		if x >= 24 && x <= 31 {
			return fmt.Errorf("%w: reserved simple value", ErrEncode)
		}
		head(buf, 7, uint64(x))
	default:
		return fmt.Errorf("%w: %T", ErrEncode, v)
	}
	return nil
}

// --- A small CBOR decoder --------------------------------------------------

// Decode decodes exactly one well-formed CBOR data item. Integers and floats
// stay distinct, maps decode to Map, and duplicate map keys are rejected.
func Decode(data []byte) (any, error) {
	v, n, err := decode(data, 0)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("%w: trailing octets", ErrDecode)
	}
	return v, nil
}

func take(data []byte, pos, n int) ([]byte, error) {
	if n < 0 || pos+n > len(data) || pos+n < pos {
		return nil, fmt.Errorf("%w: truncated", ErrDecode)
	}
	return data[pos : pos+n], nil
}

func decode(data []byte, pos int) (any, int, error) {
	b, err := take(data, pos, 1)
	if err != nil {
		return nil, 0, err
	}
	pos++
	major, ai := b[0]>>5, b[0]&0x1f
	if major == 7 && ai >= 25 && ai <= 27 {
		n := 1 << (ai - 24)
		raw, err := take(data, pos, n)
		if err != nil {
			return nil, 0, err
		}
		switch ai {
		case 25:
			return fromHalf(binary.BigEndian.Uint16(raw)), pos + n, nil
		case 26:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(raw))), pos + n, nil
		}
		return math.Float64frombits(binary.BigEndian.Uint64(raw)), pos + n, nil
	}
	var arg uint64
	indefinite := false
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 27:
		n := 1 << (ai - 24)
		raw, err := take(data, pos, n)
		if err != nil {
			return nil, 0, err
		}
		for _, c := range raw {
			arg = arg<<8 | uint64(c)
		}
		pos += n
	case ai == 31 && major >= 2 && major <= 5:
		indefinite = true
	default:
		return nil, 0, fmt.Errorf("%w: reserved additional information", ErrDecode)
	}
	atBreak := func() (bool, error) {
		c, err := take(data, pos, 1)
		if err != nil {
			return false, err
		}
		return c[0] == 0xff, nil
	}
	switch major {
	case 0:
		return Int{N: arg}, pos, nil
	case 1:
		return Int{Neg: true, N: arg}, pos, nil
	case 2, 3:
		var out []byte
		if indefinite {
			for {
				brk, err := atBreak()
				if err != nil {
					return nil, 0, err
				}
				if brk {
					pos++
					break
				}
				if data[pos]>>5 != major || data[pos]&0x1f == 31 {
					return nil, 0, fmt.Errorf("%w: bad chunk", ErrDecode)
				}
				chunk, np, err := decode(data, pos)
				if err != nil {
					return nil, 0, err
				}
				pos = np
				if major == 2 {
					out = append(out, chunk.([]byte)...)
				} else {
					out = append(out, chunk.(string)...)
				}
			}
		} else {
			if arg > uint64(len(data)) {
				return nil, 0, fmt.Errorf("%w: truncated", ErrDecode)
			}
			raw, err := take(data, pos, int(arg))
			if err != nil {
				return nil, 0, err
			}
			out = append([]byte{}, raw...)
			pos += int(arg)
		}
		if major == 2 {
			if out == nil {
				out = []byte{}
			}
			return out, pos, nil
		}
		if !utf8.Valid(out) {
			return nil, 0, fmt.Errorf("%w: invalid UTF-8", ErrDecode)
		}
		return string(out), pos, nil
	case 4, 5:
		var arr []any
		var m Map
		for count := uint64(0); ; count++ {
			if indefinite {
				brk, err := atBreak()
				if err != nil {
					return nil, 0, err
				}
				if brk {
					pos++
					break
				}
			} else if count == arg {
				break
			}
			item, np, err := decode(data, pos)
			if err != nil {
				return nil, 0, err
			}
			pos = np
			if major == 4 {
				arr = append(arr, item)
				continue
			}
			val, np, err := decode(data, pos)
			if err != nil {
				return nil, 0, err
			}
			pos = np
			m = append(m, Pair{item, val})
		}
		if major == 4 {
			if arr == nil {
				arr = []any{}
			}
			return arr, pos, nil
		}
		seen := map[string]bool{}
		for _, p := range m {
			k, err := EncodeCoreDeterministic(p.Key)
			if err != nil {
				return nil, 0, fmt.Errorf("%w: %v", ErrDecode, err)
			}
			if seen[string(k)] {
				return nil, 0, fmt.Errorf("%w: duplicate map key", ErrDecode)
			}
			seen[string(k)] = true
		}
		if m == nil {
			m = Map{}
		}
		return m, pos, nil
	case 6:
		inner, np, err := decode(data, pos)
		if err != nil {
			return nil, 0, err
		}
		return Tag{arg, inner}, np, nil
	}
	// major 7: simple values
	if ai == 24 && arg < 32 {
		return nil, 0, fmt.Errorf("%w: simple value below 32 in two octets", ErrDecode)
	}
	switch arg {
	case 20:
		return false, pos, nil
	case 21:
		return true, pos, nil
	case 22:
		return nil, pos, nil
	}
	return Simple(arg), pos, nil
}

// --- Applicable Content Types (the draft's consistency check) -----------

var coreDeterministicMediaTypes = map[string]bool{
	"application/cbor":           true,
	"application/cbor-seq":       true,
	"application/cose":           true,
	"application/cose-key":       true,
	"application/cose-key-set":   true,
	"application/cose-x509":      true,
	"application/cwt":            true,
	"application/multipart-core": true,
}

var coreDeterministicSuffixes = map[string]bool{
	"+cbor": true, "+cbor-seq": true, "+cose": true, "+cwt": true, "+sd-cwt": true,
}

// ContentFormats is a subset of the CoAP Content-Formats registry: numbers
// assigned to a media type with no content coding. A number not listed is
// not matched.
var ContentFormats = map[uint64]string{
	16:  "application/cose", // cose-type="cose-encrypt0"
	17:  "application/cose", // cose-type="cose-mac0"
	18:  "application/cose", // cose-type="cose-sign1"
	50:  "application/json",
	60:  "application/cbor",
	61:  "application/cwt",
	62:  "application/multipart-core",
	63:  "application/cbor-seq",
	96:  "application/cose", // cose-type="cose-encrypt"
	97:  "application/cose", // cose-type="cose-mac"
	98:  "application/cose", // cose-type="cose-sign"
	101: "application/cose-key",
	102: "application/cose-key-set",
	258: "application/swid+cbor",
}

// ContentTypeMatches reports whether a 259 value matches the Applicable
// Content Types of the encoding. Values 1 and 2 list the same ones.
func ContentTypeMatches(encoding int64, contentType any) bool {
	if encoding != CoreDeterministic && encoding != CBORBinary64 {
		return false
	}
	var media string
	switch ct := contentType.(type) {
	case Int:
		if ct.Neg {
			return false
		}
		m, ok := ContentFormats[ct.N]
		if !ok {
			return false
		}
		media = m
	case string:
		media = ct
	default:
		return false
	}
	media = strings.ToLower(strings.TrimSpace(strings.SplitN(media, ";", 2)[0]))
	if coreDeterministicMediaTypes[media] {
		return true
	}
	slash := strings.IndexByte(media, '/')
	if slash < 0 {
		return false
	}
	subtype := media[slash+1:]
	plus := strings.LastIndexByte(subtype, '+')
	return plus > 0 && coreDeterministicSuffixes[subtype[plus:]]
}

// --- Emitter and verifier --------------------------------------------------

func hasher(alg int64) func() hash.Hash {
	switch alg {
	case -16:
		return sha256.New
	case -43:
		return sha512.New384
	case -44:
		return sha512.New
	}
	return nil
}

func digest(alg int64, data []byte) []byte {
	h := hasher(alg)()
	h.Write(data)
	return h.Sum(nil)
}

// Emitted is the result of Emit.
type Emitted struct {
	Preimage, Payload, Protected []byte
}

// Emit encodes value with core-deterministic, hashes it with hashAlg, and
// builds the serialized protected header (alg, 258, 259 and label).
func Emit(value any, contentType any, alg, hashAlg int64, label int64) (*Emitted, error) {
	return EmitEncoding(value, contentType, alg, hashAlg, CoreDeterministic, label)
}

// EmitEncoding is Emit with the encoding given as a registry value.
func EmitEncoding(value any, contentType any, alg, hashAlg, encoding int64, label int64) (*Emitted, error) {
	if hasher(hashAlg) == nil {
		return nil, fmt.Errorf("detenc: hash algorithm %d not implemented", hashAlg)
	}
	enc := Encoder(encoding)
	if enc == nil {
		return nil, fmt.Errorf("detenc: encoding %d not implemented", encoding)
	}
	if !ContentTypeMatches(encoding, contentType) {
		// Consistency with preimage-content-type: a producer MUST NOT emit this pairing.
		return nil, errors.New("detenc: content type is not an Applicable Content Type of the encoding")
	}
	pre, err := enc(value)
	if err != nil {
		return nil, err
	}
	prot, err := EncodeCoreDeterministic(Map{
		{I(LabelAlg), I(alg)},
		{I(LabelPayloadHashAlg), I(hashAlg)},
		{I(LabelPreimageContentType), contentType},
		{I(label), I(encoding)},
	})
	if err != nil {
		return nil, err
	}
	return &Emitted{pre, digest(hashAlg, pre), prot}, nil
}

// Held is the content a verifier holds: the preimage, a structured value,
// or neither.
type Held struct {
	Preimage []byte // nil when not held
	Value    any
	HasValue bool
}

// Result is a content-binding outcome and a short reason code.
type Result struct {
	Outcome, Reason string
}

func smallInt(v any) (int64, bool) {
	i, ok := v.(Int)
	if !ok || i.N > math.MaxInt64 {
		return 0, false
	}
	if i.Neg {
		return -1 - int64(i.N), true
	}
	return int64(i.N), true
}

// Verify checks the content binding of a Hash Envelope. protected is the
// serialized protected header map. Signature validity is not checked.
func Verify(protected, payload []byte, held Held, label int64) (Result, error) {
	hv, err := Decode(protected)
	if err != nil {
		return Result{}, err
	}
	header, ok := hv.(Map)
	if !ok {
		return Result{}, fmt.Errorf("%w: protected header is not a map", ErrDecode)
	}
	encRaw, hasEncoding := header.Get(label)
	ctype, hasCtype := header.Get(LabelPreimageContentType)
	enc, isInt := smallInt(encRaw)
	recognized := hasEncoding && isInt && Encoder(enc) != nil

	// Consistency with preimage-content-type: this check comes first.
	if hasEncoding {
		if !hasCtype {
			return Result{Failed, "content-type-absent"}, nil
		}
		if recognized && !ContentTypeMatches(enc, ctype) {
			return Result{Failed, "content-type-mismatch"}, nil
		}
	}

	hashRaw, _ := header.Get(LabelPayloadHashAlg)
	hashAlg, ok := smallInt(hashRaw)
	implemented := ok && hasher(hashAlg) != nil

	// RFC 9995 Section 5.3: a held preimage needs no encoding information.
	if held.Preimage != nil {
		if !implemented {
			return Result{Unverified, "hash-alg-not-implemented"}, nil
		}
		if bytes.Equal(digest(hashAlg, held.Preimage), payload) {
			return Result{Verified, "preimage-digest-match"}, nil
		}
		return Result{Failed, "preimage-digest-mismatch"}, nil
	}
	if !held.HasValue {
		return Result{Unverified, "no-content"}, nil
	}
	if !hasEncoding {
		return Result{Unverified, "encoding-absent"}, nil
	}
	if !recognized {
		return Result{Unverified, "encoding-not-implemented"}, nil
	}
	if !implemented {
		return Result{Unverified, "hash-alg-not-implemented"}, nil
	}
	pre, err := Encoder(enc)(held.Value)
	if err != nil {
		return Result{Unverified, "value-not-encodable"}, nil
	}
	if bytes.Equal(digest(hashAlg, pre), payload) {
		return Result{Verified, "recreated-digest-match"}, nil
	}
	return Result{Failed, "recreated-digest-mismatch"}, nil
}

// Conforms reports whether preimage is exactly what the encoding produces for
// the value it decodes to: the check of stored content the draft's Security
// Considerations ask of a producer before hashing. It accepts or rejects; for
// content that passes, the octets it would hash are the octets the encoding
// produces.
func Conforms(preimage []byte, encoding int64) bool {
	enc := Encoder(encoding)
	if enc == nil {
		return false
	}
	v, err := Decode(preimage)
	if err != nil {
		return false
	}
	out, err := enc(v)
	return err == nil && bytes.Equal(out, preimage)
}
