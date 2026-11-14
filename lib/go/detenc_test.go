// SPDX-License-Identifier: BSD-3-Clause

package detenc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"regexp"
	"testing"
)

type vectors struct {
	HeaderLabel int64 `json:"header_label"`
	Emit        []struct {
		ID          string          `json:"id"`
		ValueCBOR   string          `json:"value_cbor"`
		ContentType json.RawMessage `json:"content_type"`
		HashAlg     int64           `json:"hash_alg"`
		Expected    struct {
			Preimage, Payload, Protected string
		} `json:"expected"`
	} `json:"emit"`
	Reject []struct {
		ID          string          `json:"id"`
		ValueCBOR   string          `json:"value_cbor"`
		ContentType json.RawMessage `json:"content_type"`
		HashAlg     int64           `json:"hash_alg"`
	} `json:"reject"`
	Verify []struct {
		ID        string  `json:"id"`
		Protected string  `json:"protected"`
		Payload   string  `json:"payload"`
		Preimage  *string `json:"preimage"`
		ValueCBOR *string `json:"value_cbor"`
		Expected  struct {
			Outcome, Reason string
		} `json:"expected"`
	} `json:"verify"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contentType(t *testing.T, raw json.RawMessage) any {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	return Int{N: n}
}

func TestEmitVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Emit {
		t.Run(c.ID, func(t *testing.T) {
			val, err := Decode(unhex(t, c.ValueCBOR))
			if err != nil {
				t.Fatal(err)
			}
			e, err := Emit(val, contentType(t, c.ContentType), -7, c.HashAlg, v.HeaderLabel)
			if err != nil {
				t.Fatal(err)
			}
			for name, pair := range map[string][2]string{
				"preimage":  {hex.EncodeToString(e.Preimage), c.Expected.Preimage},
				"payload":   {hex.EncodeToString(e.Payload), c.Expected.Payload},
				"protected": {hex.EncodeToString(e.Protected), c.Expected.Protected},
			} {
				if pair[0] != pair[1] {
					t.Errorf("%s = %s, want %s", name, pair[0], pair[1])
				}
			}
		})
	}
}

func TestRejectVectors(t *testing.T) {
	v := load(t)
	if len(v.Reject) == 0 {
		t.Fatal("no reject vectors")
	}
	for _, c := range v.Reject {
		t.Run(c.ID, func(t *testing.T) {
			val, err := Decode(unhex(t, c.ValueCBOR))
			if err != nil {
				t.Fatal(err)
			}
			e, err := Emit(val, contentType(t, c.ContentType), -7, c.HashAlg, v.HeaderLabel)
			if !errors.Is(err, ErrEncode) {
				t.Fatalf("got %v, %v; want an ErrEncode error", e, err)
			}
		})
	}
}

func TestVerifyVectors(t *testing.T) {
	v := load(t)
	for _, c := range v.Verify {
		t.Run(c.ID, func(t *testing.T) {
			var held Held
			if c.Preimage != nil {
				held.Preimage = unhex(t, *c.Preimage)
			}
			if c.ValueCBOR != nil {
				val, err := Decode(unhex(t, *c.ValueCBOR))
				if err != nil {
					t.Fatal(err)
				}
				held.Value, held.HasValue = val, true
			}
			got, err := Verify(unhex(t, c.Protected), unhex(t, c.Payload), held, v.HeaderLabel)
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome != c.Expected.Outcome || got.Reason != c.Expected.Reason {
				t.Errorf("got %s/%s, want %s/%s", got.Outcome, got.Reason, c.Expected.Outcome, c.Expected.Reason)
			}
		})
	}
}

// The draft's example digest, read from the draft text.
func TestDraftExample(t *testing.T) {
	src, err := os.ReadFile("../../draft-mih-sokolov-cose-deterministic-encodings-01.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("7-octet preimage\\s+`([0-9a-f]+)`, whose SHA-256 digest is\\s+`([0-9a-f]{64})`").FindSubmatch(src)
	if m == nil {
		t.Fatal("example preimage/digest not found in the draft")
	}
	val := Map{{"b", I(2)}, {"a", I(1)}}
	e, err := Emit(val, "application/cbor", -7, -16, LabelDeterministicEncodings)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(e.Preimage) != string(m[1]) || hex.EncodeToString(e.Payload) != string(m[2]) {
		t.Fatalf("got %x / %x, draft says %s / %s", e.Preimage, e.Payload, m[1], m[2])
	}
}

func TestHalfFloats(t *testing.T) {
	for _, c := range []struct {
		f    float64
		want string
	}{
		{1.5, "f93e00"}, {0, "f90000"}, {65504, "f97bff"}, {5.960464477539063e-08, "f90001"},
		{6.103515625e-05, "f90400"}, {100000, "fa47c35000"}, {1.1, "fb3ff199999999999a"},
		{-4, "f9c400"}, {3.0517578125e-05, "f90200"},
	} {
		b, err := EncodeCoreDeterministic(c.f)
		if err != nil || hex.EncodeToString(b) != c.want {
			t.Errorf("%v: got %x, want %s", c.f, b, c.want)
		}
		back, err := Decode(b)
		if err != nil || back.(float64) != c.f {
			t.Errorf("%v: round trip gave %v", c.f, back)
		}
	}
}

func TestDecoderRejects(t *testing.T) {
	for _, h := range []string{"a2616101616102", "0100", "6261", "f818", "1c"} {
		if _, err := Decode(unhex(t, h)); err == nil {
			t.Errorf("%s: decoded, want error", h)
		}
	}
}

func TestProducerRefusesJSON(t *testing.T) {
	if _, err := Emit(Map{{"a", I(1)}}, "application/json", -7, -16, LabelDeterministicEncodings); err == nil {
		t.Fatal("emitted \"dtrm\" with application/json")
	}
}

func TestHeaderValueIsTextString(t *testing.T) {
	e, err := Emit(Map{{"a", I(1)}}, "application/cbor", -7, -16, LabelDeterministicEncodings)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Decode(e.Protected)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := h.(Map).Get(LabelDeterministicEncodings); got != "dtrm" {
		t.Fatalf("header value %#v, want \"dtrm\"", got)
	}
}

// The integer 1 an -00 producer writes is not "dtrm": unverified, never failed.
func TestHeaderInteger1NotRecognized(t *testing.T) {
	prot, err := EncodeCoreDeterministic(Map{
		{I(LabelAlg), I(-7)}, {I(LabelPayloadHashAlg), I(-16)},
		{I(LabelPreimageContentType), "application/json"}, {I(LabelDeterministicEncodings), I(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(prot, make([]byte, 32), Held{Value: Map{{"a", I(1)}}, HasValue: true}, LabelDeterministicEncodings)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Result{Unverified, "encoding-not-implemented"}) {
		t.Fatalf("got %v", got)
	}
}

// "dtrm" emits one NaN, 0xf97e00; the vectors emit-nan and emit-nan-binary64,
// plus the binary32 form.
func TestOneNaNEmitted(t *testing.T) {
	for _, given := range []string{"a16178f97e00", "a16178fa7fc00000", "a16178fb7ff8000000000000"} {
		val, err := Decode(unhex(t, given))
		if err != nil {
			t.Fatal(err)
		}
		e, err := Emit(val, "application/cbor", -7, -16, LabelDeterministicEncodings)
		if err != nil || hex.EncodeToString(e.Preimage) != "a16178f97e00" {
			t.Errorf("%s: got %v, %v", given, e, err)
		}
	}
}

// Every other NaN is rejected; the four reject vectors, plus binary32 forms.
func TestNonTrivialNaNRejected(t *testing.T) {
	for _, given := range []string{"f97e01", "f97c01", "f9fe00", "fb7ff8000000000001",
		"fa7fc00001", "fa7f800001", "faffc00000", "fbfff8000000000000",
		"fb7ff0000000000001", "f9fe01"} {
		val, err := Decode(unhex(t, "a16178"+given))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Emit(val, "application/cbor", -7, -16, LabelDeterministicEncodings); !errors.Is(err, ErrEncode) {
			t.Errorf("%s: got %v, want an ErrEncode error", given, err)
		}
	}
}

// fromHalf returns math.NaN() for every NaN half, and math.NaN() is
// 0x7FF8000000000001: a bit check after decoding would call f97e00
// non-trivial. The decoder decides from the encoded bits instead.
func TestNaNDecidedFromTheBits(t *testing.T) {
	if bits := math.Float64bits(fromHalf(0x7e00)); bits == qNaNBits64 {
		t.Fatalf("fromHalf(0x7e00) has bits %#x; the trap this test documents is gone", bits)
	}
	v, err := Decode(unhex(t, "f97e00"))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := v.(float64); !ok || math.Float64bits(f) != qNaNBits64 {
		t.Fatalf("f97e00 decoded to %#v", v)
	}
	v, err = Decode(unhex(t, "f97e01"))
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := v.(NonTrivialNaN); !ok || hex.EncodeToString(n) != "f97e01" {
		t.Fatalf("f97e01 decoded to %#v", v)
	}
}

func TestFloatNaNByBitPattern(t *testing.T) {
	b, err := EncodeCoreDeterministic(math.Float64frombits(qNaNBits64))
	if err != nil || hex.EncodeToString(b) != "f97e00" {
		t.Errorf("0x7ff8000000000000: got %x, %v", b, err)
	}
	for _, bits := range []uint64{0xfff8000000000000, 0x7ff8000000000001, 0x7ff0000000000001} {
		if _, err := EncodeCoreDeterministic(math.Float64frombits(bits)); !errors.Is(err, ErrEncode) {
			t.Errorf("%#x: got %v, want an ErrEncode error", bits, err)
		}
	}
	if _, err := EncodeCoreDeterministic(math.NaN()); !errors.Is(err, ErrEncode) {
		t.Errorf("math.NaN(): got %v, want an ErrEncode error", err)
	}
}

// A verifier holding a value with a non-trivial NaN cannot re-encode it:
// unverified, not failed.
func TestVerifierHoldingNonTrivialNaN(t *testing.T) {
	e, err := Emit(Map{{"a", I(1)}}, "application/cbor", -7, -16, LabelDeterministicEncodings)
	if err != nil {
		t.Fatal(err)
	}
	val, err := Decode(unhex(t, "a16178f97e01"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(e.Protected, e.Payload, Held{Value: val, HasValue: true}, LabelDeterministicEncodings)
	if err != nil || got != (Result{Unverified, "value-not-encodable"}) {
		t.Fatalf("got %v, %v", got, err)
	}
}
