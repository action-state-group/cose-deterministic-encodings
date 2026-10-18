// SPDX-License-Identifier: BSD-3-Clause

package detenc

import (
	"encoding/hex"
	"encoding/json"
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
	src, err := os.ReadFile("../../draft-mih-sokolov-cose-deterministic-encodings-00.md")
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
		t.Fatal("emitted core-deterministic with application/json")
	}
}
