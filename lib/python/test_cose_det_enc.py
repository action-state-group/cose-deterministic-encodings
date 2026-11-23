# SPDX-License-Identifier: BSD-3-Clause
"""Run the shared vectors, and tie them to the draft text.

    python3 -m unittest discover -s lib/python
"""

from __future__ import annotations

import json
import re
import struct
import unittest
from pathlib import Path

import cose_det_enc as c

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "vectors" / "vectors.json").read_text())
DRAFT = (ROOT / "draft-mih-sokolov-cose-deterministic-encodings-04.md").read_text()
# The URL that -02 listed for RFC 8949 Section 4.2.1; -03 identifies that
# encoding by the integer 1.
URL_02 = "https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1"


def phrase(text: str) -> str:
    """A regular expression for text, with any whitespace between its words."""
    return r"\s+".join(re.escape(w) for w in text.split())


class DraftExample(unittest.TestCase):
    def test_example_matches_draft_text(self):
        # The preimage and digest are read from the draft's Examples section, so
        # a change to either side of the pair fails here.
        m = re.search(r"7-octet preimage\s+`([0-9a-f]+)`, whose SHA-256 digest is\s+`([0-9a-f]{64})`",
                      DRAFT)
        self.assertIsNotNone(m, "example preimage/digest not found in the draft")
        preimage, digest = m.group(1), m.group(2)
        case = next(e for e in VECTORS["emit"] if e["id"] == "emit-draft-example")
        self.assertEqual(case["expected"]["preimage"], preimage)
        self.assertEqual(case["expected"]["payload"], digest)
        e = c.emit(c.decode(bytes.fromhex(case["value_cbor"])), "application/cbor")
        self.assertEqual(e.preimage.hex(), preimage)
        self.assertEqual(e.payload.hex(), digest)


class Vectors(unittest.TestCase):
    def test_emit(self):
        for case in VECTORS["emit"]:
            with self.subTest(case["id"]):
                e = c.emit(c.decode(bytes.fromhex(case["value_cbor"])), case["content_type"],
                           hash_alg=case["hash_alg"], label=VECTORS["header_label"])
                self.assertEqual(e.preimage.hex(), case["expected"]["preimage"])
                self.assertEqual(e.payload.hex(), case["expected"]["payload"])
                self.assertEqual(e.protected.hex(), case["expected"]["protected"])

    def test_verify(self):
        for case in VECTORS["verify"]:
            with self.subTest(case["id"]):
                value = case.get("value_cbor")
                got = c.verify(bytes.fromhex(case["protected"]), bytes.fromhex(case["payload"]),
                               preimage=bytes.fromhex(case["preimage"]) if "preimage" in case else None,
                               value=c.decode(bytes.fromhex(value)) if value else None,
                               has_value=value is not None, label=VECTORS["header_label"])
                self.assertEqual(got.outcome, case["expected"]["outcome"])
                self.assertEqual(got.reason, case["expected"]["reason"])

    def test_reject(self):
        for case in VECTORS["reject"]:
            with self.subTest(case["id"]):
                value = c.decode(bytes.fromhex(case["value_cbor"]))
                with self.assertRaises(c.EncodeError):
                    c.emit(value, case["content_type"], hash_alg=case["hash_alg"],
                           label=VECTORS["header_label"])

    def test_every_outcome_is_covered(self):
        outcomes = {v["expected"]["outcome"] for v in VECTORS["verify"]}
        self.assertEqual(outcomes, {c.VERIFIED, c.FAILED})


class Producer(unittest.TestCase):
    def test_refuses_json_pairing(self):
        # Consistency with preimage-content-type: a producer MUST NOT pair the integer 1 with application/json.
        with self.assertRaises(ValueError):
            c.emit({"a": 1}, "application/json")

    def test_refuses_values_other_than_1(self):
        for other in (True, 1.0, URL_02, "dtrm", 2):
            with self.subTest(repr(other)), self.assertRaises(ValueError):
                c.emit({"a": 1}, "application/cbor", encoding=other)

    def test_header_value_is_the_integer_1(self):
        e = c.emit({"a": 1}, "application/cbor")
        got = c.decode(e.protected).get(c.LABEL_DETERMINISTIC_ENCODINGS)
        self.assertIs(type(got), int)
        self.assertEqual(got, 1)
        # Label 271 (19 01 0f) sorts last; its value is the 1-byte integer 01.
        self.assertEqual(e.protected[-4:].hex(), "19010f01")

    def test_value_matches_draft_text(self):
        # The CDDL and the example in the draft carry the integer 1.
        self.assertRegex(DRAFT, phrase("? &(deterministic_encodings: TBD_1) => 1 / tstr,"))
        m = re.search(r"/ deterministic encodings / TBD_1: (\S+?),", DRAFT)
        self.assertIsNotNone(m, "example header line not found in the draft")
        self.assertEqual(m.group(1), str(c.CORE_DETERMINISTIC))

    def test_sizes_match_draft_text(self):
        # The draft compares the integer with the URL that -02 listed.
        m = re.search(phrase("The integer takes") + r"\s+(\d+)\s+" + phrase("byte; the URL of that section on "
                      "the RFC Editor's site would take") + r"\s+(\d+)\s+bytes", DRAFT)
        self.assertIsNotNone(m, "size sentence not found in the draft")
        self.assertEqual(int(m.group(1)), len(c.encode_core_deterministic(c.CORE_DETERMINISTIC)))
        self.assertEqual(int(m.group(2)), len(c.encode_core_deterministic(URL_02)))

    def test_dtrm_text_not_recognized(self):
        # The text string "dtrm" an -01 producer writes is not the integer 1.
        self.assertFalse(c.is_implemented("dtrm"))
        self.assertFalse(c.content_type_matches("dtrm", "application/cbor"))


def _f64(bits: int) -> float:
    return struct.unpack(">d", bits.to_bytes(8, "big"))[0]


class NaN(unittest.TestCase):
    # This reference emits one NaN, 0xf97e00, and rejects every other.

    def test_one_nan_emitted(self):
        # The vectors emit-nan and emit-nan-binary64, plus the binary32 form.
        for given in ("a16178f97e00", "a16178fa7fc00000", "a16178fb7ff8000000000000"):
            with self.subTest(given):
                e = c.emit(c.decode(bytes.fromhex(given)), "application/cbor")
                self.assertEqual(e.preimage.hex(), "a16178f97e00")

    def test_non_trivial_nan_rejected(self):
        # The four reject vectors, plus binary32 forms of each kind.
        for given in ("f97e01", "f97c01", "f9fe00", "fb7ff8000000000001",
                      "fa7fc00001", "fa7f800001", "faffc00000", "fbfff8000000000000",
                      "fb7ff0000000000001", "f9fe01"):
            with self.subTest(given):
                v = c.decode(bytes.fromhex("a16178" + given))
                with self.assertRaises(c.EncodeError):
                    c.emit(v, "application/cbor")

    def test_decided_from_the_bits_not_the_float(self):
        # What struct.unpack(">e", 7e01) returns depends on the Python version:
        # before 3.14 the bits 7ff8000000000000, where the payload is gone and
        # the float alone would look like the one NaN; from 3.14 the bits
        # 7ff8040000000000.  The decoder does not depend on it.
        got = c.decode(bytes.fromhex("f97e01"))
        self.assertIsInstance(got, c.NonTrivialNaN)
        self.assertEqual(got.encoded.hex(), "f97e01")
        trivial = c.decode(bytes.fromhex("f97e00"))
        self.assertIsInstance(trivial, float)
        self.assertEqual(struct.pack(">d", trivial).hex(), "7ff8000000000000")

    def test_float_nan_by_bit_pattern(self):
        self.assertEqual(c.encode_core_deterministic(_f64(0x7FF8000000000000)).hex(), "f97e00")
        for bits in (0xFFF8000000000000, 0x7FF8000000000001, 0x7FF0000000000001):
            with self.subTest(hex(bits)), self.assertRaises(c.EncodeError):
                c.encode_core_deterministic(_f64(bits))

    def test_verifier_holding_non_trivial_nan(self):
        # The value cannot be re-encoded: the check fails.
        ok = c.emit({"a": 1}, "application/cbor")
        got = c.verify(ok.protected, ok.payload, value=c.decode(bytes.fromhex("a16178f97e01")),
                       has_value=True)
        self.assertEqual((got.outcome, got.reason), (c.FAILED, "value-not-encodable"))


class Floats(unittest.TestCase):
    def test_shortest_form(self):
        # The same table as the Go test, TestHalfFloats.
        for f, want in [(1.5, "f93e00"), (0.0, "f90000"), (65504.0, "f97bff"),
                        (5.960464477539063e-08, "f90001"), (6.103515625e-05, "f90400"),
                        (100000.0, "fa47c35000"), (1.1, "fb3ff199999999999a"), (-4.0, "f9c400"),
                        (3.0517578125e-05, "f90200")]:
            with self.subTest(f):
                b = c.encode_core_deterministic(f)
                self.assertEqual(b.hex(), want)
                self.assertEqual(c.decode(b), f)


class Verifier(unittest.TestCase):
    def test_only_the_integer_1_is_implemented(self):
        self.assertTrue(c.is_implemented(1))
        self.assertTrue(c.content_type_matches(1, "application/cbor"))
        # true and 1.0 compare equal to 1 in Python, but are other CBOR data items.
        for other in (True, 1.0, "1", URL_02, "dtrm", 2, 0, -1, None, b"\x01"):
            with self.subTest(repr(other)):
                self.assertFalse(c.is_implemented(other))
                self.assertFalse(c.content_type_matches(other, "application/cbor"))

    def test_url_02_ignored(self):
        # The URL that -02 listed is not the integer 1: the verifier ignores it, and
        # holding only a value it has no preimage to hash, so the check fails.
        ok = c.emit({"a": 1}, "application/cbor")
        prot = c.encode_core_deterministic({1: -7, 258: -16, 259: "application/cbor",
                                            c.LABEL_DETERMINISTIC_ENCODINGS: URL_02})
        got = c.verify(prot, ok.payload, value={"a": 1}, has_value=True)
        self.assertEqual((got.outcome, got.reason), (c.FAILED, "encoding-not-implemented"))
        got = c.verify(prot, ok.payload, preimage=ok.preimage)
        self.assertEqual((got.outcome, got.reason), (c.VERIFIED, "preimage-digest-match"))


class Decoder(unittest.TestCase):
    def test_rejects_duplicate_keys(self):
        with self.assertRaises(c.DecodeError):
            c.decode(bytes.fromhex("a2616101616102"))

    def test_rejects_trailing_octets(self):
        with self.assertRaises(c.DecodeError):
            c.decode(bytes.fromhex("0100"))

    def test_rejects_truncation(self):
        with self.assertRaises(c.DecodeError):
            c.decode(bytes.fromhex("6261"))

    def test_rejects_reserved(self):
        for bad in ("f818", "1c"):
            with self.subTest(bad), self.assertRaises(c.DecodeError):
                c.decode(bytes.fromhex(bad))

    def test_int_and_float_keys_stay_distinct(self):
        # 1 and 1.0 are different data items; both may be keys of one map.
        m = c.decode(bytes.fromhex("a201f5f93c00f4"))
        self.assertEqual(c.encode_structured(m).hex(), "a201f5f93c00f4")


if __name__ == "__main__":
    unittest.main()
