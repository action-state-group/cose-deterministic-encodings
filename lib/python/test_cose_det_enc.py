# SPDX-License-Identifier: BSD-3-Clause
"""Run the shared vectors, and tie them to the draft text.

    python3 -m unittest discover -s lib/python
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import cose_det_enc as c

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "vectors" / "vectors.json").read_text())
DRAFT = (ROOT / "draft-mih-sokolov-cose-deterministic-encodings-00.md").read_text()


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

    def test_binary64_example_matches_draft_text(self):
        m = re.search(r"12-octet preimage\s+`([0-9a-f]+)`, whose SHA-256 digest is\s+`([0-9a-f]{64})`",
                      DRAFT)
        self.assertIsNotNone(m, "cbor-binary64 example preimage/digest not found in the draft")
        preimage, digest = m.group(1), m.group(2)
        case = next(e for e in VECTORS["emit"] if e["id"] == "emit-b64-draft-example")
        self.assertEqual(case["expected"]["preimage"], preimage)
        self.assertEqual(case["expected"]["payload"], digest)
        e = c.emit({"x": 1.5}, "application/cbor", encoding=c.CBOR_BINARY64)
        self.assertEqual(e.preimage.hex(), preimage)
        self.assertEqual(e.payload.hex(), digest)


class Vectors(unittest.TestCase):
    def test_emit(self):
        for case in VECTORS["emit"]:
            with self.subTest(case["id"]):
                e = c.emit(c.decode(bytes.fromhex(case["value_cbor"])), case["content_type"],
                           hash_alg=case["hash_alg"], encoding=case.get("encoding", 1),
                           label=VECTORS["header_label"])
                self.assertEqual(e.preimage.hex(), case["expected"]["preimage"])
                self.assertEqual(e.payload.hex(), case["expected"]["payload"])
                self.assertEqual(e.protected.hex(), case["expected"]["protected"])

    def test_emit_reject(self):
        for case in VECTORS["emit_reject"]:
            with self.subTest(case["id"]), self.assertRaises(c.EncodeError):
                c.emit(c.decode(bytes.fromhex(case["value_cbor"])), case["content_type"],
                       encoding=case["encoding"], label=VECTORS["header_label"])

    def test_conformance(self):
        for case in VECTORS["conformance"]:
            with self.subTest(case["id"]):
                preimage = bytes.fromhex(case["preimage"])
                want = case["expected"]
                self.assertIs(c.conforms(preimage, case["encoding"]), want["conforms"])
                try:
                    recreated = c.ENCODINGS[case["encoding"]](c.decode(preimage)).hex()
                except c.EncodeError:
                    recreated = None
                self.assertEqual(recreated, want["recreated"])
                # Strict check and value rule agree: content that passes is hashed as is.
                self.assertEqual(want["conforms"], recreated == case["preimage"])

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

    def test_every_outcome_is_covered(self):
        outcomes = {v["expected"]["outcome"] for v in VECTORS["verify"]}
        self.assertEqual(outcomes, {c.VERIFIED, c.FAILED, c.UNVERIFIED})


class Producer(unittest.TestCase):
    def test_refuses_json_pairing(self):
        # Consistency with preimage-content-type: a producer MUST NOT pair core-deterministic with application/json.
        with self.assertRaises(ValueError):
            c.emit({"a": 1}, "application/json")

    def test_refuses_nan(self):
        with self.assertRaises(c.EncodeError):
            c.encode_core_deterministic(float("nan"))

    def test_binary64_refuses_json_pairing(self):
        with self.assertRaises(ValueError):
            c.emit({"a": 1.5}, "application/json", encoding=c.CBOR_BINARY64)

    def test_unknown_encoding_does_not_conform(self):
        self.assertFalse(c.conforms(bytes.fromhex("01"), 99))


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

    def test_binary64(self):
        # The same table as the Go test, TestBinary64Floats.
        for f, want in [(1.5, "fb3ff8000000000000"), (0.0, "fb0000000000000000"),
                        (1.0, "fb3ff0000000000000"), (65504.0, "fb40effc0000000000"),
                        (5.960464477539063e-08, "fb3e70000000000000"),
                        (100000.0, "fb40f86a0000000000"), (1.1, "fb3ff199999999999a"),
                        (-4.0, "fbc010000000000000")]:
            with self.subTest(f):
                b = c.encode_cbor_binary64(f)
                self.assertEqual(b.hex(), want)
                self.assertEqual(c.decode(b), f)

    def test_binary64_keeps_integers(self):
        self.assertEqual(c.encode_cbor_binary64([1, -1, 1000]).hex(), "830120" + "1903e8")

    def test_binary64_rejects(self):
        for f in (float("nan"), float("inf"), float("-inf"), -0.0):
            with self.subTest(f), self.assertRaises(c.EncodeError):
                c.encode_cbor_binary64(f)


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
