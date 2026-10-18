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
