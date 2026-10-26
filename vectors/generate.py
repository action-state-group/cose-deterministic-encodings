# SPDX-License-Identifier: BSD-3-Clause
"""Generate vectors/vectors.json from the case definitions below.

    python3 vectors/generate.py          # rewrite vectors.json
    python3 vectors/generate.py --check  # exit 1 if vectors.json is stale

Every octet string the draft itself states is asserted here as a literal, so
the vectors cannot drift from the text.  Header label 271 is the value the
draft suggests for TBD_1; it is not an assigned value.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib" / "python"))

import cose_det_enc as c  # noqa: E402

L = c.LABEL_DETERMINISTIC_ENCODINGS


def h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# Literals stated in the draft (Introduction and Examples).
DRAFT_EXAMPLE_PREIMAGE = h("a2616101616202")
DRAFT_EXAMPLE_DIGEST = h("a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3")
INTRO_MAP_4_2_1 = h("a2 19 03 e8 01 61 61 02")
INTRO_MAP_4_2_3 = h("a2 61 61 02 19 03 e8 01")
INTRO_FLOAT_4_2_1 = h("f9 3e 00")
INTRO_FLOAT_DAG_CBOR = h("fb 3f f8 00 00 00 00 00 00")
B64_EXAMPLE_PREIMAGE = h("a16178fb3ff8000000000000")
B64_EXAMPLE_DIGEST = h("daf2cb80c76c789a6ef57296c4550ce1b4b87c2c7c43a6d9a39f774d9c747b55")
B64_EXAMPLE_CORE = h("a16178f93e00")


def header(**members) -> bytes:
    """A protected header map, encoded deterministically (keys as labels)."""
    m = {}
    for k, v in members.items():
        m[{"alg": 1, "hash": 258, "ctype": 259, "enc": L}.get(k, k)] = v
    return c.encode_core_deterministic(m)


def emit_case(cid, description, value_cbor, content_type, hash_alg=-16, expect_preimage=None,
              expect_payload=None, encoding=c.CORE_DETERMINISTIC):
    value = c.decode(value_cbor)
    e = c.emit(value, content_type, hash_alg=hash_alg, encoding=encoding)
    if expect_preimage is not None:
        assert e.preimage == expect_preimage, (cid, e.preimage.hex())
    if expect_payload is not None:
        assert e.payload == expect_payload, (cid, e.payload.hex())
    case = {
        "id": cid,
        "description": description,
        "value_cbor": value_cbor.hex(),
        "content_type": content_type,
        "hash_alg": hash_alg,
    }
    if encoding != c.CORE_DETERMINISTIC:
        case["encoding"] = encoding
    case["expected"] = {
        "preimage": e.preimage.hex(),
        "payload": e.payload.hex(),
        "protected": e.protected.hex(),
    }
    return case


def emit_reject_case(cid, description, value_cbor, encoding, content_type="application/cbor"):
    try:
        c.emit(c.decode(value_cbor), content_type, encoding=encoding)
    except c.EncodeError:
        pass
    else:
        raise AssertionError((cid, "emitted"))
    return {
        "id": cid,
        "description": description,
        "value_cbor": value_cbor.hex(),
        "content_type": content_type,
        "encoding": encoding,
    }


def conformance_case(cid, description, preimage, encoding, conforms, recreated=None):
    """Stored content checked against an encoding before it is hashed.

    'recreated' is what the encoding produces for the value the preimage decodes
    to (None when that value is outside the encoding).  Content conforms exactly
    when the two are equal, so for conforming content the strict check and the
    re-encoding of the value hash the same octets.
    """
    try:
        got = c.ENCODINGS[encoding](c.decode(preimage))
    except c.EncodeError:
        got = None
    assert got == (preimage if conforms else recreated), (cid, got and got.hex())
    assert c.conforms(preimage, encoding) is conforms, cid
    return {
        "id": cid,
        "description": description,
        "encoding": encoding,
        "preimage": preimage.hex(),
        "expected": {
            "conforms": conforms,
            "recreated": got.hex() if got is not None else None,
        },
    }


def verify_case(cid, description, protected, payload, expected, reason, *, preimage=None,
                value_cbor=None):
    case = {
        "id": cid,
        "description": description,
        "protected": protected.hex(),
        "payload": payload.hex(),
    }
    if preimage is not None:
        case["preimage"] = preimage.hex()
    if value_cbor is not None:
        case["value_cbor"] = value_cbor.hex()
    got = c.verify(protected, payload, preimage=preimage,
                   value=c.decode(value_cbor) if value_cbor is not None else None,
                   has_value=value_cbor is not None)
    assert (got.outcome, got.reason) == (expected, reason), (cid, got)
    case["expected"] = {"outcome": expected, "reason": reason}
    return case


def build() -> dict:
    # The draft's example value {"b": 2, "a": 1}, as a producer might hold it:
    # keys in insertion order, which is not RFC 8949 Section 4.2.1 order.
    ex_value = h("a2 61 62 02 61 61 01")
    ex_pre = DRAFT_EXAMPLE_PREIMAGE
    ex_dig = DRAFT_EXAMPLE_DIGEST

    emit_cases = [
        emit_case("emit-draft-example", "The draft's Examples section: {\"b\": 2, \"a\": 1} "
                  "encodes to the 7-octet preimage and digest the draft states",
                  ex_value, "application/cbor",
                  expect_preimage=DRAFT_EXAMPLE_PREIMAGE, expect_payload=DRAFT_EXAMPLE_DIGEST),
        emit_case("emit-intro-key-order", "The draft's Introduction map {1000: 1, \"a\": 2}, given in "
                  "length-first order, re-encodes in bytewise key order",
                  INTRO_MAP_4_2_3, "application/cbor", expect_preimage=INTRO_MAP_4_2_1),
        emit_case("emit-intro-float", "The draft's Introduction float 1.5, given as binary64, "
                  "re-encodes in its shortest form",
                  INTRO_FLOAT_DAG_CBOR, "application/cbor", expect_preimage=INTRO_FLOAT_4_2_1),
        emit_case("emit-indefinite", "Indefinite-length array and text string re-encode as "
                  "definite-length",
                  h("9f 7f 61 61 61 62 ff 01 ff"), "application/cbor",
                  expect_preimage=h("82 62 61 62 01")),
        emit_case("emit-non-preferred-int", "An integer in a longer head than needed re-encodes "
                  "in its shortest head",
                  h("a1 18 01 1a 00 00 00 0a"), "application/cbor",
                  expect_preimage=h("a1 01 0a")),
        emit_case("emit-nested", "Nested maps, arrays, negative integers, byte strings, "
                  "simple values, floats and a tag",
                  h("a5 63 6b 65 79 82 20 38 63 61 7a f6 18 64 c1 1a 5f 5e 10 00 62 62 62 a2 61 79 "
                    "f5 61 78 f4 41 00 fb 40 f8 6a 00 00 00 00 00"),
                  "application/swid+cbor"),
        emit_case("emit-sha384", "The draft example under SHA-384 (-43)", ex_value,
                  "application/cbor", hash_alg=-43),
        emit_case("emit-content-format", "A Content-Format number (60, application/cbor) as the "
                  "259 value", ex_value, 60),
        emit_case("emit-b64-draft-example", "The draft's cbor-binary64 example: {\"x\": 1.5}, "
                  "given in its shortest form, encodes to the 12-octet preimage and digest the "
                  "draft states", B64_EXAMPLE_CORE, "application/cbor",
                  expect_preimage=B64_EXAMPLE_PREIMAGE, expect_payload=B64_EXAMPLE_DIGEST,
                  encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-intro-float", "The draft's Introduction float 1.5, given in its "
                  "shortest form, encodes as binary64", INTRO_FLOAT_4_2_1, "application/cbor",
                  expect_preimage=INTRO_FLOAT_DAG_CBOR, encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-key-order", "The draft's Introduction map under cbor-binary64: the "
                  "key order of RFC 8949 Section 4.2.1 still applies",
                  INTRO_MAP_4_2_3, "application/cbor", expect_preimage=INTRO_MAP_4_2_1,
                  encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-integers", "Integers stay integers in their shortest head; only "
                  "the floats 1.0 and -1.0 become binary64",
                  h("84 01 f9 3c 00 20 f9 bc 00"), "application/cbor",
                  expect_preimage=h("84 01 fb 3f f0 00 00 00 00 00 00 20 fb bf f0 00 00 00 00 00 00"),
                  encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-int-float-keys", "1 and 1.0 as keys of one map, in bytewise order",
                  h("a2 01 f5 f9 3c 00 f4"), "application/cbor",
                  expect_preimage=h("a2 01 f5 fb 3f f0 00 00 00 00 00 00 f4"),
                  encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-positive-zero", "Positive zero is inside the encoding",
                  h("a1 61 7a f9 00 00"), "application/cbor",
                  expect_preimage=h("a1 61 7a fb 00 00 00 00 00 00 00 00"),
                  encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-nested", "The nested value of emit-nested under cbor-binary64",
                  h("a5 63 6b 65 79 82 20 38 63 61 7a f6 18 64 c1 1a 5f 5e 10 00 62 62 62 a2 61 79 "
                    "f5 61 78 f4 41 00 fb 40 f8 6a 00 00 00 00 00"),
                  "application/swid+cbor", encoding=c.CBOR_BINARY64),
        emit_case("emit-b64-content-format", "cbor-binary64 with Content-Format 60 "
                  "(application/cbor) as the 259 value", B64_EXAMPLE_CORE, 60,
                  encoding=c.CBOR_BINARY64),
    ]

    emit_reject = [
        emit_reject_case("reject-b64-nan", "NaN is outside cbor-binary64",
                         h("a1 61 78 f9 7e 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-plus-inf", "Positive infinity is outside cbor-binary64",
                         h("a1 61 78 f9 7c 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-minus-inf", "Negative infinity is outside cbor-binary64",
                         h("a1 61 78 f9 fc 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-negative-zero", "Negative zero is outside cbor-binary64",
                         h("a1 61 78 f9 80 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-negative-zero-binary64", "Negative zero given as binary64 "
                         "is still outside cbor-binary64",
                         h("a1 61 78 fb 80 00 00 00 00 00 00 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-nested", "Negative zero deep inside an array",
                         h("82 01 a1 61 79 f9 80 00"), c.CBOR_BINARY64),
        emit_reject_case("reject-b64-tagged", "NaN as the content of a tag",
                         h("c1 fb 7f f8 00 00 00 00 00 00"), c.CBOR_BINARY64),
    ]

    conformance = [
        conformance_case("conform-b64-draft-example", "The draft's cbor-binary64 preimage "
                         "conforms", B64_EXAMPLE_PREIMAGE, c.CBOR_BINARY64, True),
        conformance_case("conform-b64-nested", "The emit-b64-nested preimage conforms",
                         h(next(e for e in emit_cases if e["id"] == "emit-b64-nested")
                           ["expected"]["preimage"]), c.CBOR_BINARY64, True),
        conformance_case("conform-b64-integer", "An integer where a float might be expected "
                         "conforms: it is a different value, not a different encoding",
                         h("a1 61 78 01"), c.CBOR_BINARY64, True),
        conformance_case("conform-b64-shortest-float", "A float in its shortest form does not "
                         "conform", B64_EXAMPLE_CORE, c.CBOR_BINARY64, False,
                         recreated=B64_EXAMPLE_PREIMAGE),
        conformance_case("conform-b64-key-order", "Length-first key order does not conform",
                         INTRO_MAP_4_2_3, c.CBOR_BINARY64, False, recreated=INTRO_MAP_4_2_1),
        conformance_case("conform-b64-indefinite", "An indefinite-length array does not conform",
                         h("9f 01 ff"), c.CBOR_BINARY64, False, recreated=h("81 01")),
        conformance_case("conform-b64-non-preferred-int", "An integer in a longer head than "
                         "needed does not conform", h("a1 61 78 18 01"), c.CBOR_BINARY64, False,
                         recreated=h("a1 61 78 01")),
        conformance_case("conform-b64-negative-zero", "Binary64 negative zero does not conform, "
                         "and no conforming preimage exists for its value",
                         h("a1 61 78 fb 80 00 00 00 00 00 00 00"), c.CBOR_BINARY64, False),
        conformance_case("conform-b64-nan", "Binary64 NaN does not conform",
                         h("a1 61 78 fb 7f f8 00 00 00 00 00 00"), c.CBOR_BINARY64, False),
        conformance_case("conform-b64-inf", "Binary64 positive infinity does not conform",
                         h("a1 61 78 fb 7f f0 00 00 00 00 00 00"), c.CBOR_BINARY64, False),
        conformance_case("conform-core-draft-example", "The draft's core-deterministic "
                         "preimage conforms to value 1", DRAFT_EXAMPLE_PREIMAGE,
                         c.CORE_DETERMINISTIC, True),
        conformance_case("conform-core-binary64", "The cbor-binary64 preimage does not conform "
                         "to value 1", B64_EXAMPLE_PREIMAGE, c.CORE_DETERMINISTIC, False,
                         recreated=B64_EXAMPLE_CORE),
        conformance_case("conform-core-negative-zero", "Negative zero in its shortest form "
                         "conforms to value 1", h("a1 61 78 f9 80 00"), c.CORE_DETERMINISTIC,
                         True),
    ]

    ok = header(alg=-7, hash=-16, ctype="application/cbor", enc=1)
    mod_value = h("a2 61 62 02 61 61 02")  # {"b": 2, "a": 2}: a modified value
    dag_pre = h("a1 61 78 fb 3f f8 00 00 00 00 00 00")  # {"x": 1.5}, binary64 float
    f16_pre = h("a1 61 78 f9 3e 00")  # {"x": 1.5}, RFC 8949 Section 4.2.1
    len_first_pre = INTRO_MAP_4_2_3
    ok2 = header(alg=-7, hash=-16, ctype="application/cbor", enc=2)
    b64_dig = B64_EXAMPLE_DIGEST
    nz_b64_pre = h("a1 61 78 fb 80 00 00 00 00 00 00 00")  # {"x": -0.0}, binary64

    verify_cases = [
        verify_case("verify-preimage", "Holds the preimage; digest matches", ok, ex_dig,
                    "verified", "preimage-digest-match", preimage=ex_pre),
        verify_case("verify-value", "Holds only the structured value; re-creates the preimage "
                    "with value 1", ok, ex_dig, "verified", "recreated-digest-match",
                    value_cbor=ex_value),
        verify_case("verify-value-modified", "Holds a modified structured value", ok, ex_dig,
                    "failed", "recreated-digest-mismatch", value_cbor=mod_value),
        verify_case("verify-preimage-mismatch", "Holds a preimage that does not hash to the "
                    "payload", ok, ex_dig, "failed", "preimage-digest-mismatch",
                    preimage=h("a2616101616203")),
        verify_case("verify-value-no-encoding", "Holds only the value; the header does not "
                    "identify the encoding", header(alg=-7, hash=-16, ctype="application/cbor"),
                    ex_dig, "unverified", "encoding-absent", value_cbor=ex_value),
        verify_case("verify-preimage-no-encoding", "Holds the preimage; no encoding parameter "
                    "(an RFC 9995 Hash Envelope)", header(alg=-7, hash=-16, ctype="application/cbor"),
                    ex_dig, "verified", "preimage-digest-match", preimage=ex_pre),
        verify_case("verify-value-unknown-encoding", "Holds only the value; the encoding value "
                    "is one the verifier does not implement",
                    header(alg=-7, hash=-16, ctype="application/cbor", enc=99), ex_dig,
                    "unverified", "encoding-not-implemented", value_cbor=ex_value),
        verify_case("verify-preimage-unknown-encoding", "Holds the preimage; an unknown encoding "
                    "value does not prevent the RFC 9995 check",
                    header(alg=-7, hash=-16, ctype="application/cbor", enc=99), ex_dig,
                    "verified", "preimage-digest-match", preimage=ex_pre),
        verify_case("verify-nothing-held", "Holds neither the preimage nor the value", ok, ex_dig,
                    "unverified", "no-content"),
        verify_case("verify-ctype-absent", "The encoding parameter without 259 fails before any "
                    "recomputation, even with a matching preimage",
                    header(alg=-7, hash=-16, enc=1), ex_dig, "failed", "content-type-absent",
                    preimage=ex_pre),
        verify_case("verify-ctype-absent-value", "The encoding parameter without 259, holding "
                    "the value", header(alg=-7, hash=-16, enc=1), ex_dig, "failed",
                    "content-type-absent", value_cbor=ex_value),
        verify_case("verify-ctype-json", "core-deterministic paired with application/json "
                    "(the draft's own example of a violation)",
                    header(alg=-7, hash=-16, ctype="application/json", enc=1), ex_dig, "failed",
                    "content-type-mismatch", preimage=ex_pre),
        verify_case("verify-ctype-params-case", "A 259 media type with a parameter and in mixed "
                    "case still matches", header(alg=-7, hash=-16, ctype="Application/CBOR; x=y", enc=1),
                    ex_dig, "verified", "recreated-digest-match", value_cbor=ex_value),
        verify_case("verify-ctype-suffix", "A +cbor structured syntax suffix matches",
                    header(alg=-7, hash=-16, ctype="application/swid+cbor", enc=1), ex_dig,
                    "verified", "recreated-digest-match", value_cbor=ex_value),
        verify_case("verify-ctype-suffix-sd-cwt", "A +sd-cwt structured syntax suffix matches",
                    header(alg=-7, hash=-16, ctype="application/example+sd-cwt", enc=1), ex_dig,
                    "verified", "preimage-digest-match", preimage=ex_pre),
        verify_case("verify-ctype-not-suffix", "A subtype that only begins with cbor is not a "
                    "match", header(alg=-7, hash=-16, ctype="application/cbor-x", enc=1), ex_dig,
                    "failed", "content-type-mismatch", preimage=ex_pre),
        verify_case("verify-ctype-cf-cbor", "Content-Format 60 (application/cbor) matches",
                    header(alg=-7, hash=-16, ctype=60, enc=1), ex_dig, "verified",
                    "recreated-digest-match", value_cbor=ex_value),
        verify_case("verify-ctype-cf-json", "Content-Format 50 (application/json) does not match",
                    header(alg=-7, hash=-16, ctype=50, enc=1), ex_dig, "failed",
                    "content-type-mismatch", preimage=ex_pre),
        verify_case("verify-ctype-unknown-encoding-json", "An encoding value the verifier does "
                    "not recognize is not checked against 259",
                    header(alg=-7, hash=-16, ctype="application/json", enc=99), ex_dig,
                    "verified", "preimage-digest-match", preimage=ex_pre),
        verify_case("verify-binary64-held", "Holds a value whose float arrived as binary64; "
                    "RFC 8949 Section 4.2.1 re-creates the shortest form the producer hashed",
                    ok, sha256(f16_pre), "verified", "recreated-digest-match", value_cbor=dag_pre),
        verify_case("verify-binary64-hashed", "The producer hashed binary64 floats (another "
                    "encoding) but claimed value 1", ok, sha256(dag_pre), "failed",
                    "recreated-digest-mismatch", value_cbor=dag_pre),
        verify_case("verify-length-first-hashed", "The producer hashed length-first key order "
                    "(RFC 8949 Section 4.2.3) but claimed value 1", ok, sha256(len_first_pre),
                    "failed", "recreated-digest-mismatch", value_cbor=len_first_pre),
        verify_case("verify-length-first-preimage", "The same envelope, holding the "
                    "length-first preimage itself: the RFC 9995 check passes",
                    ok, sha256(len_first_pre), "verified", "preimage-digest-match",
                    preimage=len_first_pre),
        verify_case("verify-sha384", "SHA-384 (-43) as payload-hash-alg",
                    header(alg=-7, hash=-43, ctype="application/cbor", enc=1),
                    hashlib.sha384(ex_pre).digest(), "verified", "recreated-digest-match",
                    value_cbor=ex_value),
        verify_case("verify-hash-alg-unknown", "A payload-hash-alg the verifier does not "
                    "implement", header(alg=-7, hash=-999, ctype="application/cbor", enc=1),
                    ex_dig, "unverified", "hash-alg-not-implemented", preimage=ex_pre),
        verify_case("verify-b64-preimage", "cbor-binary64: holds the preimage; digest matches",
                    ok2, b64_dig, "verified", "preimage-digest-match", preimage=dag_pre),
        verify_case("verify-b64-value", "cbor-binary64: holds a value whose float arrived in "
                    "its shortest form; value 2 re-creates the binary64 preimage", ok2, b64_dig,
                    "verified", "recreated-digest-match", value_cbor=f16_pre),
        verify_case("verify-b64-value-binary64", "cbor-binary64: holds a value whose float "
                    "arrived as binary64", ok2, b64_dig, "verified", "recreated-digest-match",
                    value_cbor=dag_pre),
        verify_case("verify-b64-value-modified", "cbor-binary64: holds a modified value",
                    ok2, b64_dig, "failed", "recreated-digest-mismatch",
                    value_cbor=h("a1 61 78 f9 3e 01")),
        verify_case("verify-b64-shortest-hashed", "The producer hashed shortest-form floats "
                    "(value 1) but claimed value 2", ok2, sha256(f16_pre), "failed",
                    "recreated-digest-mismatch", value_cbor=f16_pre),
        verify_case("verify-b64-shortest-preimage", "The same envelope, holding the "
                    "shortest-form preimage itself: the RFC 9995 check passes",
                    ok2, sha256(f16_pre), "verified", "preimage-digest-match", preimage=f16_pre),
        verify_case("verify-b64-ctype-json", "cbor-binary64 paired with application/json",
                    header(alg=-7, hash=-16, ctype="application/json", enc=2), b64_dig, "failed",
                    "content-type-mismatch", preimage=dag_pre),
        verify_case("verify-b64-ctype-absent", "cbor-binary64 without 259",
                    header(alg=-7, hash=-16, enc=2), b64_dig, "failed", "content-type-absent",
                    value_cbor=f16_pre),
        verify_case("verify-b64-ctype-suffix", "cbor-binary64 with a +cbor structured syntax "
                    "suffix", header(alg=-7, hash=-16, ctype="application/swid+cbor", enc=2),
                    b64_dig, "verified", "recreated-digest-match", value_cbor=f16_pre),
        verify_case("verify-b64-value-negative-zero", "cbor-binary64: holds a value with "
                    "negative zero, which the encoding cannot encode", ok2, sha256(nz_b64_pre),
                    "unverified", "value-not-encodable", value_cbor=h("a1 61 78 f9 80 00")),
        verify_case("verify-b64-value-nan", "cbor-binary64: holds a value with NaN", ok2,
                    sha256(h("a1 61 78 fb 7f f8 00 00 00 00 00 00")), "unverified",
                    "value-not-encodable", value_cbor=h("a1 61 78 f9 7e 00")),
        verify_case("verify-b64-preimage-negative-zero", "A held preimage is hashed as it is: "
                    "the RFC 9995 check does not test conformance", ok2, sha256(nz_b64_pre),
                    "verified", "preimage-digest-match", preimage=nz_b64_pre),
    ]
    return {
        "description": "Vectors for draft-mih-sokolov-cose-deterministic-encodings. Header "
                       "label 271 is the value the draft suggests for TBD_1; it is not "
                       "assigned. 'protected' is the serialized protected header map. An "
                       "'encoding' member is a value of the COSE Deterministic Encodings "
                       "registry; an emit case without one uses value 1. A verifier holding "
                       "'value_cbor' decodes it and re-creates the preimage; one holding "
                       "'preimage' hashes it. An 'emit_reject' case is a value the encoding "
                       "cannot encode: a producer emits no envelope for it. A 'conformance' "
                       "case is stored content checked before hashing: 'recreated' is what the "
                       "encoding produces for the decoded value (null when the value is outside "
                       "the encoding), and the content conforms exactly when 'recreated' equals "
                       "'preimage'.",
        "header_label": L,
        "emit": emit_cases,
        "emit_reject": emit_reject,
        "conformance": conformance,
        "verify": verify_cases,
    }


def main() -> int:
    out = json.dumps(build(), indent=2) + "\n"
    path = HERE / "vectors.json"
    if "--check" in sys.argv[1:]:
        if path.read_text() != out:
            print("STALE: vectors/vectors.json differs; run python3 vectors/generate.py")
            return 1
        print("vectors.json is current")
        return 0
    path.write_text(out)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
