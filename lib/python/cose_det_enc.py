# SPDX-License-Identifier: BSD-3-Clause
"""Emitter and verifier for the deterministic-encodings Hash Envelope header.

A minimal, standard-library-only reference for
draft-mih-sokolov-cose-deterministic-encodings.  It builds the protected header
and payload of a COSE Hash Envelope (RFC 9995) whose preimage is a structured
value encoded under the Core Deterministic Encoding Requirements (RFC 8949
Section 4.2.1), and checks a content binding, reporting verified, failed or
unverified as the draft's "Producer
and Verifier Behavior" section specifies.

Signing is out of scope: the header parameter concerns the content binding,
which the draft keeps independent of signature validity.

The header label is TBD_1 in the draft; 271 is the value it suggests to IANA
and is used here as the default.  It is not an assigned value.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Any

LABEL_ALG = 1
LABEL_PAYLOAD_HASH_ALG = 258
LABEL_PREIMAGE_CONTENT_TYPE = 259
LABEL_PAYLOAD_LOCATION = 260
LABEL_DETERMINISTIC_ENCODINGS = 271  # TBD_1, suggested value; not assigned

CORE_DETERMINISTIC = 1

VERIFIED = "verified"
FAILED = "failed"
UNVERIFIED = "unverified"

# COSE Algorithms registry: the hash algorithms this reference implements.
HASH_ALGS = {
    -16: "sha256",
    -43: "sha384",
    -44: "sha512",
}

# Applicable Content Types of value 1 (the draft's COSE Deterministic Encodings registry).
CORE_DETERMINISTIC_MEDIA_TYPES = frozenset({
    "application/cbor",
    "application/cbor-seq",
    "application/cose",
    "application/cose-key",
    "application/cose-key-set",
    "application/cose-x509",
    "application/cwt",
    "application/multipart-core",
})
CORE_DETERMINISTIC_SUFFIXES = frozenset({"+cbor", "+cbor-seq", "+cose", "+cwt", "+sd-cwt"})

# A subset of the CoAP Content-Formats registry: numbers assigned to a media
# type with no content coding.  A number not listed here is not matched.
CONTENT_FORMATS = {
    16: "application/cose",  # cose-type="cose-encrypt0"
    17: "application/cose",  # cose-type="cose-mac0"
    18: "application/cose",  # cose-type="cose-sign1"
    50: "application/json",
    60: "application/cbor",
    61: "application/cwt",
    62: "application/multipart-core",
    63: "application/cbor-seq",
    96: "application/cose",  # cose-type="cose-encrypt"
    97: "application/cose",  # cose-type="cose-mac"
    98: "application/cose",  # cose-type="cose-sign"
    101: "application/cose-key",
    102: "application/cose-key-set",
    258: "application/swid+cbor",
}


class EncodeError(ValueError):
    """The value cannot be encoded under the requested deterministic encoding."""


class DecodeError(ValueError):
    """The octets are not a well-formed CBOR data item this module decodes."""


@dataclass(frozen=True)
class Tag:
    number: int
    value: Any


@dataclass(frozen=True)
class Simple:
    value: int


# --- Core Deterministic Encoding (RFC 8949 Section 4.2.1) -------------------


def _head(major: int, arg: int) -> bytes:
    mt = major << 5
    if arg < 24:
        return bytes([mt | arg])
    if arg < 0x100:
        return bytes([mt | 24, arg])
    if arg < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", arg)
    if arg < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", arg)
    if arg < 0x10000000000000000:
        return bytes([mt | 27]) + struct.pack(">Q", arg)
    raise EncodeError("integer argument does not fit in 64 bits")


def _float(value: float) -> bytes:
    # Preferred serialization: the shortest of binary16/32/64 that represents
    # the value exactly (RFC 8949 Section 4.2.1, by way of Section 4.1).
    if math.isnan(value):
        raise EncodeError("NaN is outside what this reference encodes")
    for fmt, ai in (("e", 25), ("f", 26)):
        try:
            packed = struct.pack(">" + fmt, value)
        except OverflowError:
            continue
        if struct.unpack(">" + fmt, packed)[0] == value:
            return bytes([0xE0 | ai]) + packed
    return bytes([0xFB]) + struct.pack(">d", value)


def encode_core_deterministic(value: Any) -> bytes:
    """Encode a structured value under RFC 8949 Section 4.2.1."""
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, float):
        return _float(value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (dict, Map)):
        pairs = value.items() if isinstance(value, dict) else value
        items = [(encode_core_deterministic(k), encode_core_deterministic(v)) for k, v in pairs]
        items.sort(key=lambda kv: kv[0])  # bytewise lexicographic order of encoded keys
        for (a, _), (b, _) in zip(items, items[1:]):
            if a == b:
                raise EncodeError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode_core_deterministic(v) for v in value)
    if isinstance(value, Tag):
        return _head(6, value.number) + encode_core_deterministic(value.value)
    if isinstance(value, Simple):
        if 24 <= value.value <= 31 or not 0 <= value.value <= 255:
            raise EncodeError("invalid simple value")
        return _head(7, value.value)
    raise EncodeError(f"cannot encode {type(value).__name__}")


# --- A small CBOR decoder ---------------------------------------------------


class Map(list):
    """A decoded CBOR map: (key, value) pairs in their decoded order.

    A list rather than a dict, so that keys Python cannot hash (arrays, maps)
    and keys Python would conflate (1, 1.0 and True) stay distinct.
    """

    def get(self, key: Any, default: Any = None) -> Any:
        for k, v in self:
            if type(k) is type(key) and k == key:
                return v
        return default

    def has(self, key: Any) -> bool:
        return any(type(k) is type(key) and k == key for k, _ in self)


def decode(data: bytes) -> Any:
    """Decode exactly one well-formed CBOR data item; trailing octets are an error.

    Integers and floating-point values stay distinct, and a map decodes to a
    Map.  A map whose keys are not all distinct is rejected.
    """
    value, end = _decode(data, 0)
    if end != len(data):
        raise DecodeError("trailing octets after the data item")
    return value


def _take(data: bytes, pos: int, n: int) -> bytes:
    if pos + n > len(data):
        raise DecodeError("truncated data item")
    return data[pos:pos + n]


def _decode(data: bytes, pos: int) -> tuple[Any, int]:
    ib = _take(data, pos, 1)[0]
    pos += 1
    major, ai = ib >> 5, ib & 0x1F
    if major == 7 and ai in (25, 26, 27):
        n, fmt = {25: (2, ">e"), 26: (4, ">f"), 27: (8, ">d")}[ai]
        return struct.unpack(fmt, _take(data, pos, n))[0], pos + n
    if ai < 24:
        arg = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        arg = int.from_bytes(_take(data, pos, n), "big")
        pos += n
    elif ai == 31 and major in (2, 3, 4, 5):
        arg = None
    else:
        raise DecodeError("reserved or invalid additional information")

    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg is None:
            chunks = []
            while _take(data, pos, 1)[0] != 0xFF:
                if data[pos] >> 5 != major or data[pos] & 0x1F == 31:
                    raise DecodeError("bad chunk in an indefinite-length string")
                chunk, pos = _decode(data, pos)
                chunks.append(chunk)
            return (b"".join(chunks) if major == 2 else "".join(chunks)), pos + 1
        raw = _take(data, pos, arg)
        pos += arg
        if major == 2:
            return bytes(raw), pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as e:
            raise DecodeError("invalid UTF-8 in a text string") from e
    if major in (4, 5):
        out = Map() if major == 5 else []
        count = 0
        while (arg is None and _take(data, pos, 1)[0] != 0xFF) or (arg is not None and count < arg):
            item, pos = _decode(data, pos)
            if major == 5:
                v, pos = _decode(data, pos)
                item = (item, v)
            out.append(item)
            count += 1
        if arg is None:
            pos += 1
        if major == 5:
            keys = [encode_structured(k) for k, _ in out]
            if len(set(keys)) != len(keys):
                raise DecodeError("duplicate map key")
        return out, pos
    if major == 6:
        inner, pos = _decode(data, pos)
        return Tag(arg, inner), pos
    # major == 7, simple values
    if ai == 24 and arg < 32:
        raise DecodeError("simple value below 32 in two octets")
    if arg in (20, 21, 22):
        return (False, True, None)[arg - 20], pos
    return Simple(arg), pos


def encode_structured(value: Any) -> bytes:
    """Encode a structured value (as decode() returns) under RFC 8949 Section 4.2.1."""
    return encode_core_deterministic(value)


ENCODINGS = {CORE_DETERMINISTIC: encode_structured}


# --- Applicable Content Types (the draft's consistency check) ------------


def content_type_matches(encoding: int, content_type: Any) -> bool:
    """True when a 259 value matches the Applicable Content Types of encoding."""
    if encoding != CORE_DETERMINISTIC:
        return False
    if isinstance(content_type, bool):
        return False
    if isinstance(content_type, int):
        if content_type < 0:
            return False
        media = CONTENT_FORMATS.get(content_type)
        if media is None:
            return False
        content_type = media
    if not isinstance(content_type, str):
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type in CORE_DETERMINISTIC_MEDIA_TYPES:
        return True
    if "/" not in media_type:
        return False
    subtype = media_type.split("/", 1)[1]
    plus = subtype.rfind("+")
    return plus > 0 and subtype[plus:] in CORE_DETERMINISTIC_SUFFIXES


# --- Emitter ----------------------------------------------------------------


@dataclass(frozen=True)
class Emitted:
    preimage: bytes
    payload: bytes
    protected: bytes  # the serialized protected header map


def emit(value: Any, content_type: Any, *, alg: int = -7, hash_alg: int = -16,
         encoding: int = CORE_DETERMINISTIC,
         label: int = LABEL_DETERMINISTIC_ENCODINGS) -> Emitted:
    """Encode value, hash it, and build the Hash Envelope protected header."""
    if hash_alg not in HASH_ALGS:
        raise ValueError(f"hash algorithm {hash_alg} not implemented")
    if encoding not in ENCODINGS:
        raise ValueError(f"encoding {encoding} not implemented")
    if not content_type_matches(encoding, content_type):
        # Consistency with preimage-content-type: a producer MUST NOT emit this pairing.
        raise ValueError("content type is not an Applicable Content Type of the encoding")
    preimage = ENCODINGS[encoding](value)
    payload = hashlib.new(HASH_ALGS[hash_alg], preimage).digest()
    protected = encode_core_deterministic({
        LABEL_ALG: alg,
        LABEL_PAYLOAD_HASH_ALG: hash_alg,
        LABEL_PREIMAGE_CONTENT_TYPE: content_type,
        label: encoding,
    })
    return Emitted(preimage, payload, protected)


# --- Verifier ---------------------------------------------------------------


@dataclass(frozen=True)
class Result:
    outcome: str  # VERIFIED, FAILED or UNVERIFIED
    reason: str


def verify(protected: bytes, payload: bytes, *, preimage: bytes | None = None,
           value: Any = None, has_value: bool = False,
           label: int = LABEL_DETERMINISTIC_ENCODINGS) -> Result:
    """Check the content binding of a Hash Envelope.

    protected is the serialized protected header map.  Pass the preimage
    octets if the verifier holds them, or a structured value (has_value=True)
    if it holds only that.  Signature validity is not checked here.
    """
    header = decode(protected)
    if not isinstance(header, Map):
        raise DecodeError("protected header is not a map")
    has_encoding = header.has(label)
    encoding = header.get(label)
    has_ctype = header.has(LABEL_PREIMAGE_CONTENT_TYPE)
    ctype = header.get(LABEL_PREIMAGE_CONTENT_TYPE)
    recognized = isinstance(encoding, int) and not isinstance(encoding, bool) and encoding in ENCODINGS

    # Consistency with preimage-content-type: this check comes first.
    if has_encoding:
        if not has_ctype:
            return Result(FAILED, "content-type-absent")
        if recognized and not content_type_matches(encoding, ctype):
            return Result(FAILED, "content-type-mismatch")

    hash_alg = header.get(LABEL_PAYLOAD_HASH_ALG)
    hash_name = HASH_ALGS.get(hash_alg) if isinstance(hash_alg, int) and not isinstance(hash_alg, bool) else None

    # RFC 9995 Section 5.3: a held preimage needs no encoding information.
    if preimage is not None:
        if hash_name is None:
            return Result(UNVERIFIED, "hash-alg-not-implemented")
        if hashlib.new(hash_name, preimage).digest() == payload:
            return Result(VERIFIED, "preimage-digest-match")
        return Result(FAILED, "preimage-digest-mismatch")

    if not has_value:
        return Result(UNVERIFIED, "no-content")
    if not has_encoding:
        return Result(UNVERIFIED, "encoding-absent")
    if not recognized:
        return Result(UNVERIFIED, "encoding-not-implemented")
    if hash_name is None:
        return Result(UNVERIFIED, "hash-alg-not-implemented")
    try:
        recreated = ENCODINGS[encoding](value)
    except EncodeError:
        return Result(UNVERIFIED, "value-not-encodable")
    if hashlib.new(hash_name, recreated).digest() == payload:
        return Result(VERIFIED, "recreated-digest-match")
    return Result(FAILED, "recreated-digest-mismatch")
