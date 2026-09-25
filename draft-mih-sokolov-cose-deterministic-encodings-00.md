---
title: "Deterministic Encodings for COSE"
abbrev: "COSE Deterministic Encodings"
docname: draft-mih-sokolov-cose-deterministic-encodings-00
date: 2026-09-25
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "COSE"
keyword:
 - COSE
 - hash envelope
 - preimage
 - canonicalization
 - deterministic encoding
stand_alone: yes
pi: {toc: no, sortrefs: yes, symrefs: yes}

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group, Inc.
   email: spec@actionstate.ai
 - ins: A. Sokolov
   name: Anton Sokolov
   organization: Tyche Institute
   city: Tallinn
   country: Estonia
   email: anton.sokolov@tyche.institute

normative:
  RFC2119:
  RFC8174:
  RFC6838:
  RFC7252:
  RFC8126:
  RFC8610:
  RFC8742:
  RFC8949:
  RFC9052:
  RFC9995:

informative:
  RFC9393:
  I-D.ietf-cbor-cde:
  VTOSpec:
    title: "CBOR Digest Context Requirements for VTO (work in progress)"
    target: https://github.com/seetadev/libp2p-vto-spec/blob/3955a077edb4aa409bbe90b82a989559fcdc2511/cbor-digest-context-requirements.md
    date: 2026-09-02
    author:
      - organization: libp2p Verified Telemetry Object (VTO) specification

--- abstract

A COSE Hash Envelope carries the hash of a preimage held elsewhere, but not
the deterministic encoding used to produce that preimage from structured
content, so a verifier that holds only the decoded content cannot reliably
recompute the hash. This document establishes an IANA registry of
deterministic encodings, whose initial entry is the Core Deterministic
Encoding Requirements of RFC 8949, and defines a COSE Hash Envelope
protected-header parameter that identifies which registered encoding a
producer applied.

--- note_Note_to_Readers

Individual submission, intended for the COSE Working Group (cose@ietf.org).
**Draft for co-author and working-group review; not yet submitted.**

--- middle

# Introduction {#intro}

Structured content formats often do not mandate a single deterministic
encoding, so the same value can be serialized as more than one byte sequence.
The COSE Hash Envelope {{RFC9995}} identifies the hash function (258) and the
content type of the preimage (259), but not which encoding produced it. A
verifier that holds the preimage bytes can hash them and compare the result
to the payload ({{RFC9995}} Section 5.3). A verifier that holds the content
only in decoded form -- for example, a record stored or forwarded as decoded
data, or re-serialized by an intermediary, so that the original bytes were
not retained -- has to re-encode it first, and needs to know which encoding
to use.

This document defines one protected-header parameter,
payload-preimage-encoding, which identifies that encoding, and a small IANA
registry of encoding identifiers. It uses the extension point the Hash
Envelope protected header already provides ({{Section 4 of RFC9995}}:
`* (int / tstr) => any`). The encoding is not carried as a media-type
parameter of preimage-content-type (259), because 259 may be a CoAP
Content-Format number, which cannot carry parameters, and because such a
parameter would have to be defined for every media type the encoding applies
to.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "Hash Envelope" and "preimage" in {{RFC9995}}.
As in {{RFC9995}}, the payload of a Hash Envelope is a digest, and the
preimage is the octet string that was hashed to produce it.
The Hash Envelope labels this document builds on are 258 (payload-hash-alg),
259 (preimage-content-type), and 260 (payload-location).

This document also uses the following terms:

Structured value:
: A value with internal structure, such as a CBOR data item, that a
  deterministic encoding serializes to create a preimage.

Content binding:
: The correspondence between content a verifier holds -- a preimage, or a
  structured value -- and the payload of a Hash Envelope. A verifier that
  checks a content binding reports one of three outcomes: verified, failed,
  or unverified.

Verified:
: The verifier hashed the preimage, as held or as re-created from a
  structured value, with the payload-hash-alg (258) algorithm, obtained the
  payload, and did not find the protected header inconsistent
  ({{consistency}}).

Failed:
: The verifier found the protected header inconsistent ({{consistency}}), or
  hashed the preimage, as held or as re-created, and obtained a different
  value.

Unverified:
: Any other case, in particular when the verifier holds neither the preimage
  nor the information needed to re-create it ({{verification}}).

These outcomes concern the content binding only; signature validity is
determined independently of them ({{verification}}).

# The payload-preimage-encoding Header Parameter {#header-param}

TBD\_1:
: payload-preimage-encoding. The deterministic encoding applied to a
  structured value to create the preimage, which has the content type given
  by preimage-content-type (259) and was hashed with the payload-hash-alg
  (258) algorithm to produce the payload. The value is the integer Value
  (not the Name) assigned to an encoding in the COSE Deterministic Encodings
  registry ({{iana-encodings}}).

It extends {{RFC9995}} by adding one optional member to the
Hash_Envelope_Protected_Header CDDL of {{RFC9995}} Section 4, alongside the
members for labels 258-260. The extended rule restates the {{RFC9995}} rule
with that member added:

~~~ cddl
Hash_Envelope_Protected_Header_With_Encoding = {
    ? &(alg: 1) => int,
    &(payload_hash_alg: 258) => int,
    ? &(payload_preimage_content_type: 259) => uint / tstr,
    ? &(payload_location: 260) => tstr,
    ? &(payload_preimage_encoding: TBD_1) => int,
    * (int / tstr) => any
}
~~~

Label TBD\_1 MAY be present in the protected header and MUST NOT be present
in the unprotected header, following the placement rule {{RFC9995}} states
for labels 258 through 260. When label TBD\_1 is present,
preimage-content-type (259) MUST also be present ({{consistency}}).

# Producer and Verifier Behavior {#behavior}

## Producers {#producers}

When a producer creates the preimage by applying a deterministic encoding to
a structured value, it SHOULD include payload-preimage-encoding, so that a
verifier holding only the structured value can re-create the preimage. When
present, the value MUST identify the encoding actually applied. An
unstructured preimage -- for example application/octet-stream, an image, or
an archive -- has no deterministic encoding to identify, and the parameter is
absent.

## Consistency with preimage-content-type {#consistency}

Each registered encoding lists the content types it applies to, as the
Applicable Content Types of its registry entry ({{iana-encodings}}). When
payload-preimage-encoding is present, preimage-content-type (259) MUST also
be present, and its value MUST match one of the Applicable Content Types of
the captured encoding:

* A 259 value that is a media-type name matches when its type and subtype --
  with any parameters removed, and compared case-insensitively ({{RFC6838}}
  Section 4.2) -- equal a listed media type, or when its subtype ends in a
  listed structured syntax suffix ({{RFC6838}} Section 4.2.8).

* A 259 value that is a Content-Format number matches when the CoAP
  Content-Formats registry ({{RFC7252}} Section 12.3) assigns that number to
  a matching media type with no content coding.

A producer MUST NOT emit a Hash Envelope that violates these rules -- for
example, one pairing core-deterministic with application/json. A verifier
that finds payload-preimage-encoding present with preimage-content-type
(259) absent, or with a 259 value that does not match the Applicable Content
Types of an encoding the verifier recognizes, MUST report the content
binding as failed, without attempting recomputation. This check comes
first, and takes precedence over {{verification}}. This outcome applies only
to Hash Envelopes that carry payload-preimage-encoding; a verifier that
implements only {{RFC9995}} ignores the parameter, and its results are
unchanged.

## Verifying the Content Binding {#verification}

A verifier that holds the preimage itself -- for example, as retrieved from
payload-location (260) -- checks the content binding as {{RFC9995}}
Section 5.3 describes: it hashes the preimage with the payload-hash-alg (258)
algorithm and compares the result to the payload. That check needs no
encoding information, and applies whether or not payload-preimage-encoding
is present, subject to {{consistency}}.

A verifier that holds only a structured value -- for example, content it
received, stored, or decoded in a form other than the preimage itself --
has to re-create the preimage by encoding that value, and needs
payload-preimage-encoding to do so. Such a verifier MUST encode the value
with the encoding the parameter captures, and MUST NOT infer the encoding
from preimage-content-type (259) or from the structure of the value. If
payload-preimage-encoding is absent, or carries a value the verifier does
not recognize or implement, the verifier cannot re-create the preimage: it
MUST NOT report the content binding as verified, and MUST report it as
unverified rather than as failed.

A Hash Envelope produced without this parameter -- including any produced
before the parameter was registered -- is not defective: its content binding
can still be verified from the preimage octets. Signature validity is
unaffected by any content-binding outcome: a verifier that has not
established the content binding can still validate the signature of the
COSE_Sign1 as specified in {{RFC9052}}.

# Examples {#examples}

These use Extended Diagnostic Notation ({{RFC8610}} Appendix G), in the
style of {{RFC9995}} Section 4.1; signature and key material are truncated.

The structured value `{"b": 2, "a": 1}`, a CBOR map, encoded per the Core
Deterministic Encoding Requirements of {{RFC8949}} Section 4.2.1 (bytewise
key order, placing "a" before "b"), gives the 7-octet preimage
`a2616101616202`, whose SHA-256 digest is
`a0d3af9e86e5517f729bad0657e2c6f3b7d03899894c8d6b33759074c893b5e3`:

~~~
18([ # COSE_Sign1
  <<{
    / alg               / 1: -7, # ES256
    / hash algorithm    / 258: -16, # sha-256
    / preimage type     / 259: "application/cbor",
    / preimage encoding / TBD_1: 1, # core-deterministic
  }>>
  / unprotected / {},
  / payload     / h'a0d3af9e...c893b5e3', # digest above
  / signature   / h'...'  # 64 octets, r || s
])
~~~

{{RFC9393}} registers application/swid+cbor for Concise Software
Identification (CoSWID) tags but does not require a deterministic encoding of
them, so two producers may serialize the same tag as different byte
sequences. A producer that applies the Core Deterministic Encoding
Requirements before hashing a CoSWID tag sets preimage-content-type (259) to
application/swid+cbor and payload-preimage-encoding to core-deterministic
(Value 1) -- recording its own choice, not a CoSWID requirement -- so that a
verifier holding the decoded tag knows how to re-create the preimage.

# Security Considerations {#security}

The preimage is the exact octet string the identified encoding produces, not
a rendering of it.

A deterministic encoding fixes the preimage for a given structured value, so
decoding a preimage and encoding the result again reproduces the preimage
only if decoding preserved that value exactly. Decoding into a programming
language's native types can lose distinctions the encoding depends on -- for
example, between integer and floating-point numbers, or the presence of a
tag. The core deterministic encoding requirements of {{RFC8949}} Section
4.2.1 also leave some choices to each application, such as those {{RFC8949}}
Section 4.2.2 describes for tags, large integers, and floating-point values;
those choices belong to the structured value, not to the encoding this
parameter captures. A producer that re-reads stored content before hashing
MUST ensure the preimage it hashes is byte-identical to the encoding's own
output. A verifier that re-creates a preimage from a structured value
({{verification}}) needs that value exactly as the producer encoded it;
otherwise its recomputed digest can differ from the payload, and the content
binding is then reported as failed.

# Privacy Considerations {#privacy}

A digest over deterministically encoded content is a stable function of
that content, so the payload is linkable wherever the content recurs. If the
structured value comes from a low-entropy space, encoding and hashing
candidate values can recover it; this risk already exists wherever
{{RFC9995}} is used, and identifying the encoding removes an ambiguity that
might have slowed such an attempt.

# IANA Considerations {#iana}

## COSE Header Parameters {#iana-header}

IANA is requested to register the following entry in the "COSE Header
Parameters" registry, in the "Integer values from 256 to 65535" range,
under the Specification Required policy ({{RFC8126}} Section 4.6) that
governs that range:

| Name | Label | Value Type | Value Registry | Description | Reference |
| --- | --- | --- | --- | --- | --- |
| payload-preimage-encoding | TBD\_1 (requested) | int | COSE Deterministic Encodings ({{iana-encodings}}) | Deterministic encoding applied to create the preimage of a Hash Envelope payload | This document |

The suggested value is 271, the lowest unassigned integer in the COSE
Header Parameters registry as of 2026-09-22.

## COSE Deterministic Encodings Registry {#iana-encodings}

IANA is requested to create a new registry, "COSE Deterministic Encodings".
The registry identifies deterministic encodings of structured content; it
carries no Hash Envelope semantics of its own, and a value is meaningful only
through a parameter, such as payload-preimage-encoding ({{header-param}}),
that gives it a role.

A registry is used, rather than a fixed reference, because more than one
deterministic encoding of the same data model is in use. For example,
{{VTOSpec}} encodes every floating-point field as IEEE 754 binary64, while
the core requirements of {{RFC8949}} Section 4.2.1 use the shortest form that
preserves the value: 1.5 is fb 3f f8 00 00 00 00 00 00 under the former and
f9 3e 00 under the latter. Both are carried as application/cbor, so
preimage-content-type (259) cannot distinguish them. Others have been
proposed, such as the CBOR Common Deterministic Encoding
{{I-D.ietf-cbor-cde}}.

Registration policy: Specification Required ({{RFC8126}} Section 4.6). The
registration template is: Value (an unsigned integer), Name, Description,
Applicable Content Types (media types and structured syntax suffixes, matched
against 259 as {{consistency}} specifies), Reference, and Change Controller.
The designated expert checks that the referenced specification defines
exactly one deterministic encoding for the value, and that its Applicable
Content Types are correct and can be matched as {{consistency}} specifies.
Entries are immutable: the registry grows by adding values, never by
reinterpreting an existing one. An entry MAY be withdrawn through the same
procedure; a withdrawn value and its name are never reassigned.

Initial contents:

| Value | Name | Description | Reference | Change Controller |
| --- | --- | --- | --- | --- |
| 1 | core-deterministic | Core Deterministic Encoding Requirements | {{RFC8949}} Section 4.2.1 | IETF |

The Applicable Content Types of value 1 are application/cbor,
application/cbor-seq, application/cose, application/cose-key,
application/cose-key-set, application/cose-x509, and application/cwt, and
media types with the +cbor, +cbor-seq, +cose, or +cwt structured syntax
suffix. For a CBOR sequence {{RFC8742}}, each data item is encoded according
to these requirements. The application-level choices that {{RFC8949}}
Section 4.2.2 leaves open are not part of value 1 ({{security}}).

--- back

# Acknowledgments
{:numbered="false"}

The authors thank Amaury Chamayou for a detailed review that aligned this
document's terminology, CDDL, and verification rules with {{RFC9995}} and
proposed the name core-deterministic.
