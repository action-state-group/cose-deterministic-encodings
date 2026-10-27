---
title: "Deterministic Encodings for COSE"
abbrev: "COSE Deterministic Encodings"
docname: draft-mih-sokolov-cose-deterministic-encodings-00
date: 2026-10-27
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
  I-D.ietf-cbor-serialization:
  DAG-CBOR:
    title: "Specification: DAG-CBOR"
    target: https://ipld.io/specs/codecs/dag-cbor/spec/
    date: 2026
    author:
      - organization: IPLD

--- abstract

A COSE Hash Envelope signs the digest of a preimage, not the preimage
itself. When the preimage is the encoding of a structured value, such as a
CBOR data item, and a verifier holds that value but not the bytes that were
hashed, the verifier has to encode the value again, and the digest matches
only if it applies the same deterministic encoding as the producer. RFC 8949 describes more than one such encoding for the same
content type, and the preimage content type does not identify which one was
applied. This document defines a COSE Hash Envelope protected-header
parameter that identifies the encoding, and an IANA registry of deterministic
encodings whose initial entry is the Core Deterministic Encoding Requirements
of RFC 8949.

--- note_Note_to_Readers

Individual submission, intended for the COSE Working Group (cose@ietf.org).

Source for this document, with a reference emitter and verifier and test
vectors, is at
[](https://github.com/action-state-group/cose-deterministic-encodings).

--- middle

# Introduction {#intro}

The COSE Hash Envelope {{RFC9995}} signs the digest of a preimage and
identifies the hash algorithm (258), the content type of the preimage (259),
and optionally where the preimage can be retrieved (260). A verifier that
holds the preimage can check that the digest of it, produced with the hash
algorithm identified by payload-hash-alg (258), matches the payload, as
{{RFC9995}} Section 5.3 describes. That check needs no information from this
document, and retaining the preimage is the simplest way to make it
possible.

The Hash Envelope carries the digest, not the preimage, and
payload-location (260) is optional. The content therefore reaches a
verifier, if at all, from outside the Hash Envelope, in whatever form its
application provides, which can be a structured value rather than the bytes
that were hashed. The content can arrive as a data item inside a larger CBOR
message, and unless the message wraps that item in a byte string, most CBOR
decoders cannot return its encoded bytes ({{I-D.ietf-cbor-serialization}}
Appendices H.1 and J.1). A system can also store the content in another
representation -- for example, a software inventory that keeps Concise
Software Identification (CoSWID) tags {{RFC9393}} as records in a database
-- rather than keep a second copy of each item as the bytes that were
hashed, provided that representation preserves each data item exactly
({{security}}). To check such content against its Hash Envelope, the
verifier has to encode the value again, the case in which
{{I-D.ietf-cbor-serialization}} Section 5.3.1 says deterministic encoding
becomes necessary and notes that designs of this kind are often chosen to
reduce data size, preserve privacy, or meet other design constraints. COSE
meets the same need for its own Sig_structure, which
the signer and the verifier each construct rather than transmit, by fixing
how that structure is encoded ({{RFC9052}} Sections 4.4 and 9). For a Hash
Envelope preimage, whose content type the application chooses, COSE fixes
no encoding.

Re-encoding reproduces the preimage only if the verifier applies the
encoding the producer applied, and {{RFC8949}} describes more than one.
Section 4.2.1 sorts map keys bytewise, while Section 4.2.3 keeps the
length-first order of the earlier CBOR specification for protocols that need
to be compatible with that order: `{1000: 1, "a": 2}` is
`a2 19 03 e8 01 61 61 02` under the former and `a2 61 61 02 19 03 e8 01`
under the latter. The preimage-content-type (259) names the type of the content, such as
application/swid+cbor, not the encoding applied to it, so a verifier that
guesses the encoding cannot tell a modified value from one encoded under a
different rule.

This document defines one protected-header parameter,
deterministic-encodings, which identifies that encoding, and a small IANA
registry of encoding identifiers. It uses the extension point the Hash
Envelope protected header already provides ({{Section 4 of RFC9995}}:
`* (int / tstr) => any`). The encoding is not carried as a media-type
parameter of preimage-content-type (259). The application/cbor media type defines no
parameters ({{RFC8949}} Section 9.3), so such a parameter would have to be
registered for every media type the encoding applies to, and a CoAP
Content-Format number carries only the parameters fixed in its registry
entry ({{RFC7252}} Section 12.3), so each pairing of media type and encoding
would also need its own number.

The scope of this document is structured values, such as CBOR data items,
and the deterministic encodings that serialize them. Media encodings, such
as those of images, and builds of software from source code are out of
scope; such content is checked from its bytes, as {{RFC9995}} Section 5.3
describes.

# Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as
shown here.

"COSE", "COSE_Sign1", and "protected header" are defined in {{RFC9052}};
"CDDL" in {{RFC8610}}; "Hash Envelope" and "preimage" in {{RFC9995}}.
As in {{RFC9995}}, the payload of a Hash Envelope is a digest, and the
preimage consists of the bytes that were hashed to produce it.
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
: The digest of the preimage, held or re-created from a structured value,
  produced with the hash algorithm identified by payload-hash-alg (258),
  matches the payload, and the verifier found no inconsistency in the
  protected header ({{consistency}}).

Failed:
: The verifier found the protected header inconsistent ({{consistency}}), or
  the digest of the preimage, held or re-created from a structured value,
  produced with the hash algorithm identified by payload-hash-alg (258),
  does not match the payload.

Unverified:
: Neither verified nor failed. When the verifier found no inconsistency in
  the protected header ({{consistency}}), this is the case if it holds
  neither the preimage nor a structured value; if it holds a structured
  value but not the preimage, and deterministic-encodings is absent or
  carries a value the verifier does not recognize or implement
  ({{verification}}); or if it does not implement the hash algorithm
  identified by payload-hash-alg (258).

# The deterministic-encodings Header Parameter {#header-param}

TBD\_1:
: deterministic-encodings. The deterministic encoding with which a
  structured value was serialized to create the bytes that were hashed
  (preimage) to produce the payload, given as the integer Value (not the
  Name) assigned to an encoding in the COSE Deterministic Encodings registry
  ({{iana-encodings}}).

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
    ? &(deterministic_encodings: TBD_1) => int,
    * (int / tstr) => any
}
~~~

Label TBD\_1 MAY be present in the protected header and MUST NOT be present
in the unprotected header, following the placement rule {{RFC9995}} states
for labels 258 through 260. When label TBD\_1 is present,
preimage-content-type (259) MUST also be present ({{consistency}}). A
producer MUST NOT list label TBD\_1 in the crit header parameter
({{RFC9052}} Section 3.1), so that a verifier that implements only
{{RFC9995}} can ignore it.

# Producer and Verifier Behavior {#behavior}

## Producers {#producers}

When a producer creates the preimage by applying a deterministic encoding to
a structured value, it SHOULD include deterministic-encodings, so that a
verifier holding only the structured value can re-create the preimage. When
present, the value MUST identify the encoding actually applied. A producer
that serializes a structured value without a deterministic encoding, or
whose preimage is not the serialization of a structured value -- for
example application/octet-stream content, an image, or an archive -- has no
encoding to identify, and the parameter is absent; the content binding can
then be checked only from the preimage bytes.

## Consistency with preimage-content-type {#consistency}

Each registered encoding lists the content types it applies to, as the
Applicable Content Types of its registry entry ({{iana-encodings}}). When
deterministic-encodings is present, preimage-content-type (259) MUST also
be present, and its value MUST match one of the Applicable Content Types of
the encoding that deterministic-encodings identifies:

* A 259 value that is a media-type name matches when its type and subtype --
  with any parameters removed, and compared case-insensitively ({{RFC6838}}
  Section 4.2) -- equal a listed media type, or when its subtype ends in a
  listed structured syntax suffix ({{RFC6838}} Section 4.2.8).

* A 259 value that is a Content-Format number matches when the CoAP
  Content-Formats registry ({{RFC7252}} Section 12.3) assigns that number to
  a matching media type with no content coding.

A producer MUST NOT emit a Hash Envelope that violates these rules -- for
example, one pairing core-deterministic with application/json. A verifier
that finds deterministic-encodings present with preimage-content-type
(259) absent, or with a 259 value that does not match the Applicable Content
Types of an encoding the verifier recognizes, MUST report the content
binding as failed, without attempting recomputation. This check comes
first, and takes precedence over {{verification}}. This outcome applies only
to Hash Envelopes that carry deterministic-encodings; a verifier that
implements only {{RFC9995}} ignores the parameter, and its results are
unchanged.

## Verifying the Content Binding {#verification}

A verifier that holds the preimage itself -- for example, as retrieved from
payload-location (260) -- checks the content binding as {{RFC9995}}
Section 5.3 describes: it checks whether the digest of the preimage, produced
with the hash algorithm identified by payload-hash-alg (258), matches the
payload. That check needs no encoding information, and applies whether or not deterministic-encodings
is present, subject to {{consistency}}.

A verifier that holds only a structured value -- for example, content it
received, stored, or decoded in a form other than the preimage itself --
has to re-create the preimage by encoding that value, and needs
deterministic-encodings to do so. Such a verifier MUST encode the value
with the encoding that deterministic-encodings identifies, and MUST NOT infer the encoding
from preimage-content-type (259) or from the structure of the value. If
deterministic-encodings is absent, or carries a value the verifier does
not recognize or implement, the verifier cannot re-create the preimage: it
MUST NOT report the content binding as verified, and MUST report it as
unverified rather than as failed.

A Hash Envelope produced without this parameter -- including any produced
before the parameter was registered -- is not defective: its content binding
can still be verified from the preimage bytes. Signature validity is
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
    / alg                     / 1: -7, # ES256
    / hash algorithm          / 258: -16, # sha-256
    / preimage type           / 259: "application/cbor",
    / deterministic encodings / TBD_1: 1, # core-deterministic
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
application/swid+cbor and deterministic-encodings to core-deterministic
(Value 1) -- recording its own choice, not a CoSWID requirement -- so that a
verifier holding the decoded tag knows how to re-create the preimage.

# Security Considerations {#security}

The preimage is exactly the bytes that the identified encoding produces,
not a rendering of them.

A deterministic encoding fixes the preimage for a given structured value, so
decoding a preimage and encoding the result again reproduces the preimage
only if decoding preserved that value exactly. Decoding into a programming
language's native types can lose distinctions the encoding depends on -- for
example, between integer and floating-point numbers, or the presence of a
tag. Choices that decide which data item represents a value, such as those
{{RFC8949}} Section 4.2.2 leaves to each protocol for tags and for integer
versus floating-point values, belong to the structured value, not to
the encoding that deterministic-encodings identifies. A choice that changes only how the same
data item is serialized, such as encoding every floating-point value as binary64, is a different
encoding and needs its own value. A producer that re-reads stored content before hashing
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
| deterministic-encodings | TBD\_1 | int | COSE Deterministic Encodings ({{iana-encodings}}) | Deterministic encoding applied to create the preimage of a Hash Envelope payload | This document |

The suggested value for TBD\_1 is 271, the lowest unassigned value in the
"Integer values from 256 to 65535" range of the COSE Header Parameters
registry as of 2026-10-18.

## COSE Deterministic Encodings Registry {#iana-encodings}

IANA is requested to create a new registry, "COSE Deterministic Encodings".
The registry identifies deterministic encodings of structured content; it
carries no Hash Envelope semantics of its own, and a value is meaningful only
through a parameter, such as deterministic-encodings ({{header-param}}),
that gives it a role. The registry is not specific to one data model or
content type: an entry applies wherever preimage-content-type (259) matches
its Applicable Content Types ({{consistency}}), and encodings for other
structured content types can be registered under the policy below.

A registry is used, rather than a fixed reference, for the reasons in
{{intro}}. A profile that has its own media type, such as
application/vnd.ipld.dag-cbor {{DAG-CBOR}}, is already identified by 259; content labelled
application/cbor, or with an application's own type such as
application/swid+cbor, is not. Rules that only restrict which data items may
occur produce Section 4.2.1 output and use value 1; this includes the
deterministic serialization of {{I-D.ietf-cbor-serialization}}, which only
excludes non-trivial NaNs (Appendix B.5 of that document).

Registration policy: Specification Required ({{RFC8126}} Section 4.6). The
registration template is: Value (an unsigned integer), Name, Description,
Applicable Content Types (media types and structured syntax suffixes, matched
against 259 as {{consistency}} specifies), Reference, and Change Controller.
The designated expert checks that the referenced specification defines
exactly one deterministic encoding for the value, together with any
constraints on the structured values it accepts, and that its Applicable
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
application/cose-key-set, application/cose-x509, application/cwt, and
application/multipart-core, and media types with
the +cbor, +cbor-seq, +cose, +cwt, or +sd-cwt structured syntax suffix.
For a CBOR sequence {{RFC8742}}, each data item is encoded according
to these requirements. Value 1 is exactly {{RFC8949}} Section 4.2.1; the
choices that Section 4.2.2 leaves to a protocol are not part of it
({{security}}).

--- back

# Acknowledgments
{:numbered="false"}

The authors thank Amaury Chamayou for a detailed review that aligned this
document's terminology, CDDL, and verification rules with {{RFC9995}} and
proposed the name core-deterministic, and Henk Birkholz for a review of its
scope, motivation, and terminology.
