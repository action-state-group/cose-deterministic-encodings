---
title: "Deterministic Encodings for COSE"
abbrev: "COSE Deterministic Encodings"
docname: draft-mih-sokolov-cose-deterministic-encodings-02
date: 2026-11-19
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
  RFC3986:
  RFC8949:
  RFC9052:
  RFC9995:
  I-D.ietf-cbor-serialization:

informative:
  RFC3275:
  RFC9393:
  RFC9711:
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
only if it applies the same deterministic encoding as the producer. CBOR
permits more than one encoding of the same data item, and the preimage
content type does not identify the encoding that was applied. This
document defines a COSE Hash Envelope protected-header
parameter that identifies the encoding by a URI, and one URI for CBOR
content, which identifies the deterministic serialization that the CBOR
working group defines in draft-ietf-cbor-serialization. Other URIs are out
of scope.

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
encoding the producer applied. CBOR permits more than one encoding of the
same data item ({{RFC8949}} Section 4.2), and a producer need not apply a
deterministic one: `{"x": 1.5}` is `a1 61 78 f9 3e 00` under deterministic
serialization and `a1 61 78 fb 3f f8 00 00 00 00 00 00` when every
floating-point value is written as binary64, and both are valid CBOR. The
preimage-content-type (259) names the type of the content, such as
application/swid+cbor, not the encoding applied to it. A verifier that
assumes an encoding the producer did not state cannot tell a modified
value from one encoded another way, and reports as failed a content
binding it could not check. The parameter lets the verifier tell the two
apart: when the producer states the encoding, a mismatch means the value
differs; when it does not, the outcome is unverified ({{verification}}).

This document defines one protected-header parameter,
deterministic-encodings, which identifies that encoding by a URI, and one
URI for CBOR content: the one that identifies the deterministic
serialization the CBOR working group defines ({{cbor-value}}). This
document defines no encoding of its own. As with the hash algorithm in
payload-hash-alg (258), the producer states its choice and the verifier
follows it. Naming a canonicalization or a profile by a URI has precedent:
XML Signature names the canonicalization algorithm applied to the signed
content by a URI ({{RFC3275}} Section 6.1), and the eat_profile claim names
a profile, including the encoding choices it fixes, by a URI ({{RFC9711}}
Sections 4.3.2 and 6.4). It uses the extension point the Hash
Envelope protected header already provides ({{Section 4 of RFC9995}}:
`* (int / tstr) => any`). The encoding is not carried as a media-type
parameter of preimage-content-type (259). The application/cbor media type defines no
parameters ({{RFC8949}} Section 9.3), so such a parameter would have to be
registered for every media type the encoding applies to, and a CoAP
Content-Format number carries only the parameters fixed in its registry
entry ({{RFC7252}} Section 12.3), so each pairing of media type and encoding
would also need its own number. A profile that has its own media type, such
as application/vnd.ipld.dag-cbor {{DAG-CBOR}}, is already identified by 259;
content labelled application/cbor, or with an application's own type such as
application/swid+cbor, is not.

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
  carries a value the verifier does not recognize or implement, or the
  verifier cannot produce the identified encoding of that value
  ({{verification}}); or if it does not implement the hash algorithm
  identified by payload-hash-alg (258).

# The deterministic-encodings Header Parameter {#header-param}

TBD\_1:
: deterministic-encodings. The deterministic encoding with which a
  structured value was serialized to create the bytes that were hashed
  (preimage) to produce the payload, given as a URI ({{cbor-value}}).

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
    ? &(deterministic_encodings: TBD_1) => tstr,
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

The value of deterministic-encodings is a text string holding an absolute
URI ({{RFC3986}} Section 4.3). The URI identifies the specification of the
encoding; a verifier compares it with the URIs it implements character by
character ({{RFC3986}} Section 6.2.1) and does not dereference it. Whoever
specifies an encoding issues its URI; a producer copies the URI of the
encoding it applied.

## The Value for CBOR Content {#cbor-value}

This document defines one value of deterministic-encodings, for CBOR
content. It is the URI of Section 5 of {{I-D.ietf-cbor-serialization}},
which defines deterministic serialization, the serialization that Section 8
of that document names "dtrm". The URI is shown here on two lines; the value has no line
break or space between them:

~~~
https://datatracker.ietf.org/doc/html/
draft-ietf-cbor-serialization-13#section-5
~~~

RFC Editor: please replace this URI, here and in {{examples}}, with
https://www.rfc-editor.org/rfc/rfcNNNN#section-N, where NNNN is the RFC
number of {{I-D.ietf-cbor-serialization}} and N the number of its section
that defines deterministic serialization, and remove this note.

The value states that the structured value was encoded with deterministic
serialization as that specification defines it: the Core Deterministic
Encoding Requirements of {{RFC8949}} Section 4.2.1, except that
non-trivial NaNs are excluded, as Sections 4.1 and 5.1 and Appendix B.5 of
{{I-D.ietf-cbor-serialization}} specify. For a CBOR sequence {{RFC8742}}, each
data item is encoded according to these requirements. Apart from that rule
for NaNs, the choices that {{RFC8949}} Section 4.2.2 leaves to a protocol
are not part of this encoding ({{security}}).

The URI names one version of the CBOR working group's text. If a later
version changes deterministic serialization, for example the rule for
NaNs, the changed serialization has a different URI, and Hash Envelopes
that carry this one keep their meaning.

This document defines no other value. Other deterministic encodings of
CBOR are out of scope; one would come from the CBOR working group, with a
URI of its own. Deterministic encodings of other content, such as JSON,
are also out of scope; the specification that defines such an encoding
would issue its URI and state its Applicable Content Types
({{consistency}}).

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

The Applicable Content Types of the value defined in {{cbor-value}} are
application/cbor,
application/cbor-seq, application/cose, application/cose-key,
application/cose-key-set, application/cose-x509, application/cwt, and
application/multipart-core, and media types with
the +cbor, +cbor-seq, +cose, +cwt, or +sd-cwt structured syntax suffix. When
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
example, one pairing the value defined in {{cbor-value}} with
application/json. A verifier
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
not recognize or implement -- for example, a URI that this document does
not define, or a value that is not a text string -- the verifier cannot
re-create the preimage: it
MUST NOT report the content binding as verified, and MUST report it as
unverified rather than as failed. The same applies when the verifier
cannot produce the identified encoding of the structured value -- for
example, when its encoder rejects a NaN that the encoding excludes
({{cbor-value}}).

A Hash Envelope produced without this parameter -- including any produced
before the parameter was registered -- is not defective: its content binding
can still be verified from the preimage bytes. Signature validity is
unaffected by any content-binding outcome: a verifier that has not
established the content binding can still validate the signature of the
COSE_Sign1 as specified in {{RFC9052}}.

# Examples {#examples}

These use Extended Diagnostic Notation ({{RFC8610}} Appendix G), in the
style of {{RFC9995}} Section 4.1; signature and key material are truncated.
A long text string is shown in two parts, which form one string
({{RFC8610}} Appendix G.4).

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
    / deterministic encodings / TBD_1:
        "https://datatracker.ietf.org/doc/html/"
        "draft-ietf-cbor-serialization-13#section-5",
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
application/swid+cbor and deterministic-encodings to the URI defined in
{{cbor-value}} -- recording
its own choice, not a CoSWID requirement -- so that a
verifier holding the decoded tag knows how to re-create the preimage.

A Hash Envelope over JSON content can carry deterministic-encodings only
with a URI that some other specification issues, such as
"https://json-spec.example/deterministic" with preimage-content-type
"application/json". This document does not define that URI. A verifier
that implements only this document and holds the decoded JSON value, not
its bytes, reports the content binding as unverified ({{verification}});
a verifier that holds the preimage checks its digest as {{RFC9995}}
Section 5.3 describes.

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
encoding, not the one defined in {{cbor-value}}. A producer that re-reads
stored content before hashing
MUST ensure the preimage it hashes is byte-identical to the encoding's own
output. A verifier that re-creates a preimage from a structured value
({{verification}}) needs that value exactly as the producer encoded it;
otherwise its recomputed digest can differ from the payload, and the content
binding is then reported as failed.

A verifier does not dereference the URI in deterministic-encodings, so
the value causes no network access, and a URI whose resource has moved or
changed does not change the verifier's result. A producer that states a
URI the verifier does not implement can cause only the outcome unverified,
never verified ({{verification}}).

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
| deterministic-encodings | TBD\_1 | tstr | none | Deterministic encoding applied to create the preimage of a Hash Envelope payload | This document |

The suggested value for TBD\_1 is 271, the lowest unassigned value in the
"Integer values from 256 to 65535" range of the COSE Header Parameters
registry as of 2026-11-14.

--- back

# Changes from Version 01
{:removeinrfc}

* The value of deterministic-encodings is a URI, not a token. Version 01
  used the text string "dtrm", the name {{I-D.ietf-cbor-serialization}}
  gives to deterministic serialization in its CDDL control operator. The
  one URI this document defines identifies the same serialization, Section
  5 of that document, now version 13 ({{cbor-value}}). The NaN rule is
  unchanged. Until that document is an RFC, the URI names the version of
  the draft; the RFC Editor replaces it.

* Other URIs, for other encodings of CBOR and for encodings of other
  content types, are out of scope ({{cbor-value}}). A verifier of this
  version handles the text string "dtrm" as a value it does not recognize
  ({{verification}}).

* {{I-D.ietf-cbor-serialization}} is a normative reference, since the
  value is defined by it.

* Examples show the URI and a JSON case that this document does not cover
  ({{examples}}); Security Considerations state that the URI is not
  dereferenced ({{security}}).

* The abstract and the introduction no longer rest on RFC 8949 describing
  more than one deterministic encoding. The introduction shows instead a
  value that has two valid CBOR encodings, one of them deterministic, and
  why stating the encoding lets a verifier report unverified rather than
  failed ({{intro}}).

# Changes from Version 00
{:removeinrfc}

* The "COSE Deterministic Encodings" registry is removed. This document
  requests only the registration of the header parameter ({{iana}}).

* The value of deterministic-encodings became the text string "dtrm",
  the name {{I-D.ietf-cbor-serialization}} gives to its
  deterministic serialization. Version 00 used the integer 1, the value its
  registry assigned to core-deterministic. A verifier of this version
  handles the integer 1 as a value it does not recognize
  ({{verification}}).

* "dtrm" excludes non-trivial NaNs, as {{I-D.ietf-cbor-serialization}}
  defines. In version 00, value 1 was {{RFC8949}} Section 4.2.1 without
  that exclusion.

* The Applicable Content Types, which version 00 put in the registry
  entry, are listed in {{consistency}}.

* A verifier that cannot produce the identified encoding of a structured
  value reports the content binding as unverified ({{verification}}).

# Acknowledgments
{:numbered="false"}

The authors thank Amaury Chamayou for a detailed review that aligned this
document's terminology, CDDL, and verification rules with {{RFC9995}} and
proposed the name core-deterministic, and Henk Birkholz for a review of its
scope, motivation, and terminology.
