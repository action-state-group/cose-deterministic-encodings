# Deterministic Encodings for COSE

Source for the Internet-Draft **`draft-mih-sokolov-cose-deterministic-encodings`**.

The COSE Hash Envelope (RFC 9995) carries the hash of content held elsewhere.
When that content is structured, more than one deterministic serialization of it
may be in use, and the Hash Envelope does not identify which one produced the
hashed bytes — so a verifier cannot reliably recompute the hash. This draft
defines a small IANA registry of deterministic encodings that any COSE usage can
reference, and one Hash Envelope protected-header parameter
(`deterministic-encodings`) as its first user, naming the deterministic
encoding a producer applied before hashing a Hash Envelope payload. The registry
is populated at issuance with `core-deterministic` (the Core Deterministic
Encoding Requirements of RFC 8949 §4.2.1). It extends the Hash Envelope through
its existing extension point and changes nothing in RFC 9995.

## Status

Individual submission; the intended working group is the COSE Working Group
(cose@ietf.org). **This is a working copy for co-author and working-group review;
consult the datatracker for any submitted revision.** Authors and affiliations
are as stated in the draft front matter.

## History before this repository

This draft was developed in
[`action-state-group/scitt-payload-binding`](https://github.com/action-state-group/scitt-payload-binding)
before being moved here as its own document; the commit history was carried over
with `git filter-repo` (authorship preserved). The pull-request discussion
threads from that development (including the review by Amaury Chamayou) remain on
the original repository — GitHub discussion threads do not move with the commits.

## Building

Requires [`kramdown-rfc`](https://github.com/cabo/kramdown-rfc) and
[`xml2rfc`](https://github.com/ietf-tools/xml2rfc).

```sh
make            # build the .xml and .txt
make idnits     # run the idnits checker over the .txt
make clean
```

## Reference code and vectors

A minimal emitter and verifier for the `deterministic-encodings` header, in
Python (`lib/python/`) and Go (`lib/go/`), each using only its standard
library, and a shared set of vectors (`vectors/vectors.json`). The emitter
encodes a structured value under `core-deterministic` (RFC 8949 §4.2.1),
hashes it, and builds the Hash Envelope protected header; the verifier
reports a content binding as verified, failed, or unverified as the draft's
"Producer and Verifier Behavior" section specifies. Signing is out of scope.
The vectors include the draft's own example, whose preimage and digest both
test suites read from the draft text. Label 271 is the value the draft suggests for TBD\_1; it is not an
assigned value.

```sh
python3 vectors/generate.py --check           # vectors.json is current
python3 -m unittest discover -s lib/python
(cd lib/go && go test ./...)
```

Current draft:
[`draft-mih-sokolov-cose-deterministic-encodings-00`](draft-mih-sokolov-cose-deterministic-encodings-00.md).
