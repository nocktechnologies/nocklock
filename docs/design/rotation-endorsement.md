# Offline rotation endorsement v1

## Format

This separate record leaves AnchorV2, its `0x06` domain and canonical bytes
unchanged. JSON has exactly these ten fields: `version`, `lineage_root`,
`old_chain_id`, `new_chain_id`, `head_hash`, `row_count`, `successor_public_key`,
`old_public_key`, `sig`, `acceptance`. Byte strings are 64 lowercase hex
characters; signatures follow the anchor standard-base64 rules. Empty
`acceptance` explicitly means unused. Missing fields, null, unknown/duplicate
or differently cased fields, trailing data and malformed UTF-8 are rejected.

The retiring key signs these deterministic bytes:

```
"nocklock-rotation-endorsement-v1\x00" || version[1 byte = 1] ||
lineage_root[32] || old_chain_id[32] || new_chain_id[32] ||
head_hash[32] || row_count[u64be] || successor_public_key[32] || old_public_key[32]
```

The fields bind the lineage root (first-key public key SHA-256 fingerprint,
independent of both chains), old chain identity (`chain_id`, 32 bytes), new
chain identity (`chain_id`, 32 bytes), old tail (`head_hash`, 32 bytes) and old
`row_count` (u64be), and successor public key (32 bytes). The retiring public key
is also signed. Fixed lengths need no length prefixes; there is no timestamp.

The endorsement digest is SHA-256 of
`"nocklock-rotation-endorsement-digest-v1\x00" || canonical_bytes || sig[64]`.
The successor signs `"nocklock-rotation-acceptance-v1\x00" || digest[32]`.
This countersignature is the single definition of use: the successor accepted
this exact signed transition. It detects an unaccepted endorsement without
adding an AnchorV2 field, reading an archive, or claiming operational adoption.

## Verifier contract

`VerifyRotationEndorsement` takes the bundle, independently trusted first-key
root, trusted old and new `ChainIdentity` records, expected old tail/count and
successor public key. Callers must establish these expectations independently;
copying them out of the bundle defeats substitution and truncation checks.
On the first rotation the root is the retiring key's own fingerprint. For later
rotations the caller must already trust the retiring identity's relationship to
the first-key root; this function verifies one edge, not an entire lineage. Chain identity schema and encodings are validated, but only
chain IDs and key fingerprints participate in transition matching; registration
state and legacy anchor digests are not transition attestations.

Canonical encoding and both signatures are verified before tail/count
comparison. `errors.Is` distinguishes root mismatch, retiring identity mismatch,
tail/count mismatch (including truncation), replay to another successor or new
chain, missing endorsement, unused endorsement, bad signature and malformed
encoding. Old and new chain IDs must differ. An absent bundle is missing; an
absent JSON field is malformed. A missing acceptance is unused only when its
field is present and empty. Rechecking the exact same transition is idempotent.
No offline check can distinguish a replayed copy of an identical bundle from its
first presentation, so the caller must record accepted transitions. There is no
CLI command or state mutation.

## Vectors

[Public vectors](../../internal/logging/testdata/rotation-endorsement/README.md)
pin canonical bytes, endorsement digests and acceptance bytes. Cases cover an
independent root, a first rotation whose root is the retiring key's own
fingerprint, zero/large/max counts, every signed-field tamper, substituted root,
wrong retiring identity, a signed transition into the chain it retires, replay to
another chain/key, old-tail divergence and count truncation/extension,
missing (absent or whitespace-only) and unused endorsements, both bad signatures,
and strict JSON/hex/base64 failures. Every rejection references a restored valid
control. Keys are generated ephemerally in memory; only public material is saved.

## LIMITS

An endorsement proves that the holder of the old key signed a transition from a
specific lineage root and tail to the successor key. It cannot restore trust in
an old key that was compromised before or during the rotation. It does not prove
what the old key did after the tail. It is not key switching and not remote
migration, and it does not replace the remote v2 pin. Successor acceptance proves
possession and acceptance, not execution, enrollment, archive availability or
uniqueness of the retiring key's endorsements.
