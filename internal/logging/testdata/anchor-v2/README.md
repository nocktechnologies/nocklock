# Anchor v2 public record vectors

`vectors.json` pins the record-only N11742 format from
[`docs/design/anchor-chain-identity.md`](../../../../docs/design/anchor-chain-identity.md).
It contains **only public keys, records, signatures and hashes**. The one-time
fixture generator used an ephemeral random Ed25519 key in memory and emitted no
private key or seed. Do not regenerate these vectors when changing the encoder:
they are a compatibility contract for NockLock and a remote anchor server.

## Envelope and cases

The fixture envelope is `nocklock-anchor-v2-test-vectors-1` (not an HTTP protocol).
`public_key` is standard base64 of the 32-byte Ed25519 public key. Each case has an
`anchor`, the trusted `expected_agent_id` / `expected_chain_id`, exact
`canonical_hex`, and `expected_result`. Successful cases also pin
`snapshot_digest` as lowercase hex. The separate `legacy` object supplies the
signed v1 migration witness, its canonical bytes and digest.

| Case | Record-level expectation |
| --- | --- |
| `valid_chain_a` | Signature and expected pair verify. |
| `valid_chain_b` | Same key, different chain, higher count; signature and own pair verify. |
| `forged_chain_id` | A's signature with B's chain ID fails signature verification, even when the expected pair matches the changed record. |
| `swapped_chain_b_for_a` | B's authentic anchor fails A's expected pair check; it must not become a truncation verdict. B's positive control is `valid_chain_b`. |
| `migration_from_v1` | V2 signature covers the exact legacy snapshot digest; head and count match that v1 witness. This establishes a record binding, not migration authorization or completion. |

A server consumer must reject forged or swapped records before storage or a
row-count verdict. Server routing, authentication, pair-keyed storage, conditional
updates, and migration transactions are later slices and are **not tested or
implemented here**. Chain IDs in these public examples are fixed test values;
actual chain creation must use 32 cryptographically random bytes as designed.

## Record encoding

The exact eight JSON fields are `version`, `agent_id`, `chain_id`, `head_hash`,
`row_count`, `created_at`, `legacy_anchor_digest`, `sig`. The v2 decoder rejects
unknown, duplicate (including escaped aliases), case-folded, missing, or null
fields; trailing objects/data; malformed UTF-8; and invalid field encodings.

- `version` must be integer `2`.
- IDs, head hash and legacy digest must be 64 lowercase hexadecimal characters.
- `row_count` is an unsigned 64-bit integer. Consumers must preserve its full
  value, including values above JavaScript's exact-number range. Negative,
  fractional, exponent, quoted and overflowing representations are rejected.
- `created_at` is UTC RFC3339 with `Z` and zero to nine fractional digits. Its
  exact spelling is signed; equivalent timestamps are not normalized.
- `sig` encodes exactly 64 Ed25519 signature bytes. Accept padded or unpadded
  standard base64, with optional CR/LF wrapping; reject nonzero unused padding
  bits. Canonical JSON output always uses padded standard base64 without wraps.

`MarshalAnchorV2` emits compact JSON in the field order above. JSON whitespace,
field order and permitted signature spellings do not affect signed bytes or
snapshot digests. JSON encoding/decoding validates structure, **not authenticity**;
`VerifyAnchorV2` is mandatory before trusting the record and requires a public
key whose SHA-256 fingerprint matches `agent_id`, plus an explicit expected pair.

The signed byte layout is:

```
0x06 || u32be(len(agent_id)) || agent_id UTF-8 ||
chain_id[32 decoded bytes] || head_hash[32 decoded bytes] ||
u64be(row_count) || u32be(len(created_at)) || created_at UTF-8 ||
legacy_anchor_digest[32 decoded bytes]
```

A fresh v2 record uses 32 zero bytes for `legacy_anchor_digest`. Migration records
use the validated legacy snapshot digest; subsequent anchors must retain it
(enforced by later lifecycle/server work).

Snapshot digests are SHA-256 over the ASCII domain string
`nocklock-anchor-snapshot-v1` or `nocklock-anchor-snapshot-v2`, one NUL byte, that
version's canonical signed bytes, and the 64 decoded signature bytes. Authenticate
and validate the record before computing its digest. `LegacyAnchorSnapshotDigest`
uses the unchanged v1 `0x05` signed layout, canonical lowercase IDs/hashes, and
v1's verbatim `created_at` string contract. The v2 timestamp rule does not apply
to a v1 witness: offset timestamps and other spellings already accepted by the
v1 verifier remain valid when their original signatures verify. The timestamp
is never normalized before hashing. This adds no project identity to v1.

The existing v1 emitter, parser, verifier, CLI and network paths remain unchanged
and default to v1. Record format support alone does not resolve the current
one-remote-chain-per-signing-key limitation.
