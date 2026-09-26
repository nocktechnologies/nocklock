# Tamper-Evident Audit Log: Spec (v1: hash chain)

**Status:** Scoped, design questions answered. Ready to build.
**Author:** Mira (product owner). Filed 2026-09-14.

## Why

NockLock records every fence decision to a SQLite event log (`internal/logging`,
shipped). But the log is a plain table: `id, timestamp, event_type, category,
detail, blocked, session_id`. Anyone with file access, including a compromised
wrapped agent that can reach the `.db`, can edit a `blocked` row to `passed`,
delete the record of an exfiltration attempt, or truncate the tail, and nothing
detects it. `nocklock verify` today tests the *fences*, not the *record*.

That is the exact gap between "logging" and the product's goal of producing a
verifiable receipt of what the agent did. NockGuard, the sibling product,
already signs its audit chain (Ed25519 over canonical per-row bytes). NockLock's
own audit trail should first detect accidental corruption and edits that do not
recompute its integrity metadata. This spec is v1 of that: a SHA-256 hash chain.
It is not an unforgeable receipt against an attacker who can rewrite the
database. Ed25519 signing and external anchoring are scoped follow-ons
(§ Follow-on), and this chain is their prerequisite.

## Design decisions (answered, not listed)

**1. Hash chain first, signing and external anchoring later.**
A per-row hash chain detects accidental corruption and altered, deleted, or
reordered rows when the editor does not recompute the chain. It does not resist
an active file-write adversary: the algorithm is public and unkeyed, so that
adversary can recompute every affected hash and the in-database head. Ed25519
adds *authenticity* (proves NockLock wrote it), while an external head anchor
makes rollback or truncation observable; both need lifecycle and storage
decisions. The chain is useful integrity metadata and the substrate for those
controls. Build it now, but do not describe v1 alone as an unforgeable receipt.

**2. Canonical bytes are explicit and pinned by a byte-literal test.**
The hash covers a deterministic serialization of the row. Fix it precisely to
avoid the exact class of bug fixed in NCC #1902 today (field-order / type drift
silently breaking verification). The byte layout is, in order:

1. encoding version: the single byte `0x01`;
2. `id`: unsigned 64-bit integer, big-endian;
3. `timestamp`: UTC RFC 3339 with exactly nine fractional-second digits and a
   trailing `Z`, encoded as a length-prefixed string;
4. `event_type`: length-prefixed string;
5. `category`: length-prefixed string;
6. `detail`: length-prefixed string;
7. `blocked`: the single byte `0x00` for false or `0x01` for true; and
8. `session_id`: length-prefixed string.

A length-prefixed string is a `uint32` big-endian byte length followed by the
field's unmodified UTF-8 bytes. No Unicode normalization is applied. The
database-assigned `id` is included so reordering changes the encoded row.
`prev_hash` and `entry_hash` are excluded from `canonical_bytes(row)`;
`prev_hash` is decoded from its 64 lowercase hexadecimal characters to 32 bytes
and appended separately by the chain formula below. Include a test that asserts
the exact canonical byte string for a known row **independent of the hashing
function** (a test that hashes `_canonical_bytes()` itself cannot catch drift,
that was the #1902 lesson).

**3. Chain construction.**
Add two columns: `prev_hash TEXT NOT NULL` and `entry_hash TEXT NOT NULL`.
`entry_hash = hex(sha256(canonical_bytes(row) || prev_hash_bytes))`, where the
genesis row's `prev_hash` is the SHA-256 of the empty input (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855). The chain is
maintained inside the same transaction as the INSERT so a crash can't leave a
row without its link. Reads (`Query`, `log` command) are unchanged; the chain is
verification metadata.

**4. Detection guarantee, honest about the limit.**
A pure per-row prev-hash chain detects mutation, deletion, and reordering only
when the editor does not recompute the affected hashes. Maintain a single-row
`chain_head` table holding the highest `entry_hash` and row count, updated in
the same transaction. `nocklock verify --audit` walks the chain and checks that
the head matches the last row and count. This also detects naive tail truncation.

An active adversary with write access to the SQLite file can defeat every v1
check by recomputing the public, unkeyed chain and rewriting `chain_head` in the
same file. This caveat applies to mutation, deletion, reordering, and truncation,
not only to the tail. Resistance to that adversary requires a trusted signature
or external head anchor (§ Follow-on). Document this limit in the verify output
and README; a successful verification means the stored rows and integrity
metadata are internally consistent, not that the history is authentic.

**5. Migration of existing logs.**
Existing DBs have rows with no hash columns. On first open after upgrade:
`ALTER TABLE events ADD COLUMN prev_hash` / `entry_hash` (nullable add, then
populate). Walk existing rows in `id` order and chain them forward once. These
pre-existing rows are **structurally chained but not retroactively
authenticated**: they were written before the chain existed, so the chain only
proves they haven't changed *since migration*. Mark the migration point with a
`chain_genesis` event carrying the migration timestamp, and say so in verify
output. Never claim pre-migration history is proven.

**6. `nocklock verify --audit` verdict mirrors NockGuard.**
Walk the chain from genesis; on success print `AUDIT: CONSISTENT — N entries
verified, hash chain intact (not externally anchored)`; on the first broken link
print `AUDIT: TAMPERED — chain breaks at entry <id> (<what mismatched>)` and exit
non-zero. Expose the current head hash so an external watcher (NockCC) can pin
it.

## Scope for the build (v1)

- `internal/logging`: schema columns, canonical-bytes encoder + byte-literal
  test, chain-on-insert (transactional), migration/backfill, `chain_head`
  table, a `VerifyChain()` method returning a structured result.
- `internal/cli/verify.go`: add `--audit` flag (or `nocklock audit verify`
  subcommand, builder's call, keep it discoverable) wired to `VerifyChain()`.
- Tests: canonical byte-literal pin; chain intact over N rows; each tamper class
  detected (mutate a `blocked` bit, reorder, delete a middle row, mutate
  `detail`); migration backfill; concurrency (chain stays consistent under the
  existing concurrent-Log test).
- README: a short "Tamper-evident audit log" section stating the v1 guarantee
  and its honest limit.

**Out of scope for v1 (follow-on):** Ed25519 signing; external head anchoring
(push the head to NockCC on session end for true tail-truncation resistance);
cross-session chaining.

## Build constraints

- Pure Go crypto (`crypto/sha256`), no CGO, no new heavy deps.
- **Safe to build and test from any host**: no netns, no root, no sudo, no
  fence enforcement. Standard `go test ./internal/logging/ -race` only.
- Gate on the repo's normal review legs (claude-review + CodeRabbit at head, CI
  green, 0 unresolved threads), merge is the product owner's call.

## Follow-on (filed intent, not this build)

1. **Ed25519 signing** over the same canonical bytes, per-row, key in the
   user's OS keychain / a NockLock-managed key file with 0600 perms, turns
   tamper-evidence into authenticity. This chain is the substrate.
2. **External head anchor**: on session end, push `chain_head` to NockCC (or a
   local append-only anchor file the agent can't reach) so tail-truncation is
   detectable even if `chain_head` in the DB is rewritten.
