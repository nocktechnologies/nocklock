# Tamper-Evident Audit Log — Spec (v1: hash chain)

**Status:** Scoped, design questions answered. Ready to build.
**Author:** Mira (product owner). Filed 2026-09-14.

## Why

NockLock records every fence decision to a SQLite event log (`internal/logging`,
shipped). But the log is a plain table: `id, timestamp, event_type, category,
detail, blocked, session_id`. Anyone with file access — including a compromised
wrapped agent that can reach the `.db` — can edit a `blocked` row to `passed`,
delete the record of an exfiltration attempt, or truncate the tail, and nothing
detects it. `nocklock verify` today tests the *fences*, not the *record*.

That is the exact gap between "logging" and the product's own thesis: an
**unforgeable receipt** of what the agent did. NockGuard, the sibling product,
already signs its audit chain (Ed25519 over canonical per-row bytes). NockLock's
own audit trail must at minimum be **tamper-evident**. This spec is v1 of that:
a SHA-256 hash chain. Ed25519 signing (authenticity, not just integrity) is a
scoped follow-on (§ Follow-on), and this chain is its prerequisite.

## Design decisions (answered, not listed)

**1. Hash chain first, signing later.**
A per-row hash chain gives tamper-*evidence* — detect any altered, deleted, or
reordered row — with zero key management. Ed25519 adds *authenticity* (proves
NockLock wrote it) but needs a key, a key-storage story, and a compromise story.
The chain is 80% of the moat value at 20% of the complexity, and signing is
strictly built on top of it. Build the chain now; do not block it on the key
decision.

**2. Canonical bytes are explicit and pinned by a byte-literal test.**
The hash covers a deterministic serialization of the row. Fix it precisely to
avoid the exact class of bug fixed in NCC #1902 today (field-order / type drift
silently breaking verification): fields in a FIXED order, each length-prefixed
(`uint32` big-endian byte length + UTF-8 bytes) so no delimiter can be forged by
crafted content, integers as fixed-width big-endian, `blocked` as a single
`0x00`/`0x01` byte. Include a test that asserts the exact canonical byte string
for a known row **independent of the hashing function** (a test that signs
against `_canonical_bytes()` itself cannot catch drift — that was the #1902
lesson). Version the encoding with a leading `v1` byte so a future change is
detectable, not silent.

**3. Chain construction.**
Add two columns: `prev_hash TEXT NOT NULL` and `entry_hash TEXT NOT NULL`.
`entry_hash = hex(sha256(canonical_bytes(row) || prev_hash_bytes))`, where the
genesis row's `prev_hash` is a fixed 32-zero-byte constant. The chain is
maintained inside the same transaction as the INSERT so a crash can't leave a
row without its link. Reads (`Query`, `log` command) are unchanged; the chain is
verification metadata.

**4. Truncation detection — honest about the limit.**
A pure per-row prev-hash chain detects mutation and reordering but NOT deletion
of the *tail* (drop the last N rows and the remaining chain still verifies).
Close it as far as v1 honestly can: maintain a single-row `chain_head` table
holding the highest `entry_hash` and the row count, updated in the same
transaction. `nocklock verify --audit` walks the chain AND checks the head
matches the last row + count. This detects tail-truncation UNLESS the attacker
also rewrites `chain_head` — which they can, since it's in the same file. So v1's
honest guarantee is: **detects any in-place mutation, reordering, or
non-tail deletion; detects tail-truncation unless `chain_head` is also rewritten
in lockstep.** Full tail-truncation resistance needs an external anchor (§
Follow-on). Document this limit in the verify output and the README — no silent
success about our own guarantee.

**5. Migration of existing logs.**
Existing DBs have rows with no hash columns. On first open after upgrade:
`ALTER TABLE events ADD COLUMN prev_hash` / `entry_hash` (nullable add, then
populate). Walk existing rows in `id` order and chain them forward once. These
pre-existing rows are **structurally chained but not retroactively
authenticated** — they were written before the chain existed, so the chain only
proves they haven't changed *since migration*. Mark the migration point with a
`chain_genesis` event carrying the migration timestamp, and say so in verify
output. Never claim pre-migration history is proven.

**6. `nocklock verify --audit` verdict mirrors NockGuard.**
Walk the chain from genesis; on success print `AUDIT: PROTECTED — N entries
verified, hash chain intact` (matching NockGuard's `verify` verdict shape so the
two products read consistently); on the first broken link print `AUDIT:
TAMPERED — chain breaks at entry <id> (<what mismatched>)` and exit non-zero.
Expose the current head hash so an external watcher (NockCC) can pin it.

## Scope for the build (v1)

- `internal/logging`: schema columns, canonical-bytes encoder + byte-literal
  test, chain-on-insert (transactional), migration/backfill, `chain_head`
  table, a `VerifyChain()` method returning a structured result.
- `internal/cli/verify.go`: add `--audit` flag (or `nocklock audit verify`
  subcommand — builder's call, keep it discoverable) wired to `VerifyChain()`.
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
- **Safe to build and test from any host** — no netns, no root, no sudo, no
  fence enforcement. Standard `go test ./internal/logging/ -race` only.
- Gate on the repo's normal review legs (claude-review + CodeRabbit at head, CI
  green, 0 unresolved threads) — merge is the product owner's call.

## Follow-on (filed intent, not this build)

1. **Ed25519 signing** over the same canonical bytes, per-row, key in the
   user's OS keychain / a NockLock-managed key file with 0600 perms — turns
   tamper-evidence into authenticity. This chain is the substrate.
2. **External head anchor** — on session end, push `chain_head` to NockCC (or a
   local append-only anchor file the agent can't reach) so tail-truncation is
   detectable even if `chain_head` in the DB is rewritten.
