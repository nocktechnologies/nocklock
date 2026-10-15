# Bounded anchor verification: profile and design

Status: profiling and design for Nock #11775. Nothing here changes runtime behavior; the only code added is a profiling recipe and one negative-control test (`internal/logging/anchor_verify_profile_test.go`, `anchor_head_only_test.go`). Implementation is a separate PR after Mira reviews this design. It sequences before N11766 (opt-in periodic committed-head v2 checkpoints).

## Problem

Anchor emission authenticates the whole local chain synchronously. `EmitAnchor` (`internal/logging/anchor.go`) and `emitAnchorV2Locked` (`internal/logging/anchor_chain.go`) call `VerifyChainSigned`, which walks every row in `verifyChainInTransaction` (`internal/logging/logger.go`). `finishAnchorSession` (`internal/cli/anchor_v2.go`) runs that on every `wrap` teardown, and `VerifyAgainstAnchorV2` runs the same walk for `anchor verify`.

Three properties matter for periodic checkpoints:

1. **Cost is linear in total rows, not in new rows.** Every checkpoint re-verifies rows verified by the previous one.
2. **The walk ignores its deadline.** `verifyChainInTransaction` takes no context and queries with `tx.Query`. `EmitAnchor` takes none either. In the v2 path `ctx` bounds only the identity-lock acquisition (`EmitAnchorV2Context`). `anchorPushTimeout` (5 s, `internal/cli/anchor_push.go`) therefore bounds lock waits and HTTP, not the walk.
3. **The walk runs under the chain-identity store lock.** `emitAnchorV2Locked` verifies while `EmitAnchorV2Context` holds the lock that `Prune` and registration also take, so a long walk blocks them.

## Measurements

Recipe (read-only, no root, no network, no new dependency):

```
NOCKLOCK_PROFILE_ROWS=100000 go test ./internal/logging \
  -run TestProfileAnchorVerification -count=1 -v -timeout 30m
```

On a host with umask `002` run `umask 022` first, or the logging tests that check state-directory modes fail on 0775 temp directories. The test builds a genuinely signed chain through `LogBatch` (row signature plus head signature per row, the normal append path), then times each phase three times in-process.

| Item | Value |
| --- | --- |
| Host | linux/amd64, AMD Ryzen 9 PRO 8945HS, 16 CPU, Linux 7.0.0, go1.26.4 |
| Commit | `4284341` (`origin/next`) plus the two test files in this PR |
| Warm | In-process repeats after the first populate; OS page cache warm |
| "Cold-open" | A new `Logger` and connection pool in the same process; OS page cache and Go heap still warm. A truly cold page cache needs root (`drop_caches`) and was not measured |
| Remote | Disabled. No phase touches the network; push, enroll and remote verify are out of scope of every number below |

100,000 rows, 43.3 MB database, median of three warm runs:

| Phase | Median | Share of `VerifyChainSigned` |
| --- | --- | --- |
| `VerifyChainSigned` (full authentication) | 4.048 s | 100% |
| `EmitAnchor` (`VerifyChainSigned` + one signature) | 3.994 s (runs: 4.044, 3.949, 4.205) | n/a |
| Ed25519 row-signature verification only (rows in memory) | 3.910 s | about 97% |
| SQLite `SELECT` + `Scan` only | 0.119 s | about 3% |
| Hash recompute only (rows in memory) | 0.033 s | about 1% |
| `VerifyChain` (hash only, no key) | 0.162 s | about 4% |
| Prefix rescan prototype: scan + hash chain + sig-inclusive SHA-256 digest, no signature verify (option C below). A lower bound: the real step adds a read transaction, receipt and head checks | 0.17 to 0.18 s (two runs of three) | about 4% |
| `ed25519.Sign` of one anchor | 0.020 ms | <0.001% |
| `WriteAnchor` (temp file + rename) | 0.09 to 0.42 ms | <0.01% |
| Cold-open `EmitAnchor` | 4.150 s | n/a |

10,000 rows (4.3 MB) for scaling: `VerifyChainSigned` 0.393 s, signatures 0.377 s, scan 12.8 ms, hash 3.6 ms, prefix rescan 18.2 ms. Everything scales about 10x for 10x rows, as expected for a linear walk. Repeat spread is up to about 10% on this host (three hand-timed repeats, no GC control), so read the shares as approximate. The phases are additive (3.910 + 0.119 + 0.033 is about 4.06 s against 4.05 s measured).

Findings:

- **About 97% of the cost is one Ed25519 verification per row (about 39 µs/row here).** Signing the anchor and writing the file are noise. SQLite and hashing together are about 1.5 µs/row.
- The sibling measurement in the Nock (Apple M4, darwin-arm64, Go 1.26.5, PR209 head `937115fd`: 2.970 s `EmitAnchor`, 3.122 s `finishAnchorSession` at 100,000 rows) is the same shape on different hardware. It was not reproduced here and is quoted from the Nock. This host is about 1.35x slower per row. Neither number is a universal bound.
- The nominal 5 s teardown budget would cover roughly 125,000 rows on this host and more on the M4. Linear extrapolation (not measured) puts 1,000,000 rows at about 40 s full verification against about 1.7 s for a prefix rescan.
- The prefix rescan costs about 1/24 of the full walk when nothing is new.

## Threat model

Assets: the claim that an emitted anchor attests a chain whose every row was written by the key holder, in order, with nothing removed from the middle, and whose head signature covers it.

| Actor | Capability | Required outcome |
| --- | --- | --- |
| A1 keyless writer | Arbitrary writes to `events.db` (edit/strip/reorder/insert rows, rewrite `chain_head`, rewrite keyless hashes), including while a long-lived signing `Logger` is open | Detected: no anchor, `forged`/`tampered` |
| A2 rollback | Restore an older copy of `events.db` (consistent: rows, head, signature all old) | Not detectable locally today, and must not become less detectable. The remote v2 pin detects it (`truncation`) |
| A3 copier | Copy a database, or any cached state, to another project or key | Cached state is never trusted for different bytes or a different key |
| A4 key holder | Has the audit private key | Out of scope, as today |
| A5 interruption | Kill, crash, disk full, or deadline mid-walk | No anchor and no `authentic` result from a partial walk; state is recoverable |
| A6 concurrent appender | Logger appends while verification runs | Anchor covers exactly one snapshot |

Out of scope: root on the host, theft of the key, compromise of the remote pin together with local trusted state (`anchor-chain-identity.md`).

## Why a signed-head-only shortcut is not equivalent

The tempting optimization is to verify only `chain_head.head_sig` (plus, at most, the keyless hash chain). It is not equivalent, and the repo now shows it: `TestHeadOnlyVerificationMissesLaunderedTamper`.

1. A keyless writer edits a middle row and recomputes the keyless hashes and `chain_head.entry_hash` (the head signature is now stale; the head-only check correctly fails).
2. A long-lived signing `Logger` appends. `logInTransaction` reads `chain_head.entry_hash` without re-verifying history (it validates the head signature only when the log is opened, `validateAdoptedSigningHead`) and signs a head over the tampered chain.
3. The head-only check (hash chain plus head signature) now passes. Per-row signatures still fail: `VerifyChainSigned` reports `forged`, and `EmitAnchor` refuses.

Per-row signatures are what authenticate row content independently of the logger's current head. Any shortcut must therefore preserve their verdict, which is what option C does (by proof about previously verified bytes, not by skipping).

## Options

**A. Status quo, bound the walk (necessary, not sufficient).** Thread a `context.Context` through the walk (`QueryContext`, check every 1,024 rows) and return a typed `ErrVerifyInterrupted`. Equivalent detection by construction. Fixes property 2 only; cost stays linear.

**B. Parallel signature verification (stdlib only).** Verify row signatures on a worker pool while one goroutine owns the hash-chain walk. Equivalent detection. On this host's 16 cores the dominant 3.9 s could fall roughly 8 to 10x (not measured). Costs: CPU burst at teardown, hardware-dependent, must report the lowest broken id deterministically, and still linear. Optional complement, not the primary answer.

**C. Signed verification receipt with prefix rescan (recommended).** Cache the result of a previous complete signature verification as a key-signed receipt, and on the next run re-prove that the prefix bytes are unchanged without re-verifying signatures. Detailed below.

### Rejected

| Option | Why rejected |
| --- | --- |
| R1 Verify only `head_sig` | Fooled by laundering (above); not equivalent |
| R2 Hash chain + `head_sig`, skip row sigs | Same laundering test, same failure |
| R3 Sign "verified-through" into the head signature | The head is signed by the appending `Logger`, which does not verify history; it would sign verified-through over unverified rows (same laundering) |
| R4 Unsigned cache of "verified through row k" (in SQLite or a sidecar) | A keyless writer rewrites the cache to match the tampered rows |
| R5 Trust file size, mtime, inode or `PRAGMA data_version` to skip the rescan | A writer restores or preserves them; fine as a hint, never as trust |
| R6 Sample or probabilistic row verification | Tamper outside the sample passes by design |
| R7 On timeout, emit an anchor from the stored head, or skip verification | Exactly the unauthenticated shortcut; violates fail-closed. On timeout there is no anchor, loudly |
| R8 Batch Ed25519 verification | Not in the standard library; would need a new dependency |
| R9 Drop teardown emission | Loses the final head anchor |
| R10 Detach emission into a background goroutine at exit | Dies with the process; fire-and-forget hides failure. Periodic in-session work (N11766) is the right home for background effort |

## Recommended design

Three independently landable steps, in order.

### Step 1: context-bounded, fail-closed walk (prerequisite, no cache)

- `verifyChainInTransaction` gains a context. Row and prefix loops check `ctx.Err()` every 1,024 rows; queries use `QueryContext` so SQLite is interrupted too.
- Interruption returns `ErrVerifyInterrupted` (distinct from `Intact=false`, `forged`, `tampered`). It is never converted to `authentic`, and never reported as tampering. `EmitAnchor`, `EmitAnchorV2Context`, `VerifyAgainstAnchorV2Context` and `finishAnchorSession` propagate it: no anchor is written, the existing warning path prints "chain anchor not written", and the process still exits normally.
- Run the walk without holding the identity store lock where the lock is not needed for the snapshot; at minimum, release on interruption promptly (the lock is already released by `defer store.close()`).
- Alone this satisfies "bounded", at the cost of a missing final anchor for stores too large for the budget. Steps 2 and 3 remove that cost.

### Step 2: signed verification receipt (option C)

**Receipt.** A single-row table `verify_receipt` in `events.db`. It attests a *verified prefix*, not an authentic chain: it is written only by code that has just checked linkage, hash and signature of every row through `through_id` within one read snapshot, under the signing key. Reaching the snapshot head and a clean head signature is a separate gate that only anchor emission requires. Fields, signed with the audit key under a new domain byte (unused today: rows `0x01`, head `0x03`, anchor v1 `0x05`, anchor v2 `0x06`; confirm at implementation) so it cannot be confused with another signature:

`version || key_fingerprint || signed_genesis_at || unsigned_through_id || through_id || through_count || through_head_hash || D`

where `D` is the rolling digest `D_i = SHA-256(D_{i-1} || entry_hash_i || entry_sig_i)` over every row through `through_id` (empty `entry_sig` for pre-adoption rows).

**Use.** On verification with the receipt present:

1. Load the receipt. Ignore it (fall back to the full walk, Step 1 semantics) unless: the version is known; the signature verifies under the supplied public key; the fingerprint equals the key's; and `signed_genesis_at` and `unsigned_through_id` equal the current head metadata.
2. In one read transaction, rescan rows `1..through_id`: check `prev_hash` linkage, recompute each `entry_hash` from the row's canonical bytes, compare to stored, and fold `D`. Require the recomputed `through_head_hash`, `through_count` and `D` to equal the receipt. Any mismatch discards the receipt and runs the full walk, so diagnostics (first broken id and reason) are identical to today.
3. Verify signatures (and the stripped-signature rule) only for rows after `through_id`, then run the unchanged head checks (row count, head hash, head signature, `classifySigState`).
4. Never trust the receipt for the head: the head signature, count and hash are always re-checked.

**Why detection is equivalent.** Full verification's verdict on rows `1..k` is a function of `(canonical bytes, prev_hash, entry_hash, entry_sig)` per row, the head metadata and the key. A matching receipt means (a) an earlier complete verification under this key authenticated bytes with digest `D` (receipts are only written after that, and only the key holder can sign one), and (b) the current rows reproduce `D` and recompute to the same hashes. So the entry hashes and signatures are byte-identical to those verified, and equal hashes over `canonicalBytes` imply equal canonical bytes under SHA-256 collision resistance. Hence every per-row check that verification would perform gives the same result. Anything else (content edit with or without re-chaining, signature edit or strip, reorder, deletion, key or adoption-metadata change) changes a hash or `D` and falls back to the full walk. Tail changes are verified in full. A column outside the canonical bytes and `entry_sig` is unauthenticated today and stays so.

**Rollback (A2).** A consistent older database, receipt included, is still verified as authentic, exactly as today; the remote pin remains the only rollback detector. A newer receipt restored onto an older database fails step 2 (missing row or hash mismatch) and is ignored. The receipt cannot make rollback less detectable, and it is not a rollback pin.

**Write path.**

- Written only when the verified-prefix precondition above holds and a signing key is present; it needs no `Intact`/`authentic` whole-chain result. A chain that fails at row j may still leave a receipt for rows before j, since those rows did pass. Writes use a separate short transaction after the read snapshot ends, with a bounded busy timeout.
- It advances to the highest row verified in this run. A deadline mid-suffix (`ErrVerifyInterrupted`) therefore advances the receipt to the last verified boundary, and the anchor is emitted only if the walk reaches the snapshot head.
- **Monotonicity:** a receipt can only shrink the set of rows whose signatures are skipped; it never extends trust past bytes the key holder already attested. Restoring an older or stale receipt causes more verification, not less.
- Verification becomes a database writer in this step. A receipt write is not a fence decision, so the audit-row invariant in `CLAUDE.md` does not apply. On a read-only copy, mount or forensic image the write is skipped, which is expected and not an error; the verdict is unchanged.
- `INSERT OR REPLACE` of one row is atomic in SQLite: a crash leaves the old receipt or none, never a torn one.
- Anything unreadable or of unknown version is ignored, and an older binary ignores the table, so downgrade is safe. Receipt loss costs one full walk and nothing else (a performance, not integrity, event).

**Invalidation.**

| Event | Effect |
| --- | --- |
| Append | Receipt stays valid; the suffix is verified and the receipt advances |
| `Prune` | Re-chains every surviving row: hashes change, `D` mismatches, full walk |
| Tail truncation or rollback | `through_id` missing or head mismatch: ignored, full walk |
| Copy to another project, same key and bytes | Valid (same bytes, same verdict); not a rollback pin |
| Copy with different bytes, or any prefix edit | `D`/hash mismatch: full walk |
| Different or rotated key | Fingerprint or signature mismatch: ignored |
| Adoption metadata change | Receipt covers it: ignored |
| Chain identity (`chain_id`, registration state) | Not in the receipt. Identity is read from trusted state on every emission and is unaffected |
| Corrupt, unknown version, deleted | Ignored, full walk |

**Cost after Step 2.** Warm, no new rows: about 0.17 to 0.18 s per 100,000 rows (measured with the prototype loop, a lower bound) plus one Ed25519 verify and sign. Each new row adds about 40 µs. The linear term shrinks from about 40 µs to about 1.7 µs per row, so the teardown budget on this host stretches from roughly 125,000 to roughly 2,500,000 rows of already-verified prefix (extrapolated, not measured). A first run on a large store without a receipt still pays the full walk, bounded by Step 1.

### Step 3: pacing with N11766 periodic checkpoints

The periodic checkpointer owns the work: each tick verifies the suffix with a row budget, advances the receipt on interruption, and emits a checkpoint only when the walk reaches the snapshot head. `wrap` teardown then verifies only the residual since the last tick plus the rescan. Periodic ticks must run off the append path (never inside `logInTransaction`) and must not hold the identity lock across a long walk. The N11766 design should consume `ErrVerifyInterrupted` as a normal "try next tick" outcome and log it loudly.

Option B (parallel signature verification) is a later lever if a cold first run on a very large store is unacceptable; it composes with C.

## Negative-control plan (for the implementation PR)

Each negative control has a positive control that proves the allowed case still passes, and a differential oracle: for every case, the receipt-assisted verdict (`Intact`, `SigState`, `FirstBrokenID`, reasons) must equal full verification's.

| # | Scenario | Expected |
| --- | --- | --- |
| 1 | Valid receipt, append k rows (positive) | `authentic`; a test counter shows signature checks equal k, not N |
| 2 | Prefix row edited, no re-chain | Hash mismatch, receipt dropped, `tampered` |
| 3 | Prefix row edited and keyless re-chain plus head rewrite | `D` mismatch, full walk, `forged` |
| 4 | Laundered head (`TestHeadOnlyVerificationMissesLaunderedTamper` flow, receipt present) | `forged`; `EmitAnchor` refuses |
| 5 | Prefix `entry_sig` altered or stripped | `D` mismatch, full walk, `forged` |
| 6 | Rows reordered, swapped or one deleted from the middle | Linkage fails, `tampered` |
| 7 | First row deleted (prune-like) and real `Prune` | Receipt dropped; delete = `tampered`, real prune = `authentic` with prune metadata |
| 8 | Tail truncated, head rewritten keylessly | Head signature fails or receipt dropped; never `authentic` |
| 9 | Restore an older complete database (A2) | `authentic` locally (documented limit); `VerifyAgainstAnchorV2` reports `truncation` against a later pin |
| 10 | Newer receipt on older database | Ignored, full walk |
| 11 | Receipt forged: unsigned, wrong key, row/head/anchor signature bytes replayed as a receipt, altered `through_head_hash`/`D`/count | Ignored, full walk, never trusted |
| 12 | Receipt from database B pasted into A (different bytes), and with a different key file | Ignored |
| 13 | Adoption metadata changed | Ignored |
| 14 | Context cancelled at row 0, mid-prefix, mid-suffix, and at the last row (injected via a row-counting hook, not wall-clock) | `ErrVerifyInterrupted`, no anchor, never `authentic`/`tampered`; next run completes with the identical verdict |
| 15 | Receipt write fails (read-only DB, busy) or process killed between verify and write | Verdict unchanged; old or no receipt; next run correct |
| 16 | Chain broken at row j; pub-key-only verifier; read-only database | Receipt at most through the last good row, never past j; pub-key-only verifier writes none; read-only skips the write without error |
| 17 | Appends during verification | Anchor equals the snapshot head; receipt `through_count` is at most the snapshot count |
| 18 | Differential property test: random sequences of {append, edit, re-chain, strip, delete, prune, key swap, receipt add/stale/drop} on small chains, many seeds | receipt verdict equals full verdict in every case |
| 19 | Mutation check: temporarily skip the `D` comparison | Cases 2, 3, 5 and 18 must fail, proving the controls bite |

Step 1 alone needs rows 14 and 17 plus a bounded-time test using the injected hook (EmitAnchor returns `ErrVerifyInterrupted` at the deadline instead of finishing the walk).

## Decisions requested from Mira

1. Receipt location: `events.db` table (recommended: moves, backs up and rolls back with the data it describes; costs a short writer transaction) versus a sidecar file in the audit state directory (no DB schema change, but a separate file to relocate). Integrity does not depend on the choice.
2. Whether Step 1 ships as its own PR ahead of Step 2.
3. Whether Step 3's row budget belongs to N11766 or here.

## Limits of this evidence

Single host and single run set; cold OS page cache not measured; 1,000,000-row and teardown-budget figures are extrapolations; parallel verification speed-up is an estimate; the macOS figures are quoted from the Nock, not reproduced.
