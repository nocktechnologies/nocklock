# Run lifecycle contract: per-run vs global chain, signed close binding

Status: design for Nock #11764 (Codex NockLock proposal item 4, part 1). Nothing here changes runtime behavior; no code is added. The writer and verifier are N11765, which cites this document. The idea of a signed lifecycle receipt comes from pipelock's lifecycle receipts (Apache-2.0); only the idea is used, no code or format.

This builds on, and does not repeat, [bounded anchor verification](anchor-verification-profile.md) (the signed `verify_receipt`, `internal/logging/verify_receipt.go`, #224) and [remote anchor chain identity](anchor-chain-identity.md) (v2 anchors).

## Problem

1. `wrap` writes `session_end` through a local `logEvent` closure that discards the `Logger.Log` error (`internal/cli/wrap.go`, `_ = logger.Log(...)`). A failed end row is invisible: the run looks like a crash.
2. Nothing checks that a run's rows are complete. A verifier sees one linear chain, not "this run, these rows".
3. `session_end` is written on several paths with different shapes: some with no `session_start` (early refusals, `scan` preflight), and the exit-code text is free-form `detail`.

## Per-run vs global-chain semantics

- **The chain is global and per project.** `events.db` holds one hash-chained, Ed25519-signed sequence (`chain_head`: `entry_hash`, `row_count`, `head_sig`). Every guarantee in the audit log (linkage, row and head signatures, receipt, v2 anchor) is a property of that one sequence.
- **A run is a label, not a chain.** `session_id` (a UUID minted per `wrap`, inside each row's signed canonical bytes) tags rows. Runs are not contiguous: two `wrap` processes on one project interleave, and the chain gives a total order across them. A run's rows are a subsequence selected by `session_id`.
- **Consequence.** The chain proves the sequence is intact; it does not say a run's subsequence is *complete*. Deleting a run's tail while re-chaining is a different attack (key holder, covered by anchors and the head signature). Not writing the tail at all (crash, write error, kill) leaves a perfectly valid chain. The close binding exists to give a run an explicit, signed statement of its own extent.
- **Per-run commitments are computed over the global chain, never beside it.** There is no per-run chain, key, file or table. A per-run chain would add a second state to keep consistent and a new rollback surface, for nothing the global chain does not already give.

## The close binding

A new signed row, `session_close` (event type, `category = "session"`), written once per run, after the run's last row, in the normal append path (so it is hash-chained, row-signed with domain byte `0x01`, and counted in `row_count` and the head signature like any row). **No new signature domain byte and no schema change**: the binding is a content claim inside a row that is already authenticated.

Its `detail` is `key=value` fields in the same quoted style as the `session_start` fields (N11763):

| Field | Meaning |
| --- | --- |
| `close=1` | contract version |
| `session=<id>` | the run (also in the row's `session_id`) |
| `first_id` | id of the run's `session_start` row |
| `last_id` | id of the run's last row before the close |
| `rows` | count of the run's rows from `first_id` through `last_id`, close excluded (**count**) |
| `root` | 64-hex rolling digest of those rows (**root**, below) |
| `end` | `clean`, `child_exit`, `refused`, `audit_failed`: why the run ended, from the writer's own paths (not the child's exit code; that stays in `session_end`) |

`end` is the writer's own reason for closing the run, recorded only inside a close row that itself made it to disk — it is not a status layered on top of a failed write. `audit_failed` means the egress decision-log reader failed (`decisionFailed`, checked at `internal/cli/wrap.go:1105`) but the `session_end` and close writes that follow it still succeeded. If the same underlying failure took down the signing logger, the `session_end` (or close) write fails too, per the rule above, and the run is `unclosed` instead — so `audit_failed` and a failed close can never both describe the same run.

**Root.** `R_0 = SHA-256("nocklock-run-close-v1\0" || session_id)`, `R_i = SHA-256(R_{i-1} || SHA-256(canonical_bytes_i))` over the run's rows in id order, where `canonical_bytes_i` is the row's existing signed canonical byte string (`canonicalBytes`, `internal/logging/logger.go:1297`, covering `id`, timestamp, type, category, detail, blocked and session id). Using canonical bytes and not `entry_hash` is deliberate: `entry_hash` includes `prev_hash`, which `Prune` rewrites (`internal/logging/logger.go:1180-1235`: it keeps each surviving row's `id` and canonical bytes and rewrites only `prev_hash` and `entry_hash`); canonical bytes do not, so a surviving run still verifies after a prune of other rows. Because `id` is itself inside the canonical bytes, the root survives a prune only *because* `Prune` preserves ids — a prune that renumbered surviving rows would break every root computed before it. The row signature already commits to the same bytes.

**Atomicity.** The close is computed and appended in one SQLite write transaction, the same discipline `LogBatch` uses for predecessor lookup and append. It therefore covers every run row committed before it (a `session_id` belongs to one `wrap` process). Rows of other runs between `first_id` and `last_id` are excluded by the `session_id` filter. Cost is one indexed scan (`idx_events_session`) and one SHA-256 per run row, once per run.

**Who writes a run's rows.** `session_id` is minted once per `wrap` process (`uuid.New()`, `internal/cli/wrap.go:80`) and held in memory; every component that stamps it onto a row is constructed with that in-memory value directly, inside the same `wrap` process: the network proxy and its look-back rules (`network.NewProxyServer(proxyCfg, logger, sessionID)`, `internal/cli/wrap.go:744`; `ProxyServer.sessionID`, `internal/fence/network/proxy.go:149`; look-back rows at `internal/fence/network/lookback.go:233`), the egress decision-log scanner (`newDecisionLogScanner(logger, sessionID)`, `internal/cli/wrap.go:1021`), the macOS denial tailer's tag (`fsfence.DenialTag(sessionID)`, `internal/cli/wrap.go:1066`), the config-digest recorder (`internal/cli/wrap.go:197`), and the secret preflight run from inside `wrap` (`runSecretPreflight`, `internal/cli/wrap.go:288`, implemented at `internal/cli/scan.go:78-110`). None of them read the id back from anywhere; they all share the one Go variable. The standalone `nocklock scan` command (`internal/cli/scan.go:20-48`, the CLI entry point of the same name) is a different code path: it never calls `runSecretPreflight`, holds no `Logger`, and writes only a report to stdout/JSON, never a row to `events.db`.

`wrap` also exports the id to the child as `NOCKLOCK_SESSION_ID` (`internal/cli/wrap.go:916`), but nothing in this codebase reads that variable to write a row into this run's `events.db` — a repo-wide search for it turns up only the constant and the setter in `wrap.go` (`internal/cli/wrap.go:1290,1295`). Its purpose is cross-chain correlation, not shared writing: the comment at the definition says it exists so "a co-located tool (NockGuard) [can] stamp the same id so one verifier can join both chains" (`internal/cli/wrap.go:1287-1289`). NockGuard cannot do that by importing this chain's writer: `internal/logging` cannot be imported from outside this module, so a sibling tool reaches the chain only through the narrow read-only `pkg/receipt` package (`pkg/receipt/receipt.go:1-6`), which has no append path. A NockGuard row carrying this `session_id` therefore lives in NockGuard's own, separate chain, never in this run's `events.db`, and a late row from it is not a `rows_after_close` question: it is a different chain, outside the `idx_events_session` scan the close and the verifier both use. (`internal/forward/forward.go:149` also carries `SessionID`, but only to relay an already-committed row's fields, `entry_hash` included, to an external ops-log sink over HTTP — it reads the chain outward and never writes back into it.) No process other than `wrap` writes rows with a given `session_id` into this chain today, and N11765's writer must keep it that way: any future producer of a run's rows has to receive `session_id` in-process from `wrap`, never re-derive or read it back, and must be one of the producers the next rule joins before the close.

**Teardown ordering.** The close must be the last write for a run's `session_id`. Before attempting it, the writer stops and joins every other producer that can still write rows under that id: the network proxy, including its look-back rows (`ProxyServer.Stop`, `internal/fence/network/proxy.go:347`), the egress decision-log reader (`close(decisionDone)` then `decisionReaderWg.Wait()`), and the macOS denial tailer (`denialTailer.Stop()`). `ProxyServer.Stop` blocks on `http.Server.Shutdown` with a 5-second deadline, so a handler still writing a row — including a look-back write, `internal/fence/network/handler.go:194`, `internal/fence/network/lookback.go:233` — is normally drained before `Stop` returns and logs `EventProxyStop`. A handler still running past that deadline is the one case this ordering cannot fully close out; N11765 must treat it as a reason to skip the close (the run reads `unclosed`) rather than risk a `rows_after_close` false positive on an honestly slow request. Only once every producer has returned does the writer append `session_end`, then the close, then call `finishAnchorSession` (already the existing order; see "Relation to the v2 anchor" below). Today `wrap` defers `proxy.Stop()` (`internal/cli/wrap.go:821`) so it runs *after* `session_end` is already logged (e.g. `internal/cli/wrap.go:1144`); N11765 must join the proxy's stop before writing `session_end`, not leave it as a trailing defer.

**Close failure is loud.** The close and the `session_end` write must not discard errors. A failed write prints a loud stderr warning naming the run and the error and is also recorded by the verifier as `unclosed`. It does not change the child's exit code (the child already ran; exit codes are the contract in `docs/reference/cli.md`, and anchor push failures behave the same). Whether a failed close should escalate the exit code is an operator decision for N11765; the recommendation is no. The fence-start invariant (fail closed) is unaffected: it concerns the fence initializing, not the receipt of a finished run.

**A failed `session_end` must not produce `closed`.** The close's `last_id` is only meaningful once `session_end` is the run's last ordinary row, so the two writes are not independent: if the `session_end` append itself fails, the writer must not attempt the close at all. It stops at the loud warning above, and the run reads `unclosed` — never `closed` over a run that is missing its own end row.

## What a missing close means

**A missing close cannot tell a crash from a deliberate cut.** The same observation, a run with `session_start` and rows but no `session_close`, results from `SIGKILL`, power loss, a `wrap` panic, a failed close write, or someone who stopped the writer or removed the tail rows. The chain stays valid in every case. The design does not pretend otherwise:

- The verifier reports `unclosed` as a distinct, neutral status. It is **not** `tampered`, and **not** clean. Callers choose whether it fails (`verify --require-closed`, flag name for N11765).
- `nocklock verify` lists any `unclosed` runs inside the same `COVERAGE: LIMITED` notice it already appends for recording limits (N11761, `docs/reference/cli.md`), not only in a per-run status line. A clean overall verdict must never appear next to runs still missing their close without that notice naming them.
- Only an outside witness can distinguish the cases: a v2 anchor whose pinned `row_count` exceeds the local count shows a cut after the anchor (`TRUNCATION`), and operator logs may show a crash. The close adds no power here; its value is the **positive** case.
- A run's `session_end` without a close is likewise `unclosed`, since `session_end` carries no count or root.

## Verification

For each run found in the chain (`session_start` rows with `lifecycle=1`, below), the verifier reports one of:

| Status | Condition | Severity |
| --- | --- | --- |
| `closed` | one `session_close`; recomputed `rows`, `root`, `first_id`, `last_id` equal the signed values; no later row has the run's `session_id` | ok |
| `close_mismatch` | close present, any recomputed value differs (a run row edited, removed or inserted yet re-signed) | failure (tampered) |
| `rows_after_close` | a row with this `session_id` after its close, or two closes | failure |
| `unclosed` | start present, no close | neutral (see above) |
| `pruned` | run's rows partly gone below the prune boundary recorded in `chain_head` metadata | neutral, reported |
| `legacy` | no `lifecycle=1` on the start row (written before this contract) | neutral, never a failure |

`session_end` rows with no start (early refusals) are not runs and need no close.

**Downgrade resistance.** Whether a run owes a close is decided by `lifecycle=1` in its signed `session_start` detail. A writer that never emits `lifecycle=1` never owes one; an attacker cannot strip a signed field without breaking that row's signature, and removing the start row removes the run from view, which is the same cut attack as above.

## Relation to the verification receipt (#224)

Orthogonal, and it composes without changes to the receipt.

- The receipt is a performance cache: a key-signed attestation that rows `1..through_id` were verified, so their *signatures* are skipped. It is never evidence about a run.
- Close verification needs only per-row canonical bytes and `session_id`, which the receipt's prefix rescan already reads and re-derives (it recomputes every `entry_hash` from canonical bytes). Checking closes therefore rides the same pass and costs one extra hash per row, no signature work. A run entirely inside the verified prefix is checked on the rescan; a run in the suffix on the normal walk.
- The close must not be inferred from a receipt or vice versa. A receipt neither proves nor needs a close; a close does not let a verifier skip the receipt's prefix rescan. The receipt format, domain byte `0x07`, and `D` digest are unchanged; `D` covers `session_close` rows like any row.
- The verifier must not report a run as `closed` from a receipt alone: it recomputes `root` from the rows.

## Relation to the v2 anchor

- The anchor is the only rollback and truncation witness. It pins `(chain_id, head_hash, row_count)` off-box. A close does not replace it and cannot detect tail truncation that includes the close itself.
- Ordering: `finishAnchorSession` runs after the close (it is deferred in `wrap`), so an emitted anchor's `row_count` and `head_hash` cover the close row. A run whose close landed before the anchor is therefore pinned as closed; the anchor and the close fail independently.
- Combined reading: `closed` + anchor `row_count` at or after the close = the run is complete and was pinned. `unclosed` + anchor count beyond the local chain = cut. `unclosed` + no remote pin = indeterminate.
- The anchor wire format and domain byte `0x06` are unchanged. The close does not add anchor fields.

## Backward compatibility rule

The binding is **additive** and old data and tools keep their meaning:

1. No change to row canonical bytes, `chain_head`, the receipt, anchors, or the schema. `session_close` is an ordinary row with a new `event_type` value.
2. An old verifier verifies a chain containing `session_close` rows as intact (they link, hash and sign). It does not check them; it must not fail on an unknown `event_type`. N11765 adds a test that a pre-change verifier path (full walk without the close check) accepts a chain with close rows.
3. A new verifier on an old chain reports `legacy`, never failure.
4. A run owes a close only if its signed start row says `lifecycle=1`. The contract is not retroactive.
5. An older binary writing to a chain that already has `lifecycle=1` runs writes `legacy` runs; mixed chains are valid.
6. `session_close` is not in `lookbackBlockedTypes` (it is written with `blocked=false`) and is not a look-back trigger.

## Test plan for N11765 (writer and verifier)

Each negative control carries its positive control.

| # | Case | Result |
| --- | --- | --- |
| 1 | Run completes; close appended (positive) | `closed`; `rows` and `root` equal an independent recomputation |
| 2 | Run row edited, chain re-signed by key holder | `close_mismatch` |
| 3 | Run row removed, chain re-chained | `close_mismatch` |
| 4 | Extra row with the run's `session_id` after the close | `rows_after_close` |
| 5 | Two concurrent runs interleaved | both `closed`, each root over its own rows only |
| 6 | Kill the writer before the close | `unclosed`, chain intact, not `tampered` |
| 7 | Close write forced to fail | loud stderr; exit code unchanged; verifier says `unclosed` |
| 8 | Tail (including close) truncated and re-chained | chain intact, `unclosed`; local anchor or v2 pin reports `TRUNCATION` |
| 9 | Old chain with no `lifecycle=1` | `legacy`, verify exit unchanged |
| 10 | Chain with close rows through the receipt path (`verify_receipt` present) | same verdicts as the full walk (differential); suffix-run and prefix-run both checked |
| 11 | Prune removes an older run, a later run survives | surviving run still `closed`; partly pruned run `pruned` |
| 12 | `session_start` with `lifecycle=1` stripped | row signature fails |
| 13 | A producer (proxy, look-back rule, denial tailer) still writing when teardown begins | its rows land before `session_end`; run still `closed`, no `rows_after_close` |
| 14 | Full real `wrap` teardown against a live proxy and child | run ends `closed` |
| 15 | `session_end` write forced to fail | no close attempted; loud stderr; verifier says `unclosed` |
| 16 | Proxy shutdown exceeds its 5s drain deadline with a handler still writing | close skipped; run `unclosed`; never `rows_after_close` |

## Decisions (Mira, round 1)

1. A failed close write is a loud stderr warning only; the exit code stays the child's.
2. `unclosed` is neutral by default, with an opt-in `--require-closed`. `nocklock verify` also lists `unclosed` runs inside the `COVERAGE: LIMITED` notice (above), so a reader never sees a plain clean verdict while runs are missing their close.
3. No new signature domain byte; the close is a normal signed row.

## Limits

- A key holder can write a false close; the close defends against an unsigned or partial writer, not a stolen key.
- It cannot tell crash from cut (above).
- A run that never wrote a start (`lifecycle=1`) is invisible to it.
- Rows of a run committed after its close are detected only while that `session_id` is not reused; IDs are UUIDs minted per process.
