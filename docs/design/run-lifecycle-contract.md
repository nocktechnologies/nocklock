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
| `first_id` | id of the first row stamped with the run's `session_id`, whatever its type — in practice the config-digest row (`recordConfigDigest`, `internal/cli/wrap.go:197`), written before `session_start` |
| `last_id` | id of the run's last row before the close |
| `rows` | count of the run's rows from `first_id` through `last_id` inclusive, close excluded — this includes any pre-`session_start` rows (**count**) |
| `root` | 64-hex rolling digest of those rows (**root**, below) |
| `end` | `clean`, `child_exit`, `refused`, `audit_failed`: why the run ended, from the writer's own paths (not the child's exit code; that stays in `session_end`) |

`end` is the writer's own reason for closing the run, recorded only inside a close row that itself made it to disk — it is not a status layered on top of a failed write. `audit_failed` means the egress decision-log reader failed (`decisionFailed`, checked at `internal/cli/wrap.go:1105`) but the `session_end` and close writes that follow it still succeeded. If the same underlying failure took down the signing logger, the `session_end` (or close) write fails too (see "A failed `session_end` must not produce `closed`", below), and the run is `unclosed` instead — so `audit_failed` and a failed close can never both describe the same run.

**Root.** `R_0 = SHA-256("nocklock-run-close-v1\0" || session_id)`, `R_i = SHA-256(R_{i-1} || SHA-256(canonical_bytes_i))` over the run's rows from `first_id` through `last_id` in id order (pre-`session_start` rows included), where `canonical_bytes_i` is the row's existing signed canonical byte string (`canonicalBytes`, `internal/logging/logger.go:1297`, covering `id`, timestamp, type, category, detail, blocked and session id). Using canonical bytes and not `entry_hash` is deliberate: `entry_hash` includes `prev_hash`, which `Prune` rewrites (`internal/logging/logger.go:1180-1235`: it keeps each surviving row's `id` and canonical bytes and rewrites only `prev_hash` and `entry_hash`); canonical bytes do not, so a surviving run still verifies after a prune of other rows. Because `id` is itself inside the canonical bytes, the root survives a prune only *because* `Prune` preserves ids — a prune that renumbered surviving rows would break every root computed before it. The row signature already commits to the same bytes.

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

For each run found in the chain, the verifier reports one of the statuses in the table below. A run is found two ways: by its `session_start` row (`lifecycle=1`), and — because a prune can delete that row while the run's close survives — by any `session_close` row whose `session_id` has no surviving start row. The `unclosed` test applies only to a run found by a start row with no close; a close found with no start is never `unclosed` (it is `pruned` or `close_mismatch`, below). `first_id` is a separate notion — the earliest row carrying the run's `session_id`, which can precede `session_start` (the config-digest row at `internal/cli/wrap.go:197` and the secret-preflight row at `internal/cli/wrap.go:288` both predate `session_start` at `internal/cli/wrap.go:892`). `rows` and `root` cover every row with that `session_id` from `first_id` through `last_id`, close excluded.

**One rule for pruned vs. tampered.** `Prune` (`internal/logging/logger.go:1134`) deletes rows by `timestamp < cutoff` (`internal/logging/logger.go:1156`), not by an id prefix; `Log` stores the caller's own `event.Timestamp` (`internal/logging/logger.go:778`), not a server-assigned one. So a legitimate prune can remove any row of a run — including one in the middle, under out-of-order caller timestamps — while `first_id` and `last_id` still look intact. A boundary test keyed on id can't tell that case from tampering, so there is none: the verifier recomputes `rows` and `root` from the run's surviving rows for every close, start present or not. Matching the signed values is `closed`. A mismatch with `pruned_at` unset is `close_mismatch`. A mismatch with `pruned_at` set is `pruned`, unless one of the two suffix checks under Limits fails, in which case it is `close_mismatch` too. A start-absent close recomputes with no start row among its rows, which differs from the signed values by construction, so it is never `closed`.

| Status | Condition | Severity |
| --- | --- | --- |
| `closed` | one `session_close`; recomputed values (`rows`, `root`, `first_id`, `last_id`) equal the signed ones; no later row has the run's `session_id` | ok |
| `pruned` | `chain_head.pruned_at` is set, a recomputed value differs from the signed one, and the two suffix checks (Limits) pass | neutral, reported |
| `close_mismatch` | a recomputed value differs from the signed one, and either `pruned_at` is unset or a suffix check fails | failure (tampered) |
| `rows_after_close` | a row with this `session_id` after its close, or two closes | failure |
| `unclosed` | start present, no close | neutral (see above) |
| `legacy` | no `lifecycle=1` on the start row (written before this contract) | neutral, never a failure |

`session_end` rows with no start (early refusals) are not runs and need no close.

**Downgrade resistance.** Whether a run owes a close is decided by `lifecycle=1` in its signed `session_start` detail. A writer that never emits `lifecycle=1` never owes one; an attacker cannot strip a signed field without breaking that row's signature. Removing the start row, or any other pre-close row, and re-chaining does not remove the run from view: the run's `session_close` row still carries its `session_id`, so the verifier still finds it and recomputes `rows`/`root`, which differ from the signed values — the run reads `pruned` or `close_mismatch` by the rule above, never silently `closed`. A run with neither a surviving start nor a surviving close is invisible, the same cut attack as above, but that is the whole run gone, not one row removed from it.

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
| 2 | Run row edited, chain re-signed by key holder (`chain_head.pruned_at` unset) | `close_mismatch` |
| 3 | Run row removed, chain re-chained (`chain_head.pruned_at` unset) | `close_mismatch` |
| 4 | Extra row with the run's `session_id` after the close | `rows_after_close` |
| 5 | Two concurrent runs interleaved | both `closed`, each root over its own rows only |
| 6 | Kill the writer before the close | `unclosed`, chain intact, not `tampered` |
| 7 | Close write forced to fail | loud stderr; exit code unchanged; verifier says `unclosed` |
| 8 | Tail (including close) truncated and re-chained | chain intact, `unclosed`; local anchor or v2 pin reports `TRUNCATION` |
| 9 | Old chain with no `lifecycle=1` | `legacy`, verify exit unchanged |
| 10 | Chain with close rows through the receipt path (`verify_receipt` present) | same verdicts as the full walk (differential); suffix-run and prefix-run both checked |
| 11 | Prune deletes an older run's pre-close rows, including its `session_start`, under a cutoff that falls before the run's `session_close` is written (the close postdates the cutoff and survives); a later run's rows all survive | older run found by its close alone: `chain_head.pruned_at` set, recomputed `rows`/`root` differ from the signed values — `pruned`; later run still `closed` |
| 12 | `session_start` with `lifecycle=1` stripped | row signature fails |
| 13 | A producer (proxy, look-back rule, denial tailer) still writing when teardown begins | its rows land before `session_end`; run still `closed`, no `rows_after_close` |
| 14 | Full real `wrap` teardown against a live proxy and child | run ends `closed` |
| 15 | `session_end` write forced to fail | no close attempted; loud stderr; verifier says `unclosed` |
| 16 | Proxy shutdown exceeds its 5s drain deadline with a handler still writing | close skipped; run `unclosed`; never `rows_after_close` |
| 17 | Honest run with a config-digest row before `session_start` (`first_id` precedes the start row), then that pre-start row deleted and the chain re-signed; no prune (`chain_head.pruned_at` unset) | verifies `closed` before the deletion; `close_mismatch` after — `pruned_at` unset is what distinguishes this from control 19's legitimate prune |
| 18 | Only the `session_start` row removed and the chain re-signed; no prune (`chain_head.pruned_at` unset) | close found with no start, not explained by `pruned_at`: `close_mismatch` |
| 19 | Prune cutoff falls between the config-digest row and `session_start`: both `session_start` and `session_close` survive, only the run's pre-start rows are gone | `pruned`, found via its surviving start row: `chain_head.pruned_at` set, recomputed `rows`/`root` differ from the signed values |
| 20 | Events logged with out-of-order caller timestamps; a timestamp-keyed `Prune` (`internal/logging/logger.go:1156`, `DELETE FROM events WHERE timestamp < ?`) removes a row from the middle of a run's id range while `first_id` and `last_id` both survive | `chain_head.pruned_at` set, recomputed `rows`/`root` differ from the signed values — `pruned` |

## Decisions (Mira, round 1)

1. A failed close write is a loud stderr warning only; the exit code stays the child's.
2. `unclosed` is neutral by default, with an opt-in `--require-closed`. `nocklock verify` also lists `unclosed` runs inside the `COVERAGE: LIMITED` notice (above), so a reader never sees a plain clean verdict while runs are missing their close.
3. No new signature domain byte; the close is a normal signed row.

## Limits

- A key holder can write a false close; the close defends against an unsigned or partial writer, not a stolen key.
- It cannot tell crash from cut (above).
- A run that never wrote a start (`lifecycle=1`) is invisible to it — but a run whose start row was later pruned is not: it is still found via its surviving `session_close` (see Verification, above).
- After any prune, the close cannot tell a row the prune removed from one an attacker removed. The signed `root` covers rows from `first_id`, and the prune removed some of them, so a root cannot be checked over a surviving suffix. Instead, once `pruned_at` is set, the verifier runs two narrower checks that a prune itself cannot fail: if the row at `last_id` survives, it must still carry the run's `session_id`; and the count of surviving rows carrying that `session_id` must be at most the signed `rows` (a prune only removes rows, never adds them). A failure here means something besides the prune touched the run's surviving rows, so it reports `close_mismatch` even though `pruned_at` is set. If the row at `last_id` itself is gone (control 11), there is no suffix left to check, and the run is `pruned` on the `rows`/`root` mismatch alone. Short of that, row signatures and the global hash chain still cover any edit to a surviving row's content: altering one without removing it breaks that row's own signature or the chain's linkage, independent of `pruned_at`. A row removed from the middle of a run — whether that run straddles the prune or is entirely newer than it — instead reads as `pruned`, not `close_mismatch`, when the party removing it also re-signs the chain: `pruned_at` is itself one of the values that party re-signs. This is accepted, not closed with a new field: that party can already write a false close outright (above), so the signed chain and the remote anchor, not this check, are the witnesses against a key holder; the check above is for an unsigned or partial writer, and stays effective against that weaker attacker after a real prune. `rows_after_close` — including the two-closes case it also covers — still applies to a `pruned` run: both read forward from the close, never back into the pruned rows.
- Rows of a run committed after its close are detected only while that `session_id` is not reused; IDs are UUIDs minted per process.
- `first_id` is simply the earliest row carrying the `session_id` in the chain, not a fixed step of `wrap`'s startup; if a process exits before ever writing `session_start` (e.g. `recordConfigDigest` succeeds but `protectChainIdentity` then refuses), the config-digest and secret-preflight rows it left behind are not part of any run — there is neither a start nor a close to make one exist — the same as a `session_end` row with no start.
