# Look-back policy rules over the event history

Status: design note, no code. Nock #11296. Citations are `file:line` at `origin/main` eef51e4.

Strands Box evaluates every policy decision against one shared event history, so a rule can say "this agent read a file earlier, so refuse its next outbound request" (README and architecture doc, linked in section 5). NockLock has no such rule. This note says what we could build from what we already record.

## 1. What the log records today

- **Store.** SQLite `events` table: id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig (`internal/logging/logger.go:213-224`), with indexes on session, type, timestamp and blocked (`:225-228`). A signed `chain_head` row holds the head hash and row count (`:229-241`).
- **Chain.** Each row's hash covers `id, ts, event_type, category, detail, blocked, session_id` plus the previous hash (`canonicalBytes`, `:1105-1143`). The Ed25519 signature covers the same bytes (`:641-646`). `pkg/receipt` verifies a session offline (`pkg/receipt/receipt.go:1-50`).
- **Event types** (`logger.go:27-41`): secret, file and network passed/blocked, proxy start/stop, network error, session start/end, config loaded and digest.
- **Query.** `Logger.Query` filters by type, category, blocked, session and time, and can order by insertion id (`:800`, `QueryOptions.ByID` at `:111`). `WithEventCommitted` calls back after each commit (`:152`).
- **Retention.** `Prune` deletes old rows and re-anchors the chain (`:955`). History is not permanent.

What it does not record matters more for this feature:

1. **Allowed file reads are never logged.** The LD_PRELOAD interposer only calls `report_blocked` on denials (`internal/fence/fs/interposer/*.c:407`, called from `:817-1011`). The Go side logs each report as `file_blocked` (`internal/cli/wrap.go:833-835`). The `file_passed` rows are fence-state notes, not accesses (`wrap.go:439-551`). Landlock gives no per-access events, so a denial the interposer never reported leaves no row. The report is fire-and-forget: the interposer connects, writes, closes and ignores failures (`interposer/*.c:441-462`). The macOS denial tailer is best-effort and denials only (`wrap.go:925-945`). So "the agent read a secret" is unobservable, and "the agent was denied a read of a fenced path" is observable only when the interposer saw it.
2. **Secrets are logged once, at startup.** `secret_passed` lists the env var names passed to the child (`wrap.go:280-285`). It says nothing about use.
3. **Network decisions** log `method=... host=...` (`internal/fence/network/handler.go:107,112,160-171`, `connect.go:30,46`). The netns path adds `rule=...` (`internal/cli/decision_log.go:66-82`).
4. **Timestamps are the logger's `time.Now()`** at write time. For netns decisions that is when `wrap` folds the record in, not when the proxy decided (`decision_log.go:77`).
5. **The HTTP proxy ignores audit-write errors** (`handler.go:165`, `_ = p.logger.Log`). The netns path fails closed on them (`decision_log.go:146`, `transparent_linux.go:206`).

## 2. Minimal rule shape

A look-back rule narrows egress after a trigger event has been recorded in the current session. It is not a new allow: the allowlist already denies unlisted hosts. The rule's value is revoking allowlisted hosts, or tightening `allow_all` configs.

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"      # trigger: an event_type already in the log
within = "10m"               # optional; default = rest of the session
then   = "deny_egress"       # deny every egress request while tripped
```

Semantics: tripped if the session has a row with `event_type = on` and `blocked = 1` newer than `within`. Evaluation is a pure function `Evaluate(rules, latestTrigger, now) -> (deny bool, ruleName, triggerID)`. Its input is one indexed lookup, `WHERE session_id=? AND event_type=? AND blocked=1 ORDER BY id DESC LIMIT 1` (indexes at `logger.go:225-228`). `latestEvent` (`:574`) filters by type only, so this needs a session-scoped variant.

**Ordering: commit before the denied open returns.** The trigger row lands after three asynchronous hops: the interposer returns to the agent right after its write; `handleConn` queues the event on a 64-slot channel (`fence.go:121,171`); a consumer goroutine calls `logEvent` (`wrap.go:831-836`). A denied `open` followed at once by a CONNECT on another thread can be decided before the row exists, and the rule misses. Slice 1 closes the window with a synchronous handoff instead of documenting it. The report handler commits the `file_blocked` row itself, closes open tunnels (next paragraph), then writes a one-byte ack. The interposer waits for the ack, bounded at 250 ms, before returning EACCES. The evaluator then needs only the query, and the trigger id exists when a denial cites it. An in-memory latch was rejected because it has no row id to cite until the commit. The cost is one commit on the denied-open path, which is not hot. If the ack times out or the connect fails, the open is still denied but the race is open again. That is a stated limit.

**Tunnels already open.** `handleConnect` checks the allowlist once (`connect.go:29`) and pipes bytes for up to five minutes (`connect.go:69-71`), so a tunnel opened before the trigger would stay usable. `deny_egress` covers it: the proxy keeps a set of hijacked client connections (added after `connect.go:54`), and a trigger commit closes every one. Each closure writes a `network_blocked` row with `rule=lookback:<name> trigger=<id>`, under the cap in section 3. Plain HTTP requests are re-evaluated per request; an in-flight response is not cut. Bytes sent before the trigger are not recalled.

**Enforcement level.** The deny lives in the userspace proxy, and at ADVISORY a client that ignores `HTTP_PROXY` reaches any host (`egress_level.go:72`), so the deny would be silently bypassable. The rule therefore forces refusal: with any look-back rule, `wrap` refuses to start unless `egressLevelMeetsRequirement` holds (`egress_level.go:36-38`), the same refusal as `require_enforced` (`wrap.go:570-577`). With netns excluded from slice 1, that leaves CONFINED: Linux, syscall enforcement and the interposer (`egress_level.go:27-30`). macOS reaches only ADVISORY or OFF (`egress_level.go:17-34`), so it cannot use look-back yet.

**Where it runs.** In the `wrap` parent's HTTP proxy, beside `isAllowed` (`handler.go:31`, `:100-112`; `connect.go:26-31`). That process owns the signing logger. Elsewhere:

- **netns transparent proxy:** not feasible as is. It runs as `nobody` with no DB handle or key and only appends TSV lines (`transparent_linux.go:57-71`, `:206`). A later slice could give it a latch file that `wrap` writes after the commit, with a small race.
- **NockGuard proxy** (separate repo, not read in depth): `internal/logging` is not importable outside this module (`receipt.go:1-6`), so it would need a public read-only history API in `pkg/`. Out of scope.

**How the decision is signed.** Reuse the existing row. A denial logs `network_blocked` through `Logger.Log` with `Detail = "method=CONNECT host=h rule=lookback:<name> trigger=<event id>"`. Detail is inside the hashed and signed bytes (`logger.go:635-646`), so the receipt binds the denial to the trigger row. No new event type, canonical-bytes change or verifier change. Slice 1 keeps the `rule=` key=value form netns rows already use (`decision_log.go:66-69`) rather than the JSON envelope (`logger.go:64-98`), which would change `network_blocked` Detail for every consumer. `forward.go:71-75` already forwards `network_blocked` to Command.

## 3. Failure modes

- **History unreadable** (DB locked, query error, `Prune` removed the trigger). With any look-back rule configured, deny egress, surface on stderr, and record best-effort. This matches "fences fail closed" (`CLAUDE.md`) and the netns precedent. A rule-free config is unaffected. A pruned trigger inside the window cannot be detected, so `Prune` should refuse to delete rows from a live session (a follow-up, not designed here).
- **Clock skew.** A backward step puts the trigger "in the future": count negative age as within the window (deny). A forward step expires `within` early, which fails open. So the default window is the whole session, and a finite `within` is an opt-in whose docs say it trusts the host clock. Order by row id (`ByID`), not timestamp, given point 4 in section 1.
- **Noisy agent.**
  - *Laundering by volume.* An "N events" window is bypassable: read the secret, make N harmless requests, and the trigger falls out. So there are no event-count windows. The latest trigger is found by type, so noise cannot displace it.
  - *Self-DoS.* Spamming denied file opens trips the rule and cuts the agent's own egress. That is availability, not an escape.
  - *Row growth.* A flood of denied requests writes one signed row each (`handler.go:107`). Cap it as `DefaultMaxDenialEvents = 500` does (`internal/fence/fs/denylog.go:114`): log the first N per rule, then one suppression summary row per rule. The key is the rule, not `(rule, host)`, because the agent picks hostnames and could mint a fresh key per request. A per-rule time window is a later refinement.
  - *Query cost.* One indexed lookup per egress decision. Cache only if measured.
- **Rule that cannot fire.** Refuse to start (Box does the same): unknown `on` type; netns egress, which slice 1 does not cover (`wrap.go:659`); any effective level other than CONFINED, including OFF with no proxy in the path (`wrap.go:754`) and ADVISORY (section 2, "Enforcement level").

## 4. First slice and tests

Slice 1 is the `file_blocked` trigger (probe-then-exfil) on the HTTP proxy path at CONFINED only. It needs no new sensor, but its one sensor has blind spots.

**Catches.** A denied libc file open from a dynamically linked process that keeps `LD_PRELOAD` (`interposer/*.c:817-1011`), followed by egress through the proxy.

**Does not catch.** The `file_blocked` row exists only if the interposer reports. Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass it, as does a failed report (connect error ignored, `interposer/*.c:456`; oversized message dropped, `:437-438`). Where Landlock is active it still denies those opens but writes no row, so the rule never trips. Slice 1 also misses a successful read of an allowed-but-sensitive file. Slice 2 covers that with a `sensitive` path list in the interposer that reports allowed opens of matching paths only (low volume), and it inherits the same bypasses.

**Closing the gap, later, in order of preference:**

1. *Seccomp user-notify.* The syscall fence already installs a seccomp filter (`internal/fence/syscallfence`). A supervisor sees `openat` from static binaries and raw syscalls too, for denials and sensitive reads alike. The cost is per-syscall latency and path races.
2. *Landlock audit records.* Newer kernels can log Landlock denials to audit. That needs no agent cooperation, but kernel support and audit access are not verified here.
3. *fanotify.* It sees opens of marked files by any process, so it fits slice 2's allowed reads better than denials, and it needs elevated privileges.
4. *Proxy-side view.* The proxy sees no files, but `on = "network_blocked"` is already logged and cannot be bypassed by anything routed through the proxy. It guards a different signal (probing hosts) and could ship beside slice 1.

Tests, each with a negative control:

1. Trigger row present: CONNECT to an allowlisted host is denied, and the row carries `rule=lookback:<name> trigger=<id>`. Control: no trigger row, same request allowed.
2. The denial row and trigger verify under `pkg/receipt` as INTACT. Tampering with the trigger id in Detail breaks the chain.
3. Trigger in a different session does not trip the rule.
4. Trigger older than `within` allows the request. A trigger timestamped in the future denies it.
5. 10,000 allowed `network_passed` rows after the trigger: still denied (laundering control).
6. Injected query error: denied, stderr set. Control: no rules configured, same error, egress unaffected.
7. Config load refuses unknown `on`, netns egress, ADVISORY and OFF. Control: CONFINED loads.
8. 1,000 denied requests to 1,000 distinct hostnames produce at most the cap in rows plus one summary row.
9. Race: a denied open and a CONNECT on another thread, 200 iterations. The CONNECT is denied every time. Control: same loop with no denied open, all allowed.
10. Open tunnel, then trigger: the tunnel closes within a bounded time and a `network_blocked` row records it. Control: no trigger, the tunnel is still open after the same interval.
11. Pinned limit: a denied open from a static binary or raw syscall writes no row, and the CONNECT stays allowed. This keeps the stated blind spot true until a later slice removes it.

## 5. What Box does that we deliberately don't copy

Sources: <https://github.com/strands-agents/box> (README) and its `docs/design/architecture.md`, read through a page summarizer. The architecture doc gave no look-back rule syntax, so nothing here claims to know it.

- **A general policy language** (Dogwood `permit` and `forbid`, README). We keep a flat TOML table with one rule kind, so the first slice carries no security-sensitive parser.
- **History across runs** (architecture doc). We scope to the session. Cross-session taint would let one stale read gate a project indefinitely, and it collides with `Prune`.
- **Unsigned OTLP JSON records** (README). Our decisions stay in the signed, hash-chained log, with no second, weaker log.
- **One interpreter for everything** (architecture doc). We wrap arbitrary agents with OS fences, so our observation is weaker (section 1) and we say so.
- **Mac-only** (README). Our rule must work on the Linux fence stack.
