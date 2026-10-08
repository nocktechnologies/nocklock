# Look-back policy rules over the event history

Status: design note, no code. Nock #11296. Citations are `file:line` at `origin/main` eef51e4.

Strands Box evaluates every policy decision against one shared event history, so a rule can say "this agent read a file earlier, so refuse its next outbound request" (README and architecture doc, section 5). NockLock has no such rule. This note says what we could build from what we record.

## 1. What the log records today

- **Store and chain.** SQLite `events` table with four single-column indexes (`internal/logging/logger.go:213-228`). Each row's hash and Ed25519 signature cover `id, ts, event_type, category, detail, blocked, session_id` plus the previous hash (`canonicalBytes`, `:1105-1143`; `:641-646`). `pkg/receipt` verifies a session offline (`pkg/receipt/receipt.go:1-50`).
- **Query and retention.** `Logger.Query` filters on those columns and can order by insertion id (`:800`, `QueryOptions.ByID` at `:111`). `Prune` deletes old rows (`:955`), so history is not permanent.

What it does not record matters more for this feature:

1. **Allowed file reads are never logged.** The LD_PRELOAD interposer calls `report_blocked` only on denials (`internal/fence/fs/interposer/libfence_fs.c:407`, called from `:817-1011`), and the Go side logs each as `file_blocked` (`internal/cli/wrap.go:833-835`). The `file_passed` rows are fence-state notes (`wrap.go:439-551`). Landlock gives no per-access events, so a denial the interposer never reported leaves no row. Today the report is fire-and-forget: connect, write, close, ignore failures (`libfence_fs.c:441-462`). So "the agent read a secret" is unobservable.
2. **Secrets are logged once, at startup**, as env var names (`wrap.go:280-285`). Nothing records use.
3. **Network decisions** log `method=... host=...` (`internal/fence/network/handler.go:107,112`, `connect.go:30,46`). The netns path adds `rule=...` (`internal/cli/decision_log.go:66-82`).
4. **Timestamps are write-time `time.Now()`.** For netns decisions that is when `wrap` folds the record in (`decision_log.go:77`).
5. **The HTTP proxy ignores audit-write errors** (`handler.go:164`). The netns path fails closed (`decision_log.go:146`, `internal/fence/network/netns/transparent_linux.go:206`).

## 2. Minimal rule shape

A look-back rule narrows egress after a trigger event has been recorded in the current session. It is not a new allow. Its value is revoking allowlisted hosts, or tightening `allow_all` configs.

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"      # trigger: an event_type already in the log
within = "10m"               # optional; default = rest of the session
then   = "deny_egress"       # deny every egress request while tripped
```

Tripped means the session has a row with `event_type = on` and `blocked = 1` newer than `within`. Evaluation is a pure function `Evaluate(rules, latestTrigger, now) -> (deny, ruleName, triggerID)` over one indexed lookup, `WHERE session_id=? AND event_type=? AND blocked=1 ORDER BY id DESC LIMIT 1`. `latestEvent` (`logger.go:574`) filters by type only, so this needs a session-scoped variant.

**Ordering: commit, close tunnels, then ack.** The trigger row lands after three hops: the interposer returns right after its write; `handleConn` queues the event on a 64-slot channel (`internal/fence/fs/fence.go:121,171`); a consumer goroutine calls `logEvent` (`wrap.go:831-836`). A CONNECT on another thread right after a denied `open` can be decided before the row exists. Slice 1 closes the window with a synchronous handoff, but only when at least one look-back rule is configured. Then `wrap` tells the interposer to wait for an ack. A config without look-back rules keeps today's fire-and-forget report, with no new wait and no new write.

With rules, the report handler commits the `file_blocked` row itself, closes open tunnels, and only then writes a one-byte ack. The interposer waits for the ack, bounded at 250 ms, before returning EACCES. Acking before the close would reopen the race: the agent would resume while a tunnel opened before the trigger still carried bytes. An in-memory latch was rejected because it has no row id to cite until the commit. If the ack times out or the connect fails, the open is still denied but the race reopens. That is a stated limit.

**SQLite contention.** The logger uses one connection (`SetMaxOpenConns(1)`, `logger.go:434`), WAL mode (`:444`) and `busy_timeout=5000` (`:438`). Denied opens are rare, so one extra commit is not hot. Under WAL a read does not wait on a writer's lock, only for the pool's one connection during an in-process write. A writer blocked by another process waits up to 5 s before SQLITE_BUSY. Egress is denied for a query error (section 3), never for waiting, and a slow commit can only miss the 250 ms ack.

**Tunnels already open.** `handleConnect` checks the allowlist once (`connect.go:29`), dials, hijacks (`:54`) and pipes bytes for up to five minutes (`:69-71`), so a tunnel opened before the trigger would stay usable. One rule covers the race: a single proxy mutex is held across evaluate-and-register in the CONNECT path, and across commit-and-close-all in the report handler. The authoritative evaluation runs after `Hijack`, under the mutex. It either denies (raw 403, close) or adds the connection to the tunnel set before the 200 line is written. Dialing stays outside the mutex, so a slow dial cannot delay an ack. An earlier check before the dial may save the dial but is never relied on.

So every CONNECT is either registered before the commit begins, and close-all closes it, or evaluated after the commit, and the query denies it. None can be evaluated before the commit and registered after the close. Neither side holds the SQLite connection while waiting for the mutex, so they cannot deadlock. The rejected alternative, register before evaluate and re-evaluate after hijack, needs two evaluations and an argument that they cover the gap. The cost is that CONNECT setup waits for an in-flight trigger commit.

Each closure writes a `network_blocked` row with `rule=lookback:<name> trigger=<id>`, after the mutex is released, under the cap in section 3. Plain HTTP requests are re-evaluated per request without the mutex. One already evaluated may finish, like bytes sent before the trigger, which are not recalled.

**Enforcement level.** At ADVISORY a client that ignores `HTTP_PROXY` reaches any host (`egress_level.go:72`), so with any look-back rule `wrap` refuses to start unless `egressLevelMeetsRequirement` holds (`egress_level.go:36-38`), the same refusal as `require_enforced` (`wrap.go:570-577`). With netns excluded from slice 1, that leaves CONFINED: Linux, syscall enforcement and the interposer (`egress_level.go:27-30`). macOS reaches only ADVISORY or OFF, so it is excluded.

**What CONFINED enforces for connect().** `syscallEnforced` is true when a seccomp policy is configured and `syscallfence.Supported()` holds (`wrap.go:534-535,558`). In proxy mode `buildSyscallPolicy` narrows the socket-family allowlist to `unix` (`internal/cli/syscall_wire.go:99-100`), and the filter returns EPERM from `socket()` for any other domain (`internal/fence/syscallfence/seccomp_linux.go:346-367`). A direct TCP connect would need an AF_INET socket the kernel refuses to create, for static binaries and raw syscalls too, because seccomp acts at syscall entry and needs no `LD_PRELOAD`. The filter does not inspect `connect()` itself. Limits:

- The family filter is skipped for the 386 ABI (`seccomp_linux.go:223`), where `socket` goes through `socketcall`, and amd64 installs 386 as its secondary ABI (`denylist.go:184-187`). Whether a 32-bit process can open an inet socket under CONFINED is not tested here.
- `connect()` is unfiltered, so an inet socket inherited across exec, or a Unix socket to a listener other than the proxy, is not stopped.

Until those are closed, look-back deny is only fully enforced at KERNEL (netns), which slice 1 excludes. At CONFINED it holds against ordinary and static clients, not against a determined one.

**Where it runs.** In the `wrap` parent's HTTP proxy, beside `isAllowed` (`handler.go:31`, `:100-112`; `connect.go:26-31`), because that process owns the signing logger. The netns transparent proxy runs as `nobody` with no DB handle or key (`netns/transparent_linux.go:57-71`), and the NockGuard proxy cannot import `internal/logging` (`pkg/receipt/receipt.go:1-6`). Both are out of scope.

**How the decision is signed.** A denial logs `network_blocked` through `Logger.Log` with `Detail = "method=CONNECT host=h rule=lookback:<name> trigger=<event id>"`. Detail is inside the hashed and signed bytes (`logger.go:635-646`), so the receipt binds the denial to the trigger row. No new event type or verifier change. Slice 1 uses the `rule=` key=value form netns rows use (`decision_log.go:66-69`), not the JSON envelope (`logger.go:64-98`), which would change `network_blocked` Detail for every consumer. `internal/forward/forward.go:71-75` already forwards `network_blocked` to Command.

## 3. Failure modes

- **History unreadable** (query error after the busy timeout, `Prune` removed the trigger). With any look-back rule configured, deny egress, surface on stderr, and record best-effort. This matches "fences fail closed" (`CLAUDE.md`). A rule-free config is unaffected. A pruned trigger cannot be detected, so `Prune` should refuse to delete rows from a live session (a follow-up).
- **Clock skew.** A backward step puts the trigger "in the future": count negative age as within the window (deny). A forward step expires `within` early, which fails open. So the default window is the whole session, and a finite `within` is an opt-in that trusts the host clock. Order by row id (`ByID`), not timestamp.
- **Noisy agent.**
  - *Laundering by volume.* An "N events" window is bypassable by N harmless requests, so there are none. The latest trigger is found by type, so noise cannot displace it.
  - *Self-DoS.* Spamming denied opens cuts the agent's own egress. That is availability, not an escape.
  - *Row growth.* A flood of denied requests writes one signed row each (`handler.go:107`). Cap it as `DefaultMaxDenialEvents = 500` does (`internal/fence/fs/denylog.go:114`): log the first N per rule, then one suppression summary row per rule. The key is the rule, not `(rule, host)`, because the agent picks hostnames.
  - *Query cost.* One indexed lookup per egress decision. Cache only if measured.
- **Rule that cannot fire.** Refuse to start for: unknown `on` type; netns egress, which slice 1 does not cover (`wrap.go:659`); any effective level other than CONFINED, including OFF (`wrap.go:754`) and ADVISORY.

## 4. First slice and tests

Slice 1 is the `file_blocked` trigger (probe-then-exfil) on the HTTP proxy path at CONFINED only. It needs no new sensor, but its one sensor has blind spots.

**Catches.** A denied libc file open from a dynamically linked process that keeps `LD_PRELOAD` (`libfence_fs.c:817-1011`), followed by egress through the proxy.

**Does not catch.** Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass the interposer, as does a failed report (connect error ignored, `libfence_fs.c:456`; oversized message dropped, `:437-438`). Where Landlock is active it still denies those opens but writes no row, so the rule never trips. Slice 1 also misses a successful read of an allowed-but-sensitive file. A slice 2 `sensitive` path list in the interposer would cover that, with the same bypasses.

**Closing the gap, later:** seccomp user-notify (sees `openat` from static binaries, at a latency cost), Landlock audit records (support unverified here), or fanotify (needs privileges). A rule on `on = "network_blocked"` is already logged and unbypassable through the proxy, so it could ship beside slice 1.

Tests, each with a negative control:

1. Trigger row present: CONNECT to an allowlisted host is denied, and the row carries `rule=lookback:<name> trigger=<id>`. Control: no trigger row, same request allowed.
2. The denial row and trigger verify under `pkg/receipt` as INTACT. Editing the trigger id in Detail breaks the chain.
3. A trigger in a different session does not trip the rule.
4. A trigger older than `within` allows the request. A future-dated trigger denies it.
5. 10,000 `network_passed` rows after the trigger: still denied.
6. Injected query error: denied, stderr set. Control: no rules, same error, egress unaffected.
7. Config load refuses unknown `on`, netns, ADVISORY and OFF. Control: CONFINED loads.
8. 1,000 denied requests to 1,000 distinct hosts write at most the cap plus one summary row.
9. Race: a denied open and a CONNECT on another thread, 200 iterations. No tunnel survives past the ack: each CONNECT is denied or its tunnel is closed before the open returns. Control: same loop with no denied open, every tunnel stays open.
10. Open tunnel, then trigger: the tunnel closes before the ack and a `network_blocked` row records it. Control: no trigger, the tunnel is still open after the same interval.
11. Pinned limit: a denied open from a static binary or raw syscall writes no row, and the CONNECT stays allowed.
12. Pause between evaluate and hijack: a test seam pauses a CONNECT after `Hijack`, before the mutex. The trigger commits and close-all finishes meanwhile. On resume the CONNECT is denied. A second case pauses inside the critical section, after evaluate allows and before register: the report handler blocks, and the tunnel is closed before the ack. Control: with the mutex removed, the second case leaves the tunnel open, so the test can see the race.
13. Ack scope: with no look-back rules the interposer does not wait. With rules, EACCES returns only after the ack.
14. Write contention: another connection holds the write lock for 300 ms, and a trigger-free CONNECT is still allowed. Control: with `busy_timeout` below the hold time, the query fails and egress is denied per section 3.

## 5. What Box does that we deliberately don't copy

Sources: <https://github.com/strands-agents/box> (README) and its `docs/design/architecture.md`, read through a page summarizer. The architecture doc gave no look-back rule syntax, so nothing here claims one.

- **A general policy language** (Dogwood `permit` and `forbid`, README). We keep a flat TOML table, so slice 1 has no security-sensitive parser.
- **History across runs** (architecture doc). We scope to the session. Cross-session taint would let one stale read gate a project indefinitely, and it collides with `Prune`.
- **Unsigned OTLP JSON records** (README). Our decisions stay in the signed, hash-chained log.
- **One interpreter for everything** (architecture doc). We wrap arbitrary agents with OS fences, so our observation is weaker (section 1).
