# Look-back policy rules over the event history

Status: design note, no code. Nock #11296. Citations are `file:line` at `origin/main` eef51e4.

Strands Box evaluates policy against one shared event history, so a rule can say "this agent read a file earlier, so refuse its next outbound request" (section 5). NockLock has no such rule. This note says what we could build.

## 1. What the log records today

- **Store and chain.** SQLite `events` table with four single-column indexes (`internal/logging/logger.go:213-228`). Each row's hash and Ed25519 signature cover `id, ts, event_type, category, detail, blocked, session_id` and the previous hash (`canonicalBytes`, `:1105-1143`; `:641-646`). `pkg/receipt` verifies a session offline (`pkg/receipt/receipt.go:1-50`).
- **Query and retention.** `Logger.Query` can order by insertion id (`:800`, `QueryOptions.ByID` at `:111`). `Prune` deletes old rows (`:955`), so history is not permanent.

What it does not record matters more here:

1. **Allowed file reads are never logged.** The LD_PRELOAD interposer calls `report_blocked` only on denials (`internal/fence/fs/interposer/libfence_fs.c:407`, called from `:817-1011`), and the Go side logs each as `file_blocked` (`internal/cli/wrap.go:833-835`). The report is fire-and-forget (`libfence_fs.c:441-462`). "The agent read a secret" is unobservable.
2. **Secrets are logged once, at startup**, as env var names (`wrap.go:280-285`). Nothing records use.
3. **Network decisions** log `method=... host=...` (`internal/fence/network/handler.go:107,112`, `connect.go:30,46`). The netns path adds `rule=...` (`internal/cli/decision_log.go:66-82`).
4. **Timestamps are write-time `time.Now()`** (`decision_log.go:77` for netns).
5. **The HTTP proxy ignores audit-write errors** (`handler.go:164`). The netns path fails closed (`decision_log.go:146`).

## 2. Minimal rule shape

A look-back rule narrows egress after a trigger event is recorded in the current session. It never adds an allow.

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"      # trigger: an event_type already in the log
within = "10m"               # optional; default = rest of the session
then   = "deny_egress"       # deny every egress request while tripped
```

Tripped means the session has a row with `event_type = on` and `blocked = 1` newer than `within`. Evaluation is a pure function `Evaluate(rules, latestTrigger, now) -> (deny, ruleName, triggerID)` over one indexed lookup, `WHERE session_id=? AND event_type=? AND blocked=1 ORDER BY id DESC LIMIT 1`. `latestEvent` (`logger.go:574`) filters by type only, so this needs a session-scoped variant.

**Ordering: commit, close connections, then ack.** The trigger row lands after three hops: the interposer returns right after its write; `handleConn` queues the event on a 64-slot channel (`internal/fence/fs/fence.go:121,171`); a consumer goroutine calls `logEvent` (`wrap.go:831-836`). A CONNECT right after a denied `open` can be decided before the row exists. When a look-back rule is configured, slice 1 closes the window with a synchronous handoff; without rules the report stays fire-and-forget.

The report handler commits the `file_blocked` row itself, closes open connections, and only then writes a one-byte ack. The interposer waits for the ack, bounded at 250 ms, before returning EACCES. Acking earlier would let the agent resume while an old connection still carried bytes. If the ack times out or the connect fails, the open is still denied but the race reopens. That is a stated limit.

**SQLite contention.** The logger uses one pooled connection (`SetMaxOpenConns(1)`, `logger.go:434`), WAL mode (`:444`) and `busy_timeout=5000` (`:438`). Under WAL a read does not wait on another process's write lock, but on the one pooled connection an evaluate query queues behind any in-process write, including a trigger commit. A commit blocked by another process fails with SQLITE_BUSY after 5 s. That fails closed: the handler still runs close-all and sets an in-memory deny flag, read under the same mutex, so egress stays denied for the session and rows say `trigger=uncommitted`. A slow commit can miss the 250 ms ack: requests arriving meanwhile wait for the mutex rather than pass, but earlier tunnels stay open until close-all runs, up to 5 s later. That is part of the ack-timeout limit above.

**Connections already open.** `handleConnect` checks the allowlist once (`connect.go:29`), dials, hijacks (`:54`) and pipes bytes for up to five minutes (`:69-71`). A plain-HTTP request is also checked once (`handler.go:106`), then handed to `httputil.ReverseProxy` (`handler.go:146-156`), which streams the request body to the shared transport (`handler.go:150`) instead of buffering it. A streaming POST keeps sending while the client writes, bounded only by the five-minute `ReadTimeout` (`proxy.go:227`). Neither stops by itself when a trigger fires.

One rule covers both: close-all closes every upstream connection the proxy holds for the agent. Each is registered in one set under one proxy mutex at evaluate time, and that mutex is held across evaluate-and-register in the request path and across commit-and-close-all in the report handler. Each entry is removed from the set under the same mutex when its tunnel or request ends, by a `defer` around the pipe in `handleConnect` and around `forwardHTTP`, so the set holds only live connections.

- **CONNECT.** Evaluation runs after `Hijack`, under the mutex. It denies (raw 403, close) or adds the connection to the set before the 200 line is written.
- **Plain HTTP.** Evaluation runs under the mutex before `forwardHTTP`. It denies with 403 or registers a handle holding the request's cancel func and client connection. Close-all cancels the context, which aborts the transport's body write and closes the upstream connection, and closes the client connection, so no further body byte is read or sent. Reaching the client connection needs a `ConnContext` hook on both `http.Server` literals (`proxy.go:224,288`), which set none today. Close-all also calls `CloseIdleConnections` on the pool (`proxy.go:173-176`).

Dialing stays outside the mutex, so a slow dial cannot delay an ack. So every request is either registered before the commit begins, and close-all closes it, or evaluated after the commit, and the query denies it. Neither side holds the SQLite connection while waiting for the mutex, so they cannot deadlock.

**Cost.** A legitimate in-flight request to an allowed host, such as a large upload, is cut when a trigger fires. Bytes sent before the trigger are not recalled. New CONNECT and plain-HTTP requests wait for an in-flight trigger commit, usually milliseconds. The worst case is a commit stuck on `busy_timeout`: it holds the mutex for 5 s, so new requests stall up to that long. A separate read-only connection for evaluation is not worth building in slice 1. Evaluation may not run outside the mutex, since that reopens the evaluate-then-register gap, so requests would still wait on the mutex and the stall would remain. It would only spare evaluate from queuing behind short in-process writes.

Each closure writes a `network_blocked` row after the mutex is released, under the cap in section 3.

**Enforcement level.** At ADVISORY a client that ignores `HTTP_PROXY` reaches any host (`egress_level.go:72`), so with a look-back rule `wrap` refuses to start unless `egressLevelMeetsRequirement` holds (`egress_level.go:36-38`), as for `require_enforced` (`wrap.go:570-577`). With netns excluded, that leaves CONFINED (`egress_level.go:27-30`), so macOS is excluded.

**What CONFINED enforces.** In proxy mode the seccomp socket-family allowlist narrows to `unix` (`internal/cli/syscall_wire.go:99-100`), and the filter returns EPERM from `socket()` for other domains (`internal/fence/syscallfence/seccomp_linux.go:346-367`), so a direct TCP connect fails even for static binaries. Gaps: the filter is skipped for the 386 ABI (`seccomp_linux.go:223`, `denylist.go:184-187`), and `connect()` is unfiltered, so it lets through an inherited inet socket and also a Unix socket to any listener other than the proxy. The seccomp filter narrows `socket()` to `AF_UNIX`, so a local forwarder listening on a Unix socket is the direct route around the proxy. At CONFINED the rule holds against ordinary and static clients, not a determined one. Full enforcement needs KERNEL (netns), which slice 1 excludes.

**Where it runs.** In the `wrap` parent's HTTP proxy, beside `isAllowed` (`handler.go:31`, `:100-112`; `connect.go:26-31`), because that process owns the signing logger. The netns proxy runs as `nobody` with no DB handle or key (`netns/transparent_linux.go:57-71`), and the NockGuard proxy cannot import `internal/logging` (`pkg/receipt/receipt.go:1-6`). Both are out of scope.

**How the decision is signed.** A denial logs `network_blocked` through `Logger.Log` with `Detail = "method=CONNECT host=h rule=lookback:<name> trigger=<event id>"`. Detail is inside the signed bytes (`logger.go:635-646`), so the receipt binds the denial to the trigger row, with no new event type or verifier change. It uses the `rule=` form netns rows use (`decision_log.go:66-69`), not the JSON envelope (`logger.go:64-98`), which would change `network_blocked` Detail for every consumer. `internal/forward/forward.go:71-75` already forwards `network_blocked`.

## 3. Failure modes

- **History unreadable** (query error after the busy timeout, `Prune` removed the trigger). With a look-back rule configured, deny egress, surface on stderr, and record best-effort, per "fences fail closed" (`CLAUDE.md`). A pruned trigger cannot be detected, so `Prune` should refuse to delete rows from a live session (a follow-up).
- **Clock skew.** Count a negative age (trigger "in the future") as within the window, so it denies. A forward step expires `within` early and fails open, so a finite `within` trusts the host clock. Order by row id (`ByID`), not timestamp.
- **Noisy agent.** There is no "N events" window, since N harmless requests would launder the trigger. Spamming denied opens cuts the agent's own egress, which is availability, not an escape. A flood of denied requests writes a signed row each (`handler.go:107`), so cap it as `DefaultMaxDenialEvents = 500` does (`internal/fence/fs/denylog.go:114`): the first N per rule, then one summary row. The key is the rule, since the agent picks hostnames.
- **Rule that cannot fire.** A rule whose `on` names a type the event history can never contain can never trip, so it must not load as a silent no-op. The valid types are those in `internal/logging/logger.go:28-41`: `secret_blocked`, `secret_passed`, `file_blocked`, `file_passed`, `filesystem_fence_state`, `network_blocked`, `network_passed`, `proxy_start`, `proxy_stop`, `network_error`, `session_start`, `session_end`, `config_loaded` and `config.digest`. An `on` outside that list is a config error at start-up. Slice 1 accepts only `file_blocked`. Also refuse to start for netns egress (`wrap.go:659`), or any level other than CONFINED (`wrap.go:754` for OFF).

## 4. First slice and tests

Slice 1 is the `file_blocked` trigger (probe-then-exfil) on the HTTP proxy path at CONFINED only. It needs no new sensor, but the sensor has blind spots.

**Catches.** A denied libc file open from a dynamically linked process that keeps `LD_PRELOAD` (`libfence_fs.c:817-1011`), then egress through the proxy.

**Does not catch.** Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass the interposer, as does a failed report (`libfence_fs.c:456`, `:437-438`). Landlock still denies those opens but writes no row, so the rule never trips. Slice 1 also misses a successful read of a sensitive file; a slice 2 `sensitive` path list in the interposer would cover that, with the same bypasses.

**Later:** seccomp user-notify, Landlock audit records (unverified) or fanotify could close the gap.

Tests, each with a control:

1. Trigger row present: CONNECT to an allowlisted host is denied, and the row carries `rule=lookback:<name> trigger=<id>`. Control: no trigger row, same request allowed.
2. The denial row and trigger verify under `pkg/receipt` as INTACT. Editing the trigger id breaks the chain.
3. A trigger in another session does not trip the rule. Control: the same trigger here denies.
4. A trigger older than `within` allows the request. A future-dated one denies it.
5. 10,000 `network_passed` rows after the trigger: still denied. Control: no trigger, allowed.
6. Injected query error: denied, stderr set. Control: no rules, same error, egress unaffected.
7. Config load refuses unknown `on`, netns, ADVISORY and OFF. Control: CONFINED loads.
8. 1,000 denied requests to distinct hosts write at most the cap plus one summary row. Control: 100 requests write 100 rows.
9. Race: a denied open on one thread, and on another a CONNECT or a streaming plain-HTTP POST, 200 iterations each. No new connection or request survives past the ack: each is denied, or closed before the open returns. The receipt guarantees only that; bytes already accepted on an open connection when the rule trips are bounded by tunnel teardown, not prevented, so the test asserts no POST byte arrives after close-all completes and the client write then fails, not that none was in flight. Control: no denied open, every tunnel stays open and every POST body arrives complete.
10. Open tunnel, then trigger: the tunnel closes before the ack and a `network_blocked` row records it. A slow streaming POST is reset and its body arrives incomplete. Control: no trigger, the tunnel stays open and the POST completes.
11. Pinned limit: a denied open from a static binary or raw syscall writes no row, and the CONNECT stays allowed. Control: the same open from a dynamic binary writes a row and denies. A new sensor fails the first half, and the test is then updated.
12. A test seam pauses a CONNECT after `Hijack`, before the mutex, while the trigger commits and close-all finishes. On resume the CONNECT is denied. A second case pauses inside the critical section, after evaluate allows and before register, for a CONNECT and a plain-HTTP request: the report handler blocks on the mutex, and the connection is closed before the ack. Control: with the mutex removed, the second case leaves the connection open.
13. Ack scope: with no look-back rules the interposer does not wait. With rules, EACCES returns only after the ack.
14. Write contention. (a) Another connection holds the write lock for 300 ms, under `busy_timeout`, and the trigger commit is stalled behind it. A CONNECT arriving during the stall does not pass: it waits for the mutex, then is denied citing the new trigger row id. (b) The lock is held for 6 s, past `busy_timeout` (skipped under `-short`): the commit fails, close-all still runs, and CONNECTs, including one that arrived during the stall, are denied with `trigger=uncommitted`. Control for (b): with no lock held the same trigger commits and the denial cites the new row id. (c) An unrelated writer on a separate connection or process (not an in-process writer, which `SetMaxOpenConns(1)` would serialise behind the evaluate query) holds the lock for 300 ms and no trigger commit is in progress: a trigger-free CONNECT is allowed without waiting, since WAL reads do not wait. Control: same request with no writer, same result.
15. Set cleanup. After 100 CONNECT tunnels and 100 plain-HTTP requests finish, the registered set is empty. Control: while they are held open the set has 200 entries.

## 5. What Box does that we deliberately don't copy

Sources: <https://github.com/strands-agents/box> (README) and its `docs/design/architecture.md`, read through a summarizer. It gave no look-back rule syntax, so none is claimed.

- **A general policy language** (Dogwood `permit` and `forbid`). We keep a flat TOML table.
- **History across runs.** We scope to the session, since cross-session taint would let one stale read gate a project indefinitely.
- **Unsigned OTLP JSON records.** Ours stay in the signed, hash-chained log.
