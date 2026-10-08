# Look-back policy rules over the event history

Status: design note, no code. Nock #11296. Citations are `file:line` at `origin/main` eef51e4.

Strands Box evaluates policy against one shared event history, so a rule can say "this agent read a file earlier, so refuse its next outbound request" (section 5). NockLock has no such rule. This note says what we could build from what we record.

## 1. What the log records today

- **Store and chain.** SQLite `events` table with four single-column indexes (`internal/logging/logger.go:213-228`). Each row's hash and Ed25519 signature cover `id, ts, event_type, category, detail, blocked, session_id` and the previous hash (`canonicalBytes`, `:1105-1143`; `:641-646`). `pkg/receipt` verifies a session offline (`pkg/receipt/receipt.go:1-50`).
- **Query and retention.** `Logger.Query` filters on those columns and can order by insertion id (`:800`, `QueryOptions.ByID` at `:111`). `Prune` deletes old rows (`:955`), so history is not permanent.

What it does not record matters more here:

1. **Allowed file reads are never logged.** The LD_PRELOAD interposer calls `report_blocked` only on denials (`internal/fence/fs/interposer/libfence_fs.c:407`, called from `:817-1011`), and the Go side logs each as `file_blocked` (`internal/cli/wrap.go:833-835`). The `file_passed` rows are fence-state notes (`wrap.go:439-551`). Landlock gives no per-access events. The report is fire-and-forget: connect, write, close, ignore failures (`libfence_fs.c:441-462`). "The agent read a secret" is unobservable.
2. **Secrets are logged once, at startup**, as env var names (`wrap.go:280-285`). Nothing records use.
3. **Network decisions** log `method=... host=...` (`internal/fence/network/handler.go:107,112`, `connect.go:30,46`). The netns path adds `rule=...` (`internal/cli/decision_log.go:66-82`).
4. **Timestamps are write-time `time.Now()`**, for netns decisions when `wrap` folds the record in (`decision_log.go:77`).
5. **The HTTP proxy ignores audit-write errors** (`handler.go:164`). The netns path fails closed (`decision_log.go:146`, `internal/fence/network/netns/transparent_linux.go:206`).

## 2. Minimal rule shape

A look-back rule narrows egress after a trigger event is recorded in the current session. It never adds an allow. It revokes allowlisted hosts or tightens `allow_all` configs.

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"      # trigger: an event_type already in the log
within = "10m"               # optional; default = rest of the session
then   = "deny_egress"       # deny every egress request while tripped
```

Tripped means the session has a row with `event_type = on` and `blocked = 1` newer than `within`. Evaluation is a pure function `Evaluate(rules, latestTrigger, now) -> (deny, ruleName, triggerID)` over one indexed lookup, `WHERE session_id=? AND event_type=? AND blocked=1 ORDER BY id DESC LIMIT 1`. `latestEvent` (`logger.go:574`) filters by type only, so this needs a session-scoped variant.

**Ordering: commit, close connections, then ack.** The trigger row lands after three hops: the interposer returns right after its write; `handleConn` queues the event on a 64-slot channel (`internal/fence/fs/fence.go:121,171`); a consumer goroutine calls `logEvent` (`wrap.go:831-836`). A CONNECT right after a denied `open` can be decided before the row exists. Slice 1 closes the window with a synchronous handoff, only when a look-back rule is configured: `wrap` tells the interposer to wait for an ack. Without rules, the report stays fire-and-forget.

With rules, the report handler commits the `file_blocked` row itself, closes open connections, and only then writes a one-byte ack. The interposer waits for the ack, bounded at 250 ms, before returning EACCES. Acking before the close would let the agent resume while an older connection still carried bytes. An in-memory latch has no row id to cite until the commit. If the ack times out or the connect fails, the open is still denied but the race reopens. That is a stated limit.

**SQLite contention.** The logger uses one connection (`SetMaxOpenConns(1)`, `logger.go:434`), WAL mode (`:444`) and `busy_timeout=5000` (`:438`). Under WAL a read does not wait on a writer's lock. A trigger commit blocked by another process fails with SQLITE_BUSY after 5 s. That fails closed: the handler still runs close-all and sets an in-memory deny flag, read under the same mutex, so egress stays denied for the session and rows say `trigger=uncommitted`. A slow commit can only miss the 250 ms ack.

**Connections already open.** `handleConnect` checks the allowlist once (`connect.go:29`), dials, hijacks (`:54`) and pipes bytes for up to five minutes (`:69-71`). A plain-HTTP request is also checked once (`handler.go:106`), then handed to `httputil.ReverseProxy` (`handler.go:146-156`), which passes the request body to the shared transport (`handler.go:150`) as the outbound body instead of buffering it. A POST with a streaming or chunked body keeps sending while the client writes, bounded only by the five-minute `ReadTimeout` (`proxy.go:227`). Neither kind stops by itself when a trigger fires.

One rule covers both: close-all covers every upstream connection the proxy holds open for the agent, CONNECT tunnels and in-flight plain-HTTP requests alike. Each is registered in one set under one proxy mutex at evaluate time, and that mutex is held across evaluate-and-register in the request path and across commit-and-close-all in the report handler.

- **CONNECT.** The authoritative evaluation runs after `Hijack`, under the mutex. It either denies (raw 403, close) or adds the connection to the set before the 200 line is written.
- **Plain HTTP.** Evaluation runs under the mutex before `forwardHTTP`. It denies with 403 or registers a handle holding the request's cancel func and its client connection. Close-all cancels the context, which aborts the transport's body write and closes that upstream connection, and closes the client connection, so no further body byte is read or sent. Reaching the client connection needs a `ConnContext` hook on both `http.Server` literals (`proxy.go:224,288`), which set none today. Idle pooled upstream connections (`proxy.go:173-176`) carry nothing, and close-all drops them with `CloseIdleConnections`.

Dialing stays outside the mutex, so a slow dial cannot delay an ack. An earlier pre-dial check may save a dial but is never relied on.

So every CONNECT and plain-HTTP request is either registered before the commit begins, and close-all closes it, or evaluated after the commit, and the query denies it. None can be evaluated before the commit and registered after the close. Neither side holds the SQLite connection while waiting for the mutex, so they cannot deadlock. Register-then-re-evaluate was rejected: it needs two evaluations and an argument that they cover the gap.

**Cost.** A legitimate in-flight request to an allowed host, such as a large upload or long download, is cut when a trigger fires, and the agent sees a reset. New connections also wait for an in-flight trigger commit. Bytes sent before the trigger are not recalled.

Each closure writes a `network_blocked` row with `rule=lookback:<name> trigger=<id>`, after the mutex is released, under the cap in section 3.

**Enforcement level.** At ADVISORY a client that ignores `HTTP_PROXY` reaches any host (`egress_level.go:72`), so with a look-back rule `wrap` refuses to start unless `egressLevelMeetsRequirement` holds (`egress_level.go:36-38`), as for `require_enforced` (`wrap.go:570-577`). With netns excluded, that leaves CONFINED: Linux, syscall enforcement and the interposer (`egress_level.go:27-30`). macOS reaches only ADVISORY or OFF, so it is excluded.

**What CONFINED enforces for connect().** `syscallEnforced` needs a seccomp policy and `syscallfence.Supported()` (`wrap.go:534-535,558`). In proxy mode `buildSyscallPolicy` narrows the socket-family allowlist to `unix` (`internal/cli/syscall_wire.go:99-100`), and the filter returns EPERM from `socket()` for any other domain (`internal/fence/syscallfence/seccomp_linux.go:346-367`). A direct TCP connect needs an AF_INET socket the kernel refuses to create, for static binaries and raw syscalls too, since seccomp needs no `LD_PRELOAD`. The filter does not inspect `connect()`. Limits:

- The family filter is skipped for the 386 ABI (`seccomp_linux.go:223`), where `socket` goes through `socketcall`, and amd64 installs 386 as a secondary ABI (`denylist.go:184-187`). Whether a 32-bit process can open an inet socket under CONFINED is untested.
- `connect()` is unfiltered, so an inherited inet socket, or a Unix socket to a listener other than the proxy, is not stopped.

Until those close, look-back deny is fully enforced only at KERNEL (netns), which slice 1 excludes. At CONFINED it holds against ordinary and static clients, not a determined one.

**Where it runs.** In the `wrap` parent's HTTP proxy, beside `isAllowed` (`handler.go:31`, `:100-112`; `connect.go:26-31`), because that process owns the signing logger. The netns proxy runs as `nobody` with no DB handle or key (`netns/transparent_linux.go:57-71`), and the NockGuard proxy cannot import `internal/logging` (`pkg/receipt/receipt.go:1-6`). Both are out of scope.

**How the decision is signed.** A denial logs `network_blocked` through `Logger.Log` with `Detail = "method=CONNECT host=h rule=lookback:<name> trigger=<event id>"`. Detail is inside the hashed and signed bytes (`logger.go:635-646`), so the receipt binds the denial to the trigger row. No new event type or verifier change. Slice 1 uses the `rule=` key=value form netns rows use (`decision_log.go:66-69`), not the JSON envelope (`logger.go:64-98`), which would change `network_blocked` Detail for every consumer. `internal/forward/forward.go:71-75` already forwards `network_blocked`.

## 3. Failure modes

- **History unreadable** (query error after the busy timeout, `Prune` removed the trigger). With a look-back rule configured, deny egress, surface on stderr, and record best-effort, per "fences fail closed" (`CLAUDE.md`). A rule-free config is unaffected. A pruned trigger cannot be detected, so `Prune` should refuse to delete rows from a live session (a follow-up).
- **Clock skew.** A backward step puts the trigger "in the future": count negative age as within the window (deny). A forward step expires `within` early, which fails open, so the default is the whole session and a finite `within` trusts the host clock. Order by row id (`ByID`), not timestamp.
- **Noisy agent.**
  - *Laundering by volume.* An "N events" window is bypassable by N harmless requests, so there is none. The latest trigger is found by type.
  - *Self-DoS.* Spamming denied opens cuts the agent's own egress. That is availability, not an escape.
  - *Row growth.* A flood of denied requests writes one signed row each (`handler.go:107`). Cap it as `DefaultMaxDenialEvents = 500` does (`internal/fence/fs/denylog.go:114`): the first N per rule, then one summary row. The key is the rule, not `(rule, host)`, since the agent picks hostnames.
  - *Query cost.* One indexed lookup per decision. Cache only if measured.
- **Rule that cannot fire.** Refuse to start for: unknown `on` type; netns egress, which slice 1 does not cover (`wrap.go:659`); any effective level other than CONFINED, including OFF (`wrap.go:754`) and ADVISORY.

## 4. First slice and tests

Slice 1 is the `file_blocked` trigger (probe-then-exfil) on the HTTP proxy path at CONFINED only. It needs no new sensor, but that sensor has blind spots.

**Catches.** A denied libc file open from a dynamically linked process that keeps `LD_PRELOAD` (`libfence_fs.c:817-1011`), followed by egress through the proxy.

**Does not catch.** Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass the interposer, as does a failed report (connect error ignored, `libfence_fs.c:456`; oversized message dropped, `:437-438`). Landlock still denies those opens but writes no row, so the rule never trips. Slice 1 also misses a successful read of an allowed-but-sensitive file. A slice 2 `sensitive` path list in the interposer would cover that, with the same bypasses.

**Closing the gap, later:** seccomp user-notify, Landlock audit records (support unverified) or fanotify. An `on = "network_blocked"` rule is already logged and unbypassable through the proxy, so it could ship beside slice 1.

Tests. Each has a control and an outcome that fails if the rule is broken:

1. Trigger row present: CONNECT to an allowlisted host is denied, and the row carries `rule=lookback:<name> trigger=<id>`. Control: no trigger row, same request allowed.
2. The denial row and trigger verify under `pkg/receipt` as INTACT. Editing the trigger id breaks the chain.
3. A trigger in a different session does not trip the rule. Control: the same trigger in this session denies.
4. A trigger older than `within` allows the request. A future-dated trigger denies it.
5. 10,000 `network_passed` rows after the trigger: still denied. Control: no trigger, allowed.
6. Injected query error: denied, stderr set. Control: no rules, same error, egress unaffected.
7. Config load refuses unknown `on`, netns, ADVISORY and OFF. Control: CONFINED loads.
8. 1,000 denied requests to 1,000 distinct hosts write at most the cap plus one summary row. Control: 100 requests write 100 rows.
9. Race: a denied open on one thread, and on another a CONNECT or a plain-HTTP POST with a streaming body, 200 iterations each. No CONNECT tunnel and no in-flight plain-HTTP request survives past the ack: each is denied, or closed before the open returns. In the POST case the client keeps writing chunks across the trigger; after the ack the upstream test server receives no further byte and the client write fails. Control: no denied open, every tunnel stays open and every POST body arrives complete.
10. Open tunnel, then trigger: the tunnel closes before the ack and a `network_blocked` row records it. A slow streaming POST is reset and its body arrives incomplete. Control: no trigger, the tunnel stays open and the POST completes.
11. Pinned limit: a denied open from a static binary or raw syscall writes no row, and the CONNECT stays allowed. Control: the same open from a dynamic binary writes a row and denies. A new sensor fails the first half, and the test is then updated.
12. A test seam pauses a CONNECT after `Hijack`, before the mutex. The trigger commits and close-all finishes meanwhile. On resume the CONNECT is denied. A second case pauses inside the critical section, after evaluate allows and before register, for a CONNECT and for a plain-HTTP request: the report handler blocks, and the connection is closed before the ack. Control: with the mutex removed, the second case leaves the connection open.
13. Ack scope: with no look-back rules the interposer does not wait. With rules, EACCES returns only after the ack.
14. Write contention. (a) Another connection holds the write lock for 300 ms, under `busy_timeout`: the trigger commit waits and succeeds, and a trigger-free CONNECT during the hold is allowed because WAL reads do not wait. (b) The lock is held for 6 s, past `busy_timeout` (skipped under `-short`): the commit fails, close-all still runs, and later CONNECTs are denied with `trigger=uncommitted`. Control for (b): the same trigger with no lock held commits, and the denial cites the new row id. Allowing egress after the failed commit fails (b).

## 5. What Box does that we deliberately don't copy

Sources: <https://github.com/strands-agents/box> (README) and its `docs/design/architecture.md`, read through a page summarizer. It gave no look-back rule syntax, so none is claimed.

- **A general policy language** (Dogwood `permit` and `forbid`). We keep a flat TOML table, so slice 1 has no security-sensitive parser.
- **History across runs.** We scope to the session, since cross-session taint would let one stale read gate a project indefinitely and collides with `Prune`.
- **Unsigned OTLP JSON records.** Our decisions stay in the signed, hash-chained log.
