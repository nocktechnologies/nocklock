# Look-back policy rules over the event history

Status: design note, no code. Nock #11296. Citations are `file:line` at `origin/main` eef51e4.

Strands Box evaluates every policy decision against one shared event history, so a rule can say "this agent read a file earlier, so refuse its next outbound request" (README and architecture doc, linked in section 5). NockLock has no such rule. This note says what we could build from what we already record.

## 1. What the log records today

- **Store.** SQLite `events` table: id, timestamp, event_type, category, detail, blocked, session_id, prev_hash, entry_hash, entry_sig (`internal/logging/logger.go:213-224`). Indexes on session, type, timestamp and blocked (`:225-228`). A signed `chain_head` row holds the head hash and row count (`:229-241`).
- **Chain.** Each row's hash covers `id, ts, event_type, category, detail, blocked, session_id` plus the previous hash (`canonicalBytes`, `:1105-1143`). The Ed25519 signature covers the same bytes (`:641-646`). The head is re-signed on every write (`:661-672`). `pkg/receipt` verifies a session offline (`pkg/receipt/receipt.go:1-50`).
- **Event types** (`logger.go:27-41`): secret, file and network passed/blocked, proxy start/stop, network error, session start/end, config loaded and digest.
- **Query.** `Logger.Query` filters by type, category, blocked, session and time, and can order by insertion id (`:800`, `QueryOptions.ByID` at `:111`). `WithEventCommitted` calls back after each commit (`:152`).
- **Retention.** `Prune` deletes old rows and re-anchors the chain (`:955`). History is not permanent.

What it does not record matters more for this feature:

1. **Allowed file reads are never logged.** The LD_PRELOAD interposer only calls `report_blocked` on denials (`internal/fence/fs/interposer/*.c:407`, called from `:817-1011`). The Go side logs each report as `file_blocked` (`internal/cli/wrap.go:833-835`). The `file_passed` rows are fence-state notes such as "landlock abi=..." (`wrap.go:439-551`), not accesses. Landlock gives no per-access events. The macOS denial tailer is best-effort and denials only (`wrap.go:925-945`). So today "the agent read a secret" is unobservable. "The agent was denied a read of a fenced path" is observable.
2. **Secrets are logged once, at startup.** `secret_passed` lists the env var names passed to the child (`wrap.go:280-285`). It says nothing about use.
3. **Network decisions** log `method=... host=...` (`internal/fence/network/handler.go:107,112,160-171`, `connect.go:30,46`). The netns path logs `method=... host=h:port rule=...` (`internal/cli/decision_log.go:66-82`).
4. **Timestamps are the logger's `time.Now()`** at write time. For netns decisions that is when `wrap` folds the record in, not when the proxy decided (`decision_log.go:77`).
5. **The HTTP proxy ignores audit-write errors** (`handler.go:165`, `_ = p.logger.Log`). The netns path fails closed on them (`decision_log.go:146`, `transparent_linux.go:206`).

## 2. Minimal rule shape

A look-back rule narrows egress after a trigger event has been recorded in the current session. It is not a new allow. The existing allowlist already denies unlisted hosts, so "block non-allowlisted hosts after a read" adds nothing by itself. The rule's value is revoking allowlisted hosts, or tightening `allow_all` configs.

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"      # trigger: an event_type already in the log
within = "10m"               # optional; default = rest of the session
then   = "deny_egress"       # deny every egress request while tripped
```

Semantics: tripped if the session has a row with `event_type = on` and `blocked = 1` where the row is newer than `within`. Evaluation is a pure function `Evaluate(rules, latestTrigger, now) -> (deny bool, ruleName, triggerID)`. Its input is one indexed lookup, `WHERE session_id=? AND event_type=? AND blocked=1 ORDER BY id DESC LIMIT 1` (the indexes at `logger.go:225-228`). It resembles `latestEvent` (`:574`), which filters by type only, so it needs a session-scoped variant.

**Where it runs.** In the `wrap` parent's HTTP proxy, beside `isAllowed` (`handler.go:31`, `:100-112`; `connect.go:26-31`). That process owns the signing logger. Other places:

- **netns transparent proxy:** not feasible as is. It runs as `nobody` with no DB handle or key and only appends TSV lines (`transparent_linux.go:57-71`, `:206`). A later slice could give it a pre-opened read-only latch file that `wrap` writes after the trigger commits. There is a small race between commit and write.
- **Filesystem fence:** wrong layer. It sees files, not egress.
- **NockGuard proxy** (`~/Dev/nockguard/internal/proxy`, separate repo, skimmed only): a candidate for MCP and forward-HTTP. `internal/logging` is not importable outside this module (`receipt.go:1-6`), so it would need a public read-only history API in `pkg/`. Out of scope here.

**How the decision is signed.** Reuse the existing row. A denial logs `network_blocked` through `Logger.Log` with `Detail = "method=CONNECT host=h rule=lookback:<name> trigger=<event id>"`. Detail is inside the hashed and signed bytes (`logger.go:635-646`), so the receipt binds the denial to the trigger row. No new event type, no canonical-bytes change, no verifier change. A structured alternative is the versioned JSON envelope in the detail column (`logger.go:64-98`, today `session_start` only). It would make the fields queryable but changes `network_blocked` Detail for every consumer, so slice 1 keeps the `rule=` key=value form that netns rows already use. This follows the precedent at `decision_log.go:66-69`, and `forward.go:71-75` already forwards `network_blocked` to Command.

## 3. Failure modes

- **History unreadable** (DB locked, query error, `Prune` removed the trigger). With any look-back rule configured, deny egress, surface on stderr, and record on a best-effort basis. This matches "fences fail closed" (`CLAUDE.md`) and the netns precedent. A rule-free config is unaffected, so there is no cost to existing users. A pruned trigger inside the window cannot be detected, so `Prune` should refuse to delete rows from a live session (a follow-up to check, not designed here).
- **Clock skew.** Wall-clock windows break two ways. A backward step puts the trigger "in the future": count negative age as within the window (deny). A forward step expires `within` early, which fails open. So the default window is the whole session, which has no clock dependency. A finite `within` is an explicit opt-in, and the docs must say it trusts the host clock. Use row id, not timestamp, for ordering (`ByID`), given point 4 in section 1.
- **Noisy agent.**
  - *Laundering by volume.* An "N events" window is bypassable: read the secret, make N harmless allowed requests, and the trigger falls out of the window. So we do not offer event-count windows. The latest trigger row is found by type, so unrelated noise cannot displace it.
  - *Self-DoS.* Spamming denied file opens trips the rule and cuts the agent's own egress. That is availability, not an escape, and acceptable.
  - *Row growth.* A flood of denied requests writes one signed row each (`handler.go:107`). Cap it as `DefaultMaxDenialEvents = 500` does (`internal/fence/fs/denylog.go:114`): log the first N per `(rule, host)`, then one suppression summary row.
  - *Query cost.* One indexed lookup per egress decision. Cache only if measured.
- **Rule that cannot fire.** Refuse to start (Box does the same). Examples: unknown `on` type; rules configured while netns egress is active, since slice 1 does not cover it (`wrap.go:659`); `egress level=OFF` where no proxy is in the path (`wrap.go:754`).

## 4. First slice and tests

Slice 1 is the `file_blocked` trigger (probe-then-exfil) on the HTTP proxy path only. It needs no new sensor. It is honest about its limits: it catches an agent that was denied a fenced path and then reaches for the network. It does not catch a successful read of an allowed-but-sensitive file. That needs slice 2, a `sensitive` path list in the interposer that reports allowed opens of matching paths only (low volume). The interposer is bypassable by static binaries and raw syscalls, so slice 2 should say so.

Tests, each with a negative control:

1. Trigger row present: CONNECT to an allowlisted host is denied, and the row carries `rule=lookback:<name> trigger=<id>`. Control: no trigger row, same request allowed.
2. The denial row and trigger verify under `pkg/receipt` as INTACT. Tampering with the trigger id in Detail breaks the chain.
3. Trigger in a different session does not trip the rule.
4. Trigger older than `within` allows the request. A trigger timestamped in the future denies it.
5. 10,000 allowed `network_passed` rows after the trigger: still denied (laundering control).
6. Injected query error: denied, stderr set. Control: no rules configured, same error, egress unaffected.
7. Config load refuses unknown `on`, netns egress, and egress OFF.
8. 1,000 denied requests produce at most the cap in rows plus one summary row.

## 5. What Box does that we deliberately don't copy

Sources: <https://github.com/strands-agents/box> (README) and <https://github.com/strands-agents/box/blob/main/docs/design/architecture.md>. I read these through a page summarizer. The architecture doc gave no look-back rule syntax, so nothing here claims to know it.

- **A general policy language.** Box uses Dogwood, with `permit` and `forbid` rules (README). We keep a flat TOML table with one rule kind. A language is more than a first slice, or a security-sensitive parser, should carry.
- **Box-durable history across runs** (architecture doc). We scope to the session. Cross-session taint would let one stale read gate a project indefinitely, and it collides with `Prune`.
- **Unsigned OTLP JSON records** at `<box_dir>/private/telemetry/records.jsonl` (README). Our decisions stay in the signed, hash-chained SQLite log. That is our differentiator, and we do not add a second, weaker log.
- **One interpreter for everything.** Box routes shell, Python, MCP and network through its own interpreters and gateway (architecture doc). We wrap arbitrary agents with OS fences, so we have weaker observation (section 1) and must say so.
- **Mac-only.** Box is macOS on Apple silicon today (README). Our rule must work on the Linux fence stack.
