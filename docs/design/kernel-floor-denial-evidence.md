# Signed evidence for kernel-floor network denials

Date: 2026-10-12

Status: **Proposed; feasibility and design only**

Nock: N11634

Baseline: `a793375` (v0.7.0)

## Decision and claim boundary

Implement **Linux netns output-drop NFLOG observations first**, behind an
explicit capability/preflight check. Retain the existing nftables default-drop
policy and proxy decision rows. Each accepted kernel observation becomes a
signed `network_blocked` row, accompanied by signed coverage/health records and
a final counter summary. Prototype the observation path and measure it before
committing to production defaults. This note adds no code or enforcement claim.

Do not call those rows a complete per-application-attempt history. NFLOG observes
packets: one `connect()` can retransmit, a syscall can fail before any packet is
created, and queues can lose observations. A signature authenticates what the
trusted collector recorded; it does not turn a lossy sensor into a complete one.
The product promise for slice 1 is **signed, bounded kernel-drop evidence with
explicit coverage**, not "every denied attempt is signed."

If the requirement is literally a durable row for every denied syscall, this
slice does not satisfy it. That requires a different syscall mediation design,
including a policy for stopping the session when evidence cannot be committed.
Resolve that product distinction at design review, before implementation.

## Current behavior and gaps

| Path at this baseline | Enforcement | Existing evidence | Gap |
| --- | --- | --- | --- |
| Linux netns transparent HTTP(S) | Proxy domain policy plus namespace floor | Sidecar decision records ingested by `wrap` | Decisions that reach this proxy are distinct from packets dropped elsewhere |
| Linux netns direct egress outside allowed paths | Restricted routing plus nftables `output` default drop | No per-drop signed row | NFLOG covers only packets that reach the instrumented rule |
| Linux seccomp socket-family restrictions | `SECCOMP_RET_ERRNO` / EPERM | Setup/enforcement state | No syscall-denial callback to the parent |
| macOS Seatbelt network floor | SBPL network and resolver-service restrictions | Session-tagged messages requested by the policy | Existing unified-log parser accepts file operations, not network denials |

Source anchors: `EgressRuleset` in
`internal/fence/network/netns/egress_linux.go`; privileged lifecycle in
`internal/fence/network/netns/egress_helper_linux.go`; sidecar decision writer in
`internal/fence/network/netns/transparent_linux.go`; seccomp under
`internal/fence/syscallfence`; `internal/fence/fs/denylog.go` and
`internal/fence/fs/sbpl.go`; signed event envelope in
`internal/logging/logger.go`; ingestion/session closeout in
`internal/cli/wrap.go`.

The implementation must re-check these against the head it targets. This design
does not change the currently assigned look-back, helper subnet allocation,
doctor or macOS Unix-socket work.

## Options and costs

| Sensor | What one observation means | Privilege / implementation cost | Completeness and operational cost | Decision |
| --- | --- | --- | --- | --- |
| nftables NFLOG | A packet reaching an instrumented rule | Existing root helper opens/configures a namespace-local netlink receiver; new bounded decoder and transport | Queues and rate limits lose detail; packet retransmissions inflate apparent attempts; counters can bound coverage | Slice 1 |
| nftables kernel log / `dmesg` | Kernel text for a matching packet | Host log reader and namespace/session correlation | Global noise, permissions, text changes and host logging pressure | Avoid as primary transport |
| seccomp ERRNO with host audit logging | An audited denied syscall, where host audit policy emits it | Admin audit configuration/reader integration | Host-wide delivery policy and loss behavior are outside this process | Retain ERRNO; defer optional observation |
| seccomp USER_NOTIF | A syscall held for a supervisor decision | Replace selected filter actions; manage listener, liveness and responses | Changes the enforcement mechanism; a stalled receiver stalls tasks | Defer; not passive telemetry |
| Seatbelt unified-log stream | A sandbox diagnostic emitted and retained by macOS | Extend existing collector/parser; validate privileges on each supported OS | Emission, privacy redaction, duplicate/rate filtering and stream gaps prevent lossless claims | Follow-up spike |

NFLOG is closest to the actual rule being explained and avoids changing the
seccomp decision mechanism. The new root-side parser is still security-sensitive
code. Use the existing `x/sys` facilities where suitable and bounded parsing;
adding libnetfilter_log/cgo or another netlink dependency requires a separate
dependency decision. No dependency is added by this design.

## Linux NFLOG slice

Proposed opt-in: an additive `[audit.kernel_denials]` table with
`enabled = true`; absence/false preserves current behavior. On an unsupported
platform or a Linux run without netns, enabling it must refuse launch with the
supported-mode remedy. Keep limits fixed for slice 1 and record them in the
signed startup state. This is a proposed config contract, not an existing key.

### Scope and rule placement

Instrument only the **terminal output denial path** of the per-session `inet
nocklock` ruleset. Keep established traffic, loopback and the privileged proxy
path exactly as their current allow rules specify. Add a jump after those
allows to a dedicated regular chain, with this logical order:

```text
output: existing allow rules; jump floor_output; policy drop
floor_output:
  count every packet reaching this denial path
  rate-limited NFLOG observation (no terminating verdict)
  explicit drop
```

The counter precedes rate limiting; the drop is unconditional and separate from
the logging rule. Missing receivers, full buffers, exhausted log tokens and
collector crashes must never turn this path into accept. An atomic ruleset
transaction either installs the complete policy or refuses launch. Keep the
base-chain default drop as defense in depth. NFLOG group logging, bounded
snaplen, batching and token-bucket limits are described in the
[nftables manual](https://netfilter.org/projects/nftables/manpage.html).

Do not instrument unsolicited `input` traffic and report it as an agent attempt.
The `forward` chain and failures before this output rule are also outside slice
1 coverage. Existing HTTP(S) proxy denials keep their existing source identity;
do not fabricate an NFLOG event for them or deduplicate unrelated observations
solely by destination. A rejected route or seccomp-denied socket can produce no
NFLOG record even though enforcement worked.

In particular, the current namespace has no general default route. An off-box
direct dial may fail with ENETUNREACH before the output drop rule. NFLOG does not
close that gap. Start the probe with a reachable on-link bridge destination and
a denied port, then separately demonstrate the route-failure case produces no
packet sample. Do not add a route just to make audit collection look complete.
If the required first slice must explain every off-box failed dial, reject this
scope at review and design syscall-level observation instead.

### Receiver and trust boundary

1. The trusted parent allocates a session ID and a separate bounded observation
   spool in its protected audit-state directory, outside the project. The agent
   cannot write that directory. Do not reuse the unbounded sidecar decision TSV
   as a high-volume kernel log.
2. The privileged helper validates the request, path, owner, file type, link
   count and pinned inode before opening that spool with `O_NOFOLLOW`. The
   parent creates it exclusively at mode `0600`; the helper must reject any
   replacement. Accept no agent-controlled alternate output or group identity.
   Path/inode checks must cover ancestor substitution, not only the final path.
3. The helper opens and configures the NFLOG receiver while locked to the
   session network namespace. Do not assume all Go threads joined that
   namespace. Create the socket on that locked thread or a dedicated helper
   process; test its actual namespace membership. Bind group and session
   association from trusted launch state, not from packet text or child input.
4. The root supervisor retains ownership of the receiver for this first slice.
   It already manages the privileged namespace lifecycle. Give neither the
   agent nor the transparent proxy the receiver or spool descriptor. Close-on-
   exec and explicit child descriptor lists are required. Reusing the proxy's
   shared unprivileged UID for an allegedly trusted collector needs an isolation
   proof and is not the initial recommendation.
5. Accept only kernel-origin netlink messages on that bound receiver; validate
   source address, lengths, family, message types, group and attributes. A
   claimed PID in an untrusted message header is insufficient provenance.
   Malformed records produce bounded health information, never arbitrary rows.
6. The parent tails only the pinned spool, validates its versioned records and
   length caps, and assigns its own session ID. Only the parent writes SQLite
   and signs rows. The root helper gets no audit signing key or database handle.

The existing helper request path is not proof that this new spool transport is
safe; implementation needs dedicated path/race tests. Do not rely on arbitrary
file descriptors surviving sudo. A bounded spool works with the current helper
launch shape and keeps this transport separate from agent stdin/stdout.

Only extract protocol, source/destination address, available ports, hook,
interface, kernel timestamp/sequence and trusted collection metadata. Start with
a maximum 128-byte packet prefix in memory to decode headers; never persist raw
packet bytes, credentials, DNS names or payload. Some packets require more
headers than that, including IPv6 extension chains/fragments; record unknown
ports instead of guessing. A prefix may transiently contain payload, so bound
its lifetime and exclude it from errors/crash diagnostics. Do not infer PID,
process identity, hostname or application intent from a packet tuple.

The [NFLOG API documentation](https://netfilter.org/projects/libnetfilter_log/doxygen/html/)
and [kernel message definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_log.h)
inform the receiver prototype. Namespace isolation, delivery under load and
available metadata remain experimental acceptance gates for this implementation.

### Signed representation and compatibility

Reuse `network_blocked`, category `network`, `blocked=true` for each accepted
packet sample. Put structured, versioned JSON in the already-signed `detail`
string; do not change historical hashes or the database schema. For example:

```json
{
  "schema": "nocklock-kernel-denial/v1",
  "backend": "linux-nft-nflog",
  "kind": "sample",
  "unit": "packet",
  "hook": "output",
  "protocol": "udp",
  "destination": "192.0.2.1",
  "destination_port": 4444,
  "coverage": "sampled",
  "collection_sequence": 1
}
```

Add an additive event type `network_observation_state`, category `network`,
`blocked=false`, for startup/health/final-summary records. Its detail has a
distinct versioned schema and includes backend, instrumented hooks, observation
status, configured limits, accepted sample count and final drop-packet counter
when available. Explicitly represent unknown counters as null, not zero.

Consumer work is part of the implementation: CLI logs, exports, forwarding and
stats must understand the state type. A state record must not be counted as
allowed traffic merely because `blocked=false`, and a summary must not inflate
blocked-operation counts. Existing `network_blocked` counts become counts of
observations of different units; displays and downstream consumers must label
or separate proxy decisions and packet samples. Do not change existing receipt
verification semantics or silently reinterpret historical rows. Coordinate
NockGuard display changes separately; no NockGuard code belongs in this design
PR. If consumers cannot support these distinctions, do not enable the feature.

A signed startup record declares `coverage=sampled`, even before any loss is
detected. A final record reports `complete_summary`, `incomplete` or `unknown`
for counter/collector closeout separately from sampling. Never reuse AUTHENTIC
as an observation-completeness status. A clean session with zero drops should
have state records and zero new blocked rows.

### Bounded resource policy

Initial limits below are **proposed benchmark targets**, not measured guarantees:

| Resource | Proposed bound and exhaustion behavior |
| --- | --- |
| Kernel NFLOG generation | 25 packets/second, burst 50 per session; overflow still drops |
| Receive buffers | Explicit cap, initially 256 KiB; validate effective kernel cap |
| Decoded sample | At most 1 KiB; reject larger/malformed input |
| Persisted samples | At most 500 per session; then count without adding sample rows |
| Lifecycle records | At most four per session, including one reserved final summary; coalesce repeated errors |
| Spool | At most 1 MiB including reserved closeout space; no unbounded append or overwrite of unseen samples |
| Work queues | Fixed capacity, initially 128 records; full queue marks observation loss |
| Collector drain at close | Deadline, initially two seconds; mark incomplete if not drained |

Cap high-cardinality state as well as rows. Slice 1 needs no unbounded tuple map
and should not retain per-destination aggregates. Sanitize and bound all string
fields. Stop requesting NFLOG samples after the lifetime sample budget where it
is safe to disable only the observation rule; the denial counter and drop must
remain. Otherwise continue draining and discarding bounded messages until exit.
Rate limiting bounds parser work, not the cost of all attacker-generated
packets. Measure CPU and memory against the same enforcement without telemetry.

Track total output-drop packets via the nft counter, received samples,
persisted samples, user-space suppression, known sequence gaps/ENOBUFS and
whether final counters were obtained. If useful, add a second counter on the
rate-limited log path. It measures log-rule matches, not successful delivery.
Do not invent an exact lost-event count from incomplete sequence data. Counter
differences explain sampling only after a quiescent snapshot; otherwise label
the comparison incomplete.

These per-session limits bound this sensor's contribution, not the entire
existing SQLite database, WAL, proxy decision file or total number of sessions.
Measure actual database/WAL growth; payload limits are not exact disk limits.
A caller can still create many sessions, so deployment-wide quota/retention is
a separate operational policy. Do not automatically prune or discard signed
history to make space. Never claim this slice solves every audit-disk flood.

### Failure and shutdown policy

Before launch, a selected observation mode requires a usable receiver, writable
bounded spool, installed drop policy and a committed signed startup record.
Failure refuses the run; do not silently downgrade its evidence capability.
This requirement applies only when the new observation mode is selected;
existing enforcement-only configurations remain backward compatible.

During execution, rate limiting and a full sample budget are expected sampled
coverage. A fatal receiver/spool failure ends the session with an actionable
error and a bounded state record where possible; never loosen enforcement. If
SQLite/signing cannot commit an accepted row or health record, stop the agent
and report audit failure on stderr/nonzero exit. A disk-full condition cannot
guarantee its own durable error row, and the design must say so. No absence of a
row proves absence of a denial.

On normal close, stop the session's agent and remaining descendants, quiesce
new packet producers, obtain the final counter and drain queued observations
within the deadline. Keep namespace/receiver/spool alive through that sequence.
The parent commits the samples and summary before closing the session's signed
chain. Then tear down the privileged resources. If quiescence, counters or
draining cannot be established, record incomplete closeout. Fatal crashes or
SIGKILL may leave no summary; readers must recognize that absence as incomplete.
Watchdog cleanup must preserve enforcement until the child is dead even when
the parent/collector disappears.

## Why seccomp USER_NOTIF is a separate project

The current EPERM path can remain a small, synchronous kernel decision. A host
can configure audit emission for ERRNO actions, but that is a host audit-policy
integration, not a new callback in the existing filter. Establish exact kernel,
audit permissions and delivery configuration before claiming it observable.

USER_NOTIF would replace selected ERRNO filter branches with a listener-mediated
decision. Adding a notification filter beside an existing higher-precedence
ERRNO rule cannot observe that rule. `SECCOMP_RET_LOG` is also unsuitable as a
replacement denial: it permits execution after logging. Action ordering and
logging behavior are documented in the
[seccomp syscall reference](https://man7.org/linux/man-pages/man2/seccomp.2.html).

For a future strictly deny-only notification experiment, notify only the narrow
numeric socket argument cases, respond with the original EPERM, and never use
CONTINUE or dereference attacker pointers. Listener absence can yield ENOSYS,
and a nonresponsive listener can block the calling task. A startup handshake,
watchdog and kill-before-listener-close protocol become part of the boundary.
This requires compatibility and adversarial testing, not simply adding a log
statement. The [notification reference](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
explains listener behavior and cautions about policy uses and continuation races.

Even this narrow experiment covers only the socket-family calls selected by the
filter, not all network attempts. Its synchronous signing latency, multithreaded
request backlog, task cancellation, FD ownership, denial errno and supervisor
failure need an independent design. Keep ERRNO in slice 1.

## macOS follow-up feasibility

The generated Seatbelt profile already requests session-tagged network and
resolver-service denial messages. The file-denial collector launches
`/usr/bin/log stream` and validates kernel/Sandbox sender provenance plus the
session token before interpreting file operations. Reuse that trust boundary
when investigating network records; child stderr or a process echoing the UUID
is not kernel evidence.

First collect real network-outbound and resolver Mach-denial fixtures on each
supported macOS release under a normal user account. Distinguish socket denial
from resolver-service lookup denial in the schema. Match known operation forms,
preserve unknown destinations, and reject malformed or unrelated-session logs.
Test stream loss, privacy redaction, duplicate suppression, missing messages,
and the exact kernel sender-image check against those OS builds.

Apple documents sandbox logs as a
[diagnostic source for violations](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations).
That does not establish a stable, complete Seatbelt network event API. The
existing successful file-log fixtures do not prove network emission. If the
network fixtures pass, ship bounded best-effort observations with their own
coverage label; if they require extra privilege or reliable provenance is
unavailable, leave the feature unavailable. Do not add an admin helper,
EndpointSecurity entitlement or private API just to match Linux telemetry.

## Acceptance gates for implementation

| Gate | Required evidence |
| --- | --- |
| Enforcement unchanged | Same allowed proxy traffic succeeds with collection on/off; controlled direct TCP/UDP traffic hits the drop counter and cannot reach a reachable receiver |
| Observation provenance | Kernel receiver proof; wrong namespace/group/session and forged user-space netlink or child text cannot produce a signed kernel row |
| Counter meaning | One controlled datagram yields the expected output-drop counter/sample; TCP retransmits remain multiple packets, never renamed attempts |
| Gaps are visible | Queue overflow, rate suppression, lifetime cap, malformed records and lost closeout yield accurate sampled/incomplete states |
| Failures stay closed | Kill receiver/helper/parent, fill spool/disk, lock DB and break signer; no policy accept or silent success |
| Bounded load | Sustained and burst UDP/TCP floods plus high-cardinality destinations stay within the stated queues/rows/spool; benchmark p50/p95/p99 overhead and DB/WAL bytes |
| Session isolation | Concurrent sessions cannot exchange spool data, counters or receiver messages; no descriptor inherited by agent/proxy; stale namespace/spool reuse rejected |
| Receipt correctness | Explicit-key `verify --audit` yields AUTHENTIC after accepted rows; tampered sample/state fails; authentic incomplete sessions remain labeled incomplete |
| Consumer correctness | State records count as neither allowed nor blocked operations; packet samples are distinguished from proxy decisions in logs, exports and forwarded views |
| Teardown | Descendants stop before final counter; queued rows precede summary/session close; forced timeout is incomplete and resources are reclaimed |

Use a controlled reachable endpoint and unfenced positive control. An external
host timeout is not a proof of blocking. Include IPv4, IPv6/extension headers,
fragments and unsupported packet forms without requiring every form to produce
a populated port. Measure with collection disabled and enabled on the same host.

The implementation sequence is: receiver/provenance spike, atomic rule/counter
change, bounded spool and signed schemas, failure lifecycle, consumer handling,
then hostile-load and clean-machine evidence. Review exact heads before enabling
the feature. macOS collection and seccomp mediation remain separate follow-ups.
