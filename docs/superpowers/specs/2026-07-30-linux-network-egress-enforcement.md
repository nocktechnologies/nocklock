# Linux Network Egress Enforcement — Design

**Date:** 2026-07-30
**Status:** Proposed (Mira, product lead) — problem confirmed, mechanism recommended, Phase 0 gated on a feasibility probe
**Author:** Mira Ashworth
**Tracks:** Making NockLock's headline domain-allowlist feature both *working* and
*bypass-resistant* on Linux. Mirrors the Landlock and seccomp decisions: a
userspace boundary fails open against a determined child; the kernel-enforced
backend is the real fence.

---

## The problem (confirmed, not hypothetical)

NockLock advertises feature #3 as *"routes network traffic through a local proxy
that enforces a domain allowlist."* On Linux, in the hardened default posture,
**that allowlist does not work** — and the two ways it can behave are both wrong
for the stated goal:

1. **Syscall fence ON (the default).** `buildSyscallPolicy`
   (`internal/cli/syscall_wire.go:40`) forces the child to **unix-only sockets**
   whenever the network fence is active (`allow_all = false`). The proxy that
   enforces `network.allow` listens on **TCP** `127.0.0.1:<port>`
   (`internal/fence/network/proxy.go`, `net.Listen("tcp", …)`), which the child
   can no longer reach. The posture collapses to **no IP network at all**: the
   agent reaches *none* of the allowed domains, not a selective subset. This is
   the documented "fail-closed no-network posture" (README §Fences) and is
   asserted by `syscall_wire_test.go` — it is intended, but it means the curated
   allowlist is inert. (`nocklock doctor` now surfaces this footgun — PR #67.)

2. **Syscall fence OFF.** The child keeps `AF_INET` sockets and the proxy
   allowlist functions — but it is now a **userspace boundary**: a child that
   ignores `HTTP_PROXY` and dials an IP directly (raw socket, a non-proxy-aware
   binary, prompt-injected exfil code) bypasses it entirely. The README says as
   much: *"disable [syscall] only if you accept the proxy as a userspace
   boundary."*

**There is no third option today** — no posture that gives a *working, selective*
allowlist that a hostile child cannot bypass. That is the gap this spec closes.

### Why the obvious fix doesn't exist yet

seccomp-BPF can filter `socket(family)` but **cannot** filter
`connect(fd, sockaddr, …)`: classic seccomp-BPF cannot dereference the pointer
argument, so it cannot inspect the destination address. The choice on `AF_INET`
is therefore all-or-nothing — allow every IP or none. You cannot say "AF_INET,
but only to the proxy." That single kernel constraint is the whole reason the
allowlist and bypass-resistance are currently mutually exclusive.

---

## Candidate mechanisms (evaluated against the hostile-child threat model)

NockLock's threat model is a **compromised or prompt-injected agent** — the child
is adversarial, may be multithreaded, and may deliberately race the fence. Any
mechanism that only stops an *honest* child is not a fence.

### A. `SECCOMP_USER_NOTIF` connect-filter — REJECTED

Install `SECCOMP_RET_USER_NOTIF` on `connect()`/`sendto()`; a supervisor reads
the child's `sockaddr` and allows only permitted destinations.

**Fatal flaw: TOCTOU.** The `sockaddr` is a pointer into the child's memory. A
hostile multithreaded child can pass an allowed address, wait for the supervisor
to read+approve it, then rewrite the memory before the kernel copies it in — the
kernel's own seccomp-user-notif documentation warns explicitly against using it
for security decisions on pointer arguments for exactly this reason. Since our
child *is* the adversary, A is unsound. (This is the elegant-looking answer; it
is the wrong one, and worth recording so we don't reach for it again.)

### B. Network namespace + transparent redirect — RECOMMENDED

Run the child in a new **network namespace**; use `nftables` `tproxy` (or
`REDIRECT` + `SO_ORIGINAL_DST`) to force outbound traffic to the proxy's
listener, which recovers the original destination and applies the allowlist by
**SNI** (HTTPS `ClientHello`) and **Host header** (HTTP) — parsing the proxy
already does for the explicit-`CONNECT` path. DNS is forced through an in-namespace
stub that only answers for allowed domains (or through the proxy).

- **Bypass-resistant:** enforcement is in the kernel's packet path, not in any
  env var or library the child could ignore. Raw-socket direct-IP dials are
  redirected too; a connect with no SNI/Host fails closed (matches the existing
  "raw IP blocked" rule).
- **The child must NOT own the namespace's net-admin.** A netns created by the
  *child* via `unshare --map-root-user` grants it `CAP_NET_ADMIN` *inside that
  namespace* — enough to flush the very `nftables`/routes the fence depends on,
  which is total bypass under our hostile-child model. So a **privileged parent
  helper** creates and configures the namespace, then the child is `exec`'d into
  it with `CAP_NET_ADMIN` **removed from every capability set** — effective,
  permitted, inheritable, ambient, **and** bounding (clearing the bounding set
  alone only blocks *future* regains on `exec`; the live sets must already be
  clear). Phase 0 must prove, with the child's *real* post-drop credentials, that
  it cannot mutate `nftables`, routes, or interfaces after setup — a passing
  "child can't rewrite the fence" test is the acceptance bar.
- **All-protocol default-deny, HTTP(S)+DNS the working scope.** The `nftables`
  base policy is **default-drop egress** across every transport and both **IPv4
  and IPv6**. The v1 *working* allowlist is scoped to **HTTP(S) over TCP**
  (SNI/Host-gated at the transparent proxy) plus **DNS via the in-namespace
  stub**. **UDP/QUIC (HTTP-3 on 443) and SCTP are DENIED in v1**, not silently
  passed — a decision, not an open item: denying QUIC is fail-closed and safe
  because clients fall back to HTTP/2 over TCP, which *is* gated. A QUIC-aware
  transparent proxy (SNI-gating over QUIC) is a named future extension, not a v1
  gap. The guarantee is thus a fail-closed egress allowlist — "HTTP(S)+DNS
  allowlisted, every other transport denied" — never "TCP allowlisted, the rest
  open."
- **Composes with NockLock's philosophy:** kernel-enforced, not advisory —
  Landlock for files, seccomp for syscalls, **netns for network**.
- **Cost:** privileged-helper namespace setup + capability drop, all-protocol
  `nftables` policy, transparent-intercept handling in the proxy, and a DNS
  story. More moving parts, but the *correct* architecture.

### C. Proxy on a Unix socket + `LD_PRELOAD` `connect()` shim — REJECTED

Keep unix-only sockets; the proxy listens on a Unix socket; the existing
`LD_PRELOAD` interposer rewrites `AF_INET` connects to it.

**Flaw:** `LD_PRELOAD` is bypassable by static binaries and any child that clears
`LD_PRELOAD` — the README already disclaims it for the filesystem fence for this
exact reason. It cannot be the *enforcement* layer for a hostile child, only a
convenience/logging layer. Same verdict the fs fence already reached (Landlock
over LD_PRELOAD).

---

## Recommendation

**Adopt B (network namespace + transparent redirect).** It is the only candidate
that is bypass-resistant against a hostile child (A is TOCTOU-unsound; C is
`LD_PRELOAD`-bypassable), and it is the direct analogue of the kernel-enforced
choice we already made for the filesystem and syscall fences. Keep the existing
env-`HTTP_PROXY` path as a convenience/compatibility layer *on top of* the netns
floor — never as the enforcement boundary.

Until B ships, the honest posture is the current one, now made legible by the
`doctor` warning (PR #67): hardened = no-network; working-allowlist = userspace
boundary. We do not claim a selective bypass-resistant allowlist we don't have.

## Open questions (gated before any build)

1. **Unprivileged userns+netns feasibility — the make-or-break probe.** On the
   dev VPS, `unprivileged_userns_clone=1` and `max_user_namespaces=56182`, yet
   `unshare --user --net --map-root-user` **failed** (`uid_map` write: operation
   not permitted). So unprivileged netns creation is **not guaranteed** on target
   hosts. Phase 0 is a standalone probe across the fleet's real kernels/policies
   (Debian VPS, macOS-is-out-of-scope, CI runners). If unprivileged netns is
   unavailable, B needs a privileged helper (`CAP_NET_ADMIN`) or a setuid path —
   a materially bigger ask that changes the recommendation's cost.
2. **Transparent intercept — DECIDED: `nftables tproxy`.** `tproxy` and
   `REDIRECT`+`SO_ORIGINAL_DST` are NOT interchangeable, so Phase 1 locks to one:
   `tproxy` (with `fwmark` + an `ip rule`/`ip route` local-delivery pair). It
   preserves the *original* destination to a non-local target without rewriting
   the packet — `REDIRECT` DNATs to the local proxy and recovers the intended dst
   only via `SO_ORIGINAL_DST`, which is loopback-scoped and loses IPv6/edge cases.
   `REDIRECT` is rejected for Phase 1 (revisit only if a target kernel lacks
   `tproxy`). Phase 0 confirms `tproxy` on the target kernels; the intercept
   contract (fwmark value, rule/route, proxy `IP_TRANSPARENT` socket) is fixed
   before Phase 1.
3. **DNS — explicit path:** the ONLY UDP the base policy permits is DNS (dport 53,
   UDP *and* TCP) redirected to the in-namespace stub resolver, which answers
   only for allowed names and fails closed (NXDOMAIN/refused) for the rest; all
   other outbound UDP is dropped. External resolvers are unreachable — the child
   cannot DNS-exfil past the stub.
4. **Hostname vs IP allowlist under intercept:** SNI + Host parsing (proxy
   already does this for `CONNECT`); raw-IP / no-SNI connects fail closed.
5. **Layering:** keep env-`HTTP_PROXY` as convenience; netns as the enforcement
   floor. Confirm the watchdog/fail-closed semantics compose (proxy death still
   kills the child).
6. **Capability model (load-bearing for bypass-resistance):** the child must not
   hold `CAP_NET_ADMIN` in its own netns, or it rewrites the fence. Decide the
   ownership split — privileged parent helper creates+configures the namespace,
   child `exec`'d in with net-admin dropped from the bounding set. What is the
   minimum privilege the helper needs, and does that survive the Q1 unprivileged
   answer? Phase 0's acceptance test: the post-drop child cannot mutate
   `nftables`/routes/interfaces.
7. **All-protocol egress — DECIDED.** Base policy is default-drop across all
   transports and IPv4+IPv6. v1 working scope = HTTP(S)-over-TCP (SNI/Host-gated)
   + DNS stub; **UDP/QUIC/SCTP are denied** (fail-closed; QUIC clients fall back
   to gated HTTP/2-over-TCP). A QUIC-aware gating proxy is a future extension, not
   a v1 gap. **Phase 0 EXIT CRITERION (not just a sub-question):** deny-QUIC is
   only safe if legitimate clients actually fall back — so Phase 0 must *verify*
   the QUIC→TCP fallback for the real agent runtimes (curl, Node, Python HTTP
   stacks) reaches an allowlisted host after UDP/443 is dropped. If any runtime
   hard-fails instead of falling back, deny-QUIC is revisited before Phase 1 (the
   redirect-or-deny matrix must not pass while a legitimate client cannot connect).

## Phasing

- **Phase 0 (next, cheap):** fleet feasibility probe for Q1 — a one-file program
  that attempts userns+netns+`nftables` on each real target and reports. It also
  exercises two acceptance tests: (a) Q6 — after the helper configures the
  namespace and drops net-admin from all sets, confirm the child cannot flush
  `nftables`/routes/interfaces; (b) a **protocol-matrix egress test with
  protocol-specific outcomes** (a blanket "redirected or denied" would let a
  deny-all build pass, so each row asserts its *specific* outcome):
    - **allowed HTTP(S) over TCP** to an allowlisted host → POSITIVE success
      (connection completes through the proxy); to a non-allowlisted host → 403/deny.
    - **DNS** for an allowed name → resolves via the stub; for a non-allowed name → fails closed.
      **Direct external-resolver bypass** (instrumented UDP *and* TCP queries aimed at an
      off-namespace resolver) → assert no packet reaches the external endpoint and that every
      answer originates only from the in-namespace stub (stub answers alone are not sufficient
      proof; the bypass path must be exercised and shown to fail closed).
    - **direct-IP TCP** (no SNI) → redirected to the transparent proxy and fails closed by being
      **unable to complete / rejected for missing SNI** — assert the connection cannot establish,
      not a packet-level drop (TCP is intercepted, not dropped).
    - **UDP/QUIC (UDP/443), SCTP, raw IP** → explicit DENY (**packet dropped**).
    - **QUIC→TCP fallback** (curl/Node/Python) → still reaches an allowlisted host (Q7 exit criterion).
    - **proxy death mid-session** → child egress fails closed end-to-end (watchdog kills the child).
  Its result decides whether B is unprivileged-clean or needs a privileged helper.
- **Phase 1:** privileged-helper namespace setup with the child's net-admin
  dropped from every set; default-drop `nftables` base over IPv4+IPv6; HTTP(S)
  TCP redirected to the transparent proxy (SNI/Host allowlist, fail-closed on
  no-SNI); DNS stub; UDP/QUIC/SCTP denied per Q7.
- **Phase 2:** collapse the env-proxy path to a convenience layer over the netns
  floor; update the README threat model to claim the working+bypass-resistant
  allowlist we will then actually have.

Phase 0 is a self-contained probe, not a feature build; it is the right next
NockLock increment on this track once the `doctor`-surface PR (#67) lands.
