# Linux Network Egress Enforcement — Design

**Date:** 2026-07-30
**Status:** Proposed (Mira, product lead) — problem confirmed, mechanism recommended. **Phase 0 STARTED (2026-08-03): VPS target probed with receipts — unprivileged-clean netns RULED OUT on the tested target (AppArmor indicated; toggle test pending), privileged-helper setup path CONFIRMED viable. See "Phase 0 results — VPS probe (2026-08-03)" below.**
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
   (Ubuntu VPS, macOS-is-out-of-scope, CI runners). If unprivileged netns is
   unavailable, B needs a privileged helper (`CAP_NET_ADMIN`) or a setuid path —
   a materially bigger ask that changes the recommendation's cost.
   **VPS VERDICT (2026-08-03, receipted — see "Phase 0 results" below): unprivileged
   userns+netns is BLOCKED (symptom reproduced). **[Narrowed 2026-08-06 by the
   Amendment at the end of "Phase 0 results" below: the repeatable egress-probe (PR #70)
   shows the gated operation is specifically the `uid_map` root-mapping write, NOT
   user-namespace or network-namespace *creation* itself. The unprivileged-clean *track*
   remains out on this VPS; only the mechanism of the block is narrowed.]** The classic `unprivileged_userns_clone`
   sysctl is `=1`/permissive, so it is reproducibly NOT the blocker; the indicated cause
   is the Ubuntu 24.04+/26.04 AppArmor gate `apparmor_restrict_unprivileged_userns=1`
   (documented signature, not toggle-isolated). The privileged-helper **setup path** is
   CONFIRMED viable on the VPS — see "Phase 0 results" below for the receipts and what's
   still open. So on Ubuntu 26.04, B is the privileged-helper track, not
   unprivileged-clean. CI-runner kernels still to probe.**
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

## Phase 0 results — VPS probe (2026-08-03)

First real target probed (the Debian-family dev VPS is now **Ubuntu 26.04 LTS**,
kernel 7.0.0-27-generic). Findings are receipted (probe run inline, not modelled):

| Probe | Result | Meaning |
|---|---|---|
| `unprivileged_userns_clone` | `1` (permissive) | classic sysctl is NOT the blocker |
| `apparmor_restrict_unprivileged_userns` | `1` | restrictive — matches the Ubuntu 24.04+ gate signature (indicated cause) |
| `unshare --user --map-root-user` | FAIL — `uid_map: Operation not permitted` | unpriv userns denied |
| `unshare --user --net --map-root-user` | FAIL (same) | **unpriv netns via userns is out (Q1 = no)** — *narrowed 2026-08-06: the gated operation is the `uid_map` root-mapping write, not netns creation itself; see Amendment below* |
| `nft` present | v1.1.6 + `nft_tproxy` module available | tproxy mechanism (Q2) is on this kernel |
| `sudo -n` (NOPASSWD) | yes | privileged-helper path is reachable |
| `sudo ip netns add` + `modprobe nft_tproxy` + in-netns default-drop `nft` (via `ip netns exec`) | all OK | **privileged setup path is viable** — end-to-end `tproxy` traffic interception and the Q6 post-drop mutation test remain open |
| Q6 pre-check: `capsh --drop=cap_net_admin` then `nft add table` | rejected (preliminary) | bypass-resistance premise holds; needs the real acceptance test |

**Cause — symptom reproduced, mechanism indicated (not toggle-proven):** what is
directly observed is that the `uid_map` write is denied *even though*
`unprivileged_userns_clone=1` — so the classic sysctl is **reproducibly ruled out**
as the blocker. The positive attribution to AppArmor's
`apparmor_restrict_unprivileged_userns=1` (standard on Ubuntu 24.04+; an unconfined
process has no profile granting the `userns` capability) is the documented cause of
this exact signature, but I did **not** isolate it by toggling the sysctl (that would
mutate a live security control on the VPS). Treat it as the indicated cause pending a
toggle test in the committed probe, not a proven one.

**Decision this unblocks:** on Ubuntu 26.04, **B ships on the privileged-helper
track** — a parent helper creates + configures the netns and `nftables` policy,
then `exec`s the child with net-admin dropped from every set. Unprivileged-clean B
(no helper) is not available here. Two live options for the helper, to settle in
Phase 1: (a) setuid/sudo helper (setup path confirmed working now — see the
capability contract below for how to scope its privileges), or (b) ship a
NockLock AppArmor profile that grants `userns` so the unprivileged path
reopens — heavier, distro-specific, deferred. (a) is the Phase 1 default.

**Helper capability contract:** the VPS probe used the `sudo`/NOPASSWD path,
which runs the helper as root. A setuid-root `nocklock-egress-helper` gets
that same full set, so it is no more minimal than `sudo` — the least-privilege
refinement of option (a) is a non-setuid binary with **file capabilities**
(`setcap`) granting only what it needs: `CAP_SYS_ADMIN` to create the network
namespace (`unshare`/`clone` with `CLONE_NEWNET` requires this, not
`CAP_NET_ADMIN`), `CAP_NET_ADMIN` to configure the namespace's interfaces,
routes, and `nftables` rules, and `CAP_SYS_MODULE` only if the helper itself
loads `nft_tproxy` via `modprobe` (module loading is a global kernel action,
not namespace-scoped, so this capability cannot be dropped into the
namespace). `CAP_SYS_ADMIN` is near-root-equivalent on its own, so `setcap`
narrows *identity* (no full root shell) more than it narrows *capability*.
Real least privilege still means dropping all three once setup completes,
same as the child's post-drop requirement above.

**Still open (not yet probed):** CI-runner kernels (GitHub-hosted + the self-hosted
Mac is out of scope for Linux netns), and the full Q6 acceptance test (post-drop
child provably cannot flush `nftables`/routes/interfaces) — both belong in the
committed Phase 0 probe program, which is the next build increment (see Phasing).

### Amendment 2026-08-06 — uid-map-write-gate narrows the Phase 0 finding

The repeatable `nocklock egress-probe` (PR #70, in review — not yet on `main`)
narrows the earlier one-off Phase 0 result. The "unprivileged netns is out"
statement above — the Q1 VPS VERDICT and the `unshare --user --net --map-root-user`
table row — was **too broad** as a mechanism claim; it is superseded/narrowed by the
finding here. The *track* conclusion is unchanged: unprivileged-clean is out on this
VPS, so B ships on the privileged-helper track.

**Finding — the gate is the `uid_map` root-mapping write, not namespace creation
(from the repeatable egress-probe, PR #70):** on the dev VPS, a bare unmapped
`unshare --user --net` (no root-mapping `uid_map` write) **succeeds**; the operation
actually gated is specifically the `uid_map` **root-mapping write**. So the blocker is
narrower than "userns/netns creation is denied" — user-namespace and
network-namespace *creation* itself is not blocked. The cause remains *indicated*, not
toggle-proven: the documented signature points to
`apparmor_restrict_unprivileged_userns=1` (standard on Ubuntu 24.04+), but it has not
been isolated by a toggle test. The probe encodes exactly this as its
`uid-map-write-gate` cause (evidence qualifier `indicated`).

**Design decision (Q6 minimum-privilege direction) — DECIDED by owner:** Phase 1's
child does **NOT** need to be root-in-namespace. The privileged helper — holding
`CAP_SYS_ADMIN` to create the netns and `CAP_NET_ADMIN` to configure it (the split
already fixed in "Helper capability contract" above) — creates and configures the
network namespace, then hands a **non-root child with net-admin dropped from every
set** into it. Because that child never performs the gated `uid_map` root-mapping
write, the AppArmor restriction on unprivileged uid-map is **not on the child's path**.
This scopes the helper to setup-only and keeps the child unprivileged. It also means
`apparmor_restrict_unprivileged_userns` being on does **not** by itself block the
privileged-helper track — which answers the second half of Q6 ("does the
minimum-privilege split survive the Q1 unprivileged answer?"): yes for the track's
*direction*. Q6's acceptance test stays open (see below); only its minimum-privilege
direction is decided here.

**Still open — restated for this amendment's scope, NOT resolved** (these remain the
items in "Still open (not yet probed)" above; the amendment decides the Q6 *direction*
only):
- **(a) Prove the AppArmor cause** via a toggle test — upgrade *indicated* → *proven*
  (still pending, per the status line and the Cause block above).
- **(b) CI-runner kernel coverage for Q1** — run the now-repeatable `egress-probe` on
  `ubuntu-latest` once PR #70 merges.
- **(c) The Q6 acceptance test** — that the post-cap-drop child provably cannot mutate
  `nftables`/routes/interfaces (Q6's acceptance bar stays open).

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

Phase 0 is a self-contained probe, not a feature build. #67 (`doctor` surface) has
landed and the **VPS feasibility leg of Phase 0 is done** (2026-08-03, above):
unprivileged-clean is out on Ubuntu 26.04, the privileged-helper setup path is
confirmed viable (see "Phase 0 results" above for what's still open). The next
increment on this track is committing that probe as a repeatable `nocklock`
tool — codifying the VPS runs plus
the Q6 acceptance test and the protocol-matrix egress test — so the remaining fleet
kernels (CI runners) are probed the same way before Phase 1 locks the helper design.

### Amendment 2026-08-17 — CI activation: Q1 CI-runner coverage + the Q6 bar now execute

The `.github/workflows/network-egress.yml` workflow wires two of the amendment's
"still open" items into CI, so both are measured on every push/PR rather than
living as a one-off VPS run and a never-executed test:

- **(b) CI-runner kernel coverage for Q1 — WIRED.** The `egress-probe` job runs
  the merged repeatable probe (#70) on `ubuntu-latest`, **twice**: once on the
  bare runner image and once after `apt-get install nftables iproute2`. The bare
  run reports `track=blocked` *only because `nft` is not preinstalled* — recorded
  deliberately so "the image doesn't ship nftables" is never conflated with "this
  kernel cannot host the fence." The provisioned run is the real Q1 receipt for
  the GitHub-hosted kernel; both JSON reports are uploaded as an artifact and the
  `track`/`nft`/userns-netns/cause values are surfaced in the job summary. The
  probe always exits 0 on completion, so this job is a *receipt*, not a gate.
  **Verdict values are folded in below once the first CI run on the introducing
  PR is green — wiring is not a receipt.**
- **(c) Q6 acceptance test — now ACTUALLY EXECUTES.** #74's post-drop mutation
  test is root-gated and self-skips on the default `go test ./...` path, so until
  now it has never run anywhere (a skip is not a pass). The `q6-acceptance` job
  runs it as root with `NOCKLOCK_Q6_REQUIRE=1`, which turns the normally-green
  non-root/tool-missing skips into HARD failures. This is the first venue where
  Candidate B's bypass-resistance bar — capped child provably cannot flush
  `nftables`/routes/interfaces, with the privileged-parent positive control —
  is a receipted gate. It should be added to the branch's required checks so a
  regression blocks merge.

Item **(a)** (prove the AppArmor cause by toggling `apparmor_restrict_unprivileged_userns`)
is unchanged — it mutates a live security control and stays out of CI.

**First-run receipt — (b) Q1 CI-runner coverage (PR #76, egress-probe job, 2026-08-17, receipted):**
The GitHub-hosted `ubuntu-latest` runner **independently reproduces the dev VPS's
Q1 finding on a second, unrelated kernel** — the privileged-helper track is not a
VPS artifact.

| Check | ubuntu-latest (6.17.0-1022-azure, Ubuntu 24.04.4) | dev VPS (Ubuntu 26.04) |
|---|---|---|
| `unprivileged_userns_clone` | `1` (permissive — ruled out) | `1` (same) |
| `apparmor_restrict_unprivileged_userns` | `1` | `1` (same) |
| `unshare --user --net --map-root-user` | **blocked** | blocked (same) |
| `unshare --user --net` (unmapped) | **permitted** | permitted (same) |
| cause | `uid-map-write-gate` (indicated) | uid-map-write-gate (same) |
| `nft` / `nft_tproxy` | available / available | available / available |
| `sudo -n` | available | available |
| **track** | **`privileged-helper`** | `privileged-helper` (same) |

So on both Ubuntu 24.04+ kernels probed, unprivileged-clean B is out for the same
narrow reason (the `uid_map` root-mapping write is gated, AppArmor-indicated), and
the privileged-helper track is reachable (sudo + nft + tproxy present). Item (b) is
**closed** for the GitHub-hosted CI kernel; the AppArmor cause remains *indicated*,
not toggle-proven (item (a), still out of CI). Per-run JSON receipts (bare +
provisioned) are attached to each `egress-probe` job as the `egress-probe-results`
artifact.

**Receipt — (c) Q6 acceptance test PASSES (PR #76, q6-acceptance job, 2026-08-17,
first execution ever):** #74's test is root-gated and had never run anywhere until
this job ran it as root with `NOCKLOCK_Q6_REQUIRE=1`. On `ubuntu-24.04` it PASSED —
Candidate B's bypass-resistance premise is now receipted, not merely asserted:

- **`TestQ6_CappedChildCannotMutate`** — the child in the namespace with
  `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` dropped from every set was DENIED (EPERM) on all
  four fence mutations: `nft add table` (*Operation not permitted*), `nft flush
  ruleset` — the canonical fence-rewrite attack — (*Operation not permitted*),
  `ip route add` (RTNETLINK *Operation not permitted*), and `ip link set up`
  (RTNETLINK *Operation not permitted*).
- **`TestQ6_PrivilegedParentCanMutate_Control`** — the privileged parent performed
  the same four ops in the same namespace and each SUCCEEDED, proving the child's
  denials are caused by the capability drop, not by broken setup.

So a capped child provably cannot flush the `nftables`/routes/interfaces the fence
depends on, and the bounding-set drop that makes it hold across `execve` is
actually exercised. This closes item (c)'s acceptance bar as a receipted CI gate.

_(CI note: GitHub's `actions/setup-go` download was intermittently rate-limited
(429→503) during this window, so on any single run one of the two jobs may fail in
"Set up job" before Go installs — an infra flake, not a job-logic failure. Both
jobs passed green across runs 32042112358 (egress-probe) and 32042268453 (Q6); a
re-run clears a setup-go flake.)_

### Amendment 2026-08-24 — Q6 capability model DECIDED (unblocks Phase 1)

Open question 6 (capability model) was the last *design* gate on Phase 1 — the Q6
acceptance *bar* is receipted (the capped-child-cannot-mutate test passes on CI),
but the *minimum helper privilege and how it is acquired* was undecided. Phase 0's
receipts now settle it. This amendment fixes the ownership split so Phase 1 builds
to a decided design, not an open one.

**Decision — privilege acquisition (v1): `sudo -n`.** The privileged parent helper
is installed root-owned and non-writable by the service user at
`/usr/libexec/nocklock-egress-helper`, and invoked via passwordless
sudo with one of two fixed argument vectors: `check` (non-mutating preflight) or
`setup` (reads the validated setup request from standard input; no command-line
arguments are accepted). Availability MUST be tested with the complete command
`sudo -n /usr/libexec/nocklock-egress-helper check`, not `sudo -n true`. The host
installer owns this constrained sudoers policy (with `nocklock` replaced by the
dedicated service user when applicable):

```sudoers
Cmnd_Alias NOCKLOCK_EGRESS = /usr/libexec/nocklock-egress-helper check, \
                             /usr/libexec/nocklock-egress-helper setup
nocklock ALL = (root) NOPASSWD: NOCKLOCK_EGRESS
```

Phase 0 receipted `sudo -n` (NOPASSWD) available
on BOTH probed kernels (dev VPS Ubuntu 26.04 + `ubuntu-latest` 24.04), so this path
is confirmed reachable and does not depend on the Q1 unprivileged answer (which is
blocked by the AppArmor `uid_map`-write gate on 24.04+). v1 deliberately does NOT
ship a setuid-root or file-capability (`setcap cap_net_admin,cap_sys_admin+ep`)
binary — both are named future alternatives for hosts without NOPASSWD sudo, not v1
scope. Rationale: sudo keeps the privileged surface an auditable, host-controlled
policy decision rather than a persistently-privileged binary in the tree.

**Decision — helper's minimum privilege set.** The helper holds `CAP_NET_ADMIN`
(create/configure the netns veth/loopback, install the default-drop `nftables`
ruleset, add the `fwmark` `ip rule`/route for tproxy) and `CAP_SYS_ADMIN`
(`CLONE_NEWNET`/`setns`; and the mount for the in-namespace DNS stub's resolver
config if bind-mounted). It also holds `CAP_SETPCAP` only long enough to perform
the required `PR_CAPBSET_DROP` operations. `CAP_NET_RAW` is NOT required. These
are held ONLY for the setup window; the helper does not persist.

**Decision — child credential drop (receipted).** Before `execve` of the child, the
helper removes `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and the temporary `CAP_SETPCAP`
from ALL FIVE capability sets — effective, permitted, inheritable, ambient, AND
bounding. It drops the two fence capabilities from the bounding set while
`CAP_SETPCAP` remains effective, drops `CAP_SETPCAP` from the bounding set last,
then clears all three from the live sets. Clearing the bounding set alone only
blocks *future* regains across `exec`; the live sets must already be clear. The Q6
CI gate directly checks all five sets after the drop and before `execve`, then
exercises the resulting credential:
`TestQ6_CappedChildCannotMutate` proves the post-drop child is denied (EPERM) on
`nft add table`, `nft flush ruleset`, `ip route add`, and `ip link set up`, while
`TestQ6_PrivilegedParentCanMutate_Control` proves the parent can — so the denials
are caused by the drop, not broken setup. Q6 IS the acceptance bar for this
decision; any Phase 1 change to the credential model must keep that gate green.

**Decision — fail-closed on privilege.** If the helper cannot acquire privilege
(no NOPASSWD sudo) OR cannot fully clear the child's five sets, it MUST refuse to
`exec` the child. There is no advisory/degraded network fallback — the enforcement
boundary is not optional (same posture as the fs/syscall fences). The existing
env-`HTTP_PROXY` layer stays a convenience on top of this floor, never the boundary.

**Independence from Q1/Q7.** This capability model is the privileged-helper track
and is orthogonal to Q1 (unprivileged userns, blocked — irrelevant here) and to Q7
(QUIC→TCP fallback, the remaining Phase-0 exit criterion). The Phase 1 *foundation*
increment below — netns + default-drop-all base + cap-dropped child — denies QUIC
by default and therefore does not depend on Q7; Q7 gates only the later increment
that adds the selective HTTP(S)/DNS *allowance* on top of the default-drop floor.

**Phase 1 increment ordering (unblocked by this decision).**
1. **Foundation (Q7-independent, ships first):** privileged helper creates the
   netns, applies the default-drop `nftables` base over IPv4+IPv6 across all
   transports, and `exec`s the child with net-admin/sys-admin dropped from all five
   sets — reusing the receipted Q6 cap-drop harness. This is the kernel-enforced
   *hardened (no-network)* floor. Root-gated acceptance tests run in CI beside Q6.
2. **Transparent allowlist (gated on Q7):** tproxy intercept + SNI/Host allowlist +
   in-namespace DNS stub, turning the floor into a selective HTTP(S)+DNS allowlist.
3. **Compose + README (Phase 2):** collapse the env-proxy to a convenience layer;
   update the threat model to the working+bypass-resistant allowlist.
