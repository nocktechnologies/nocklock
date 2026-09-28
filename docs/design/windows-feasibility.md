# NockLock on Windows: what the fence can enforce without admin rights

**Date:** 2026-09-27
**Status:** Feasibility study — for decision, no product code
**Nock:** [#10825](https://cc.nocktechnologies.io/nock/10825/)

Every factual claim below is tagged **SOURCED** (with a Microsoft docs link) or
**UNVERIFIED** (needs a probe on a real Windows box). The UNVERIFIED claims are
repeated with copy-pasteable commands in [Probes](#probes-to-run-on-a-real-windows-box).

---

## Recommendation

**Build the Windows fence on an AppContainer whose capability set is empty, and
give it exactly one hole: a loopback exemption so it can reach NockLock's own
proxy.** An AppContainer holding *no* network capabilities is dropped by WFP's
"Block Outbound Default Rule" on every outbound packet, at the same kernel choke
point Windows uses for UWP isolation. (Empty is the requirement, not merely
"no `internetClient`" — `privateNetworkClientServer` alone still reaches the
intranet.) The free default-drop floor alone already lands Windows **above
macOS** on the egress row — a real kernel deny for every off-box packet,
inherited from WFP at no elevation cost, where macOS carries no network rules at
all. If the loopback exemption can additionally be granted to a zero-capability
container, the proxy becomes reachable too: a re-resolving proxy on a
default-drop floor, the Linux netns model rather than the macOS `HTTP_PROXY`
suggestion.

**One caveat that shapes Phase 1: a loopback exemption is per-AppContainer
identity, not per-port** — it opens *all* of the host's loopback, so the proxy is
*a* reachable socket, not the *only* one, and any other local listener that will
forward off-box is a confused-deputy path around the allowlist. Making the proxy
the sole loopback peer needs the elevated Phase 2 port-scoped WFP filter; Phase 1
ships default-drop-plus-proxy with this caveat stated. The mechanism and evidence
are in [(b)](#b-network-egress-floor).

Whether the exemption reaches loopback *at all* at zero capability is the pivot
of this whole study. It is **UNVERIFIED** and is
[Probe 1](#probe-1-the-pivot--zero-capability-loopback).

The fence decomposes cleanly by what elevation it costs:

| Phase | Needs admin? | What it buys |
|---|---|---|
| **0 (MVP)** | No | Files (AppContainer + per-user ACLs), process tree (job object), `network.allow = []` as a real all-or-nothing floor, audit chain the agent cannot touch — **all gated on [Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself)(b)**, the WMI-token check (see below) |
| **1** | One-time at install, *if [Probe 2](#probe-2-does-the-exemption-need-elevation) says so* | Loopback exemption for a fixed container moniker → proxy reachable (opens *all* host loopback; sole-socket egress is Phase 2), DNS-trick resistance |
| **2** (deferred; mandatory if Probe 1 fails) | One-time, service | WFP provider with persistent filters scoped by package SID → egress floor independent of the proxy, **port-scoped so the proxy is the sole loopback peer**; ETW file-event stream |

Phase 0 ships standalone and is honest on its own — **provided
[Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself)(b)
clears the WMI-token half**. If a `Win32_Process.Create` child runs under the
plain user token instead of the AppContainer token, it is outside the file *and*
network fence entirely (summary row 14), and Phase 0 does not hold; committing to
Phase 0 is gated on that result. Crucially, the loopback
exemption in Phase 1 is keyed to a **container moniker**, and NockLock can pick a
fixed one (`nocklock-fence`) — so even if it turns out to need elevation, it is
genuinely one-time at `nocklock init`, never per-session. That is what lets this
be one recommendation instead of a menu.

**Open design question, to settle in Phase 1, not here.** A *fixed* moniker means
one package SID for every session on the box, so ACEs granted for project A stay
live for a container fenced to project B — and unlike Landlock, which is
process-scoped and ephemeral, package-SID ACEs are persistent mutations of the
user's disk that a crashed `nocklock` leaves behind. Per-project monikers restore
isolation but break the one-time exemption. The likely resolution is a small pool
of pre-exempted monikers registered once at install and leased per session, plus
mandatory ACE cleanup on exit and a single-session lock per project. Phase 0
sizing below includes the cleanup path; the pool design does not belong in a
feasibility study.

### Why not the alternatives

- **LPAC instead of AppContainer.** LPAC needs explicit capabilities even to
  read the registry or use COM (**SOURCED**,
  [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)).
  `AppInit_DLLs` needing admin and being disabled under Secure Boot is
  **UNVERIFIED** background, not load-bearing here. Agent toolchains — git, node, python,
  MSVC — will not survive that. Use a regular AppContainer, which already has
  read/execute on system directories.
- **An LD_PRELOAD analog.** There isn't one worth having. `AppInit_DLLs` needs
  admin and is disabled under Secure Boot; Detours-style injection is not a
  security boundary. This has a real consequence for the audit row — see
  [(d)](#d-secret-fence-and-the-audit-chain).
- **A kernel minifilter driver.** Requires a signed driver and elevated install.
  Out of scope; it is what Phase 2 stops short of.
- **Job objects + a minifilter, as [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
  currently advertises.** That line ("Windows filesystem fence implementation
  (job objects, minifilter)") predates this study and should be updated if this
  lands. Job objects are in the design — but for the *process tree*, not files;
  they carry no path-level access control. A minifilter is the elevated
  driver option rejected above. The file fence belongs on the AppContainer token
  and DACLs, which is both stronger and free of elevation.
  [ADR-002](../../.claude/decisions/002-fence-approaches.md) chose
  LD_PRELOAD/`DYLD_INSERT_LIBRARIES` and named no Windows mechanism at all; this
  document fills that gap rather than contradicting it.
- **Do nothing: document WSL2 as the supported Windows path.** The null option,
  and it costs zero PR rounds — inside WSL2 the existing Landlock, seccomp and
  netns fences already work, unmodified. Rejected because it does not fence the
  case Kevin asked about: agents driving *native* Windows toolchains (MSVC,
  MSBuild, Windows-only SDKs, PowerShell automation) and repositories on NTFS
  paths that WSL2 reaches only across the 9p/DrvFs boundary. It remains the
  correct interim recommendation to give Windows users *today*, and should be
  said out loud in the docs until Phase 0 ships.

---

## Threat model

NockLock's convention is that the adversary is **a compromised or prompt-injected
agent**, not a well-behaved one: any mechanism that only stops an *honest* child
is not a fence. Two consequences shape everything below.

**Confused-deputy egress is a class, not a curiosity.** On Windows a great deal
of network activity is performed *by a service on the caller's behalf* rather
than by the caller opening a socket — the DNS Client service, BITS, WinHTTP
autoproxy, COM/RPC servers, and handing a URL to the shell so a browser outside
the container fetches it. WFP classifies the *service's* traffic, not ours. Every
one of these is a candidate bypass of a capability-based egress floor, and they
are why [Probe 6](#probe-6-brokered-egress--which-services-answer-for-us) tests
the class rather than DNS alone. This is the single largest open risk in the
design.

**The agent may try to escape the container, not just reach past it.** Nothing in
the AppContainer launch sequence is admin-gated — that is exactly the argument
for why NockLock can use it unelevated, and the same argument is available to the
agent. Whether a process inside a zero-capability container can create a *new*
AppContainer granting itself `internetClient` is
[Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself), and if
the answer is yes the network fence is escapable by construction. Escape need not
even mean re-containering: an out-of-process broker such as WMI
(`Win32_Process.Create`) may spawn a child from the plain user token, outside the
fence entirely — the same Probe 10 inspects that child's token.

---

## Background: the floor on each platform today

Authoritative descriptions live in [`ARCHITECTURE.md`](../../ARCHITECTURE.md) and
[`README.md`](../../README.md); this section only summarises what the Windows
design has to match. Where this doc and those disagree, they win.

| | Linux (today) | macOS (today) | Windows (this study) |
|---|---|---|---|
| Files | Landlock kernel allowlist ([spec](../superpowers/specs/2026-06-11-linux-landlock-fence-design.md)) | Seatbelt / `sandbox-exec` ([spec](../superpowers/specs/2026-06-04-macos-filesystem-fence-design.md)) | AppContainer token + DACLs |
| Egress, default | userspace domain-allowlist proxy | userspace domain-allowlist proxy | *this document* |
| Egress, kernel floor | **opt-in** `--net-fence=netns`: nftables default-drop + transparent proxy, **needs the privileged egress helper** ([spec](../superpowers/specs/2026-07-30-linux-network-egress-enforcement.md)) | **none** — SBPL profile has no network rules | *this document* |
| Syscalls | seccomp allowlist | opt-in `filesystem.hardened` bundle (approximates seccomp; not an allowlist) | — (see [(c)](#c-processsyscall-ish-limits)) |

Two things in that table matter for the Windows argument, and both cut in our favour.

**Nobody gets a kernel egress floor for free.** Linux's netns floor is opt-in and
"needs the privileged egress helper … and fails closed without it"
([README](../../README.md)); `--net-fence=netns` is the only accepted value of an
explicit flag. So "Windows needs a one-time elevated install for selective
egress" is not a Windows tax — it is the same bargain Linux already makes. The
difference is that Windows gets a *blunt* floor (all-or-nothing deny) for free,
which Linux does not.

**macOS is the cautionary tale.** Its SBPL profile carries no network rules, so a
client that ignores `HTTP_PROXY` reaches any address. PR #124 (*open at time of
writing*, `n10813-dns-escape-egress-tests`) adds Go tests demonstrating this as
the contrast case to the Linux netns fence. The Windows design must not
reproduce that shape, and the AppContainer capability model is what makes it
possible not to.

---

## (a) Filesystem confinement for a child process tree

### Mechanism

An AppContainer process token carries a **package SID** plus zero or more
**capability SIDs**, and these are a second, independent principal:

> "AppContainer SIDs (Package and Capability SIDs) are separate from the
> traditional user and group SIDs with both portions of the token being required
> to grant access to a protected resource via the object's discretionary access
> control list (DACL). […] the permitted access is the intersection of that
> granted by the user/group SIDs and AppContainer SIDs"

— **SOURCED**, [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)

That intersection rule is the whole filesystem fence. The agent runs as the
user, so it keeps the user's rights, but *additionally* every object it touches
must grant its package SID. Nothing on a normal disk grants an *ad-hoc* package
SID, so for ordinary user data the default is deny, and NockLock opens holes by
adding one ACE per allowed path — which a non-admin user can do on any path they
own.

**But "deny by default" needs one honest qualifier.** A regular AppContainer
token also carries **ALL APPLICATION PACKAGES** (`S-1-15-2-1`), and Windows
grants that SID read/execute across much of `%SystemRoot%` and `Program Files`
(the cited page: "Regular AppContainers are granted access to certain system
files/directories, common registry keys and COM objects"). That is
simultaneously *why the toolchain runs at all* and a standing **read** hole on
system paths. The fence is therefore deny-by-default for **writes everywhere**
and for **reads of paths that do not already grant ALL APPLICATION PACKAGES** —
which covers `~/.ssh`, `~/.aws`, and other user data, but not the system tree.
LPAC would close it and break the toolchain; that is the trade in
["Why not the alternatives"](#why-not-the-alternatives). Any path NockLock is
asked to protect that happens to carry an ALL APPLICATION PACKAGES ACE needs an
explicit DENY ACE, not merely the absence of a grant. **UNVERIFIED**, extend
[Probe 4](#probe-4-acl-grant-and-the-deny-default).

AppContainers also run at **Low integrity level** (SOURCED, same page), which
limits interaction with *higher*-integrity objects. Note the same page's
qualifier — Low IL is not an independent write block: "if a resource has a
mandatory label of Medium IL or lower and the DACL grants access through to the
AppContainer … then the AppContainer can read, write, or execute." The DACL is
the fence; integrity level is a backstop.

### Does it work without admin?

**Yes.** The full launch sequence is per-user:

1. `DeriveCapabilitySidsFromName` — build capability SIDs.
2. `CreateAppContainerProfile` — creates a **per-user, per-app** profile and
   returns the package SID ([SOURCED](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)).
   On `ERROR_ALREADY_EXISTS`, `DeriveAppContainerSidFromAppContainerName`.
3. `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` —
   "If this attribute is set the new process will be created as an AppContainer
   process" ([SOURCED](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)).
4. `CreateProcess` with `EXTENDED_STARTUPINFO_PRESENT`.

No step documents an elevation requirement, and the profile is explicitly
per-user — though `CreateAppContainerProfile` does document an `E_ACCESSDENIED`
return ("The caller doesn't have permission to create the profile"), which is
precisely what Probe 3 exists to rule out. **UNVERIFIED** only in the trivial sense that nothing states "works
unelevated" in so many words — [Probe 3](#probe-3-appcontainer-launch-unelevated)
settles it in one command.

Granting the project directory is `icacls` with the package SID; the user
already owns the directory, so no elevation. **UNVERIFIED**,
[Probe 4](#probe-4-acl-grant-and-the-deny-default).

### Restricted tokens (and why we skip them)

`CreateRestrictedToken` adds deny-only SIDs, removes privileges, and adds
restricting SIDs (a second access check that must also pass). It needs no
elevation for the self-restricting case:

> "If a process calls **CreateProcessAsUser** using a restricted version of its
> own token, the calling process does not need to have the
> **SE_ASSIGNPRIMARYTOKEN_NAME** privilege."

— **SOURCED**, [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)

We do **not** need it. AppContainer already gives a strictly better file story,
and restricted tokens carry a nasty caveat — MS advises running restricted
applications on a non-default desktop to prevent `SendMessage`/`PostMessage`
attacks (SOURCED, same page). AppContainer's window isolation covers that
already. Skip restricted tokens.

### What breaks

One breakage is **SOURCED** and certain. `CreateAppContainerProfile` redirects
the environment:

```
LOCALAPPDATA=C:\Users\<u>\AppData\Local\Packages\<moniker>\AC
TEMP=C:\Users\<u>\AppData\Local\Packages\<moniker>\AC\Temp
TMP=C:\Users\<u>\AppData\Local\Packages\<moniker>\AC\Temp
```

— **SOURCED**, [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)

That is the answer to "what breaks npm caches." npm, pip, cargo, and Go module
caches key off `LOCALAPPDATA`/`TEMP`; on first run inside the container they all
see an empty cache and re-download. Git's credential helpers and per-user config
discovery key off `USERPROFILE`/`APPDATA`, which are *not* documented as
redirected — so git config is likely found but the credential store likely is
not. NockLock should treat cache directories as first-class `filesystem.allow`
entries and ACL them to the package SID, exactly as it does for the project root.
(The probe launcher below does not rely on any of this: it passes an explicit
environment block that points all five of `TEMP`, `TMP`, `LOCALAPPDATA`, `APPDATA`
and `USERPROFILE` at the AC folder, so inside the probes git finds the host's
per-user config and credential store through none of them.)

Everything else in the "what breaks" list is **UNVERIFIED** and needs the probe
box: whether `git.exe`, `node.exe`, `python.exe`, and MSVC launch at all under a
regular AppContainer; named-pipe and COM use by git credential manager; whether
long-path and symlink operations survive Low IL. [Probe 5](#probe-5-toolchain-survival).

---

## (b) Network egress floor

This is where Windows is unexpectedly strong, and where the one open question lives.

### The mechanism is WFP, and it is already running

AppContainer network isolation is not advisory. It is WFP filters installed by
the Windows Firewall service:

> "The presence of the default block filters ensures network isolation for UWP
> applications. Specifically, it guarantees a network drop for a packet that
> doesn't have the correct capabilities for the resource it's trying to reach."

— **SOURCED**, [Troubleshooting UWP App Connectivity Issues in Windows Firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)

The same page walks a container with **no** capabilities (`<capabilities/>` empty
in the netEvent) being dropped by a filter literally named **"Block Outbound
Default Rule"** with `FWP_ACTION_BLOCK`. The allow path requires capability SID
**`S-1-15-3-1`** (`internetClient`), matched inside a filter owned by provider
`FWPM_PROVIDER_MPSSVC_WSH`. All **SOURCED**, same page.

And from the launch page: "without the *network* capability, an AppContainer
cannot access the network" (**SOURCED**).

So a zero-capability AppContainer has a genuine kernel-enforced default-drop —
no admin required, because we are not *installing* the filters, we are inheriting
filters Windows already installed and selecting which side of them we land on.

### Can we add our own WFP filters instead? No, not without admin.

`FwpmFilterAdd0` requires `FWPM_ACTRL_ADD` on the filter container. The default
security descriptor on the filter engine grants:

- `GENERIC_ALL` to the built-in **Administrators** group
- `GRGWGX` to **network configuration operators**
- `GRGWGX` to five service SIDs (MpsSvc, NapAgent, PolicyAgent, RpcSs, WdiServiceHost)
- **only** `FWPM_ACTRL_OPEN` and `FWPM_ACTRL_CLASSIFY` to **everyone**

— **SOURCED**, [Access control (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)

`OPEN` lets a standard user open a BFE session, nothing more — reading an
object's properties needs `FWPM_ACTRL_READ` and enumeration needs
`FWPM_ACTRL_ENUM`, neither of which is in the Everyone grant. **A standard user
cannot install WFP filters.** That is the hard
boundary, and it is what makes Phase 2 an elevated phase.

### The 2×2 that decides the design

| `internetClient`? | loopback exempt? | Result |
|---|---|---|
| no | no | No network at all. Blunt but real floor. **SOURCED** |
| yes | no | Internet-client egress *and* the proxy is unreachable. Worst cell. **SOURCED** |
| yes | yes | Proxy reachable, but the agent can bypass it. Useless without WFP. **INFERENCE** (chains the capability page to the loopback page; not a single citation) |
| **no** | **yes** | **Off-box egress dropped; all of 127.0.0.1 reachable → the proxy is reachable, but not it alone (Phase 2 closes this).** Reaching loopback at zero capability is **UNVERIFIED** ([Probe 1](#probe-1-the-pivot--zero-capability-loopback)) |

The bottom row is the product. The proxy runs *outside* the container as an
ordinary user process with normal network access; the agent runs *inside* with
no capabilities plus a loopback exemption. Direct off-box egress dies on the
default block filter. The proxy re-resolves hostnames itself, exactly as the
Linux transparent proxy does.

**The exemption is per-identity, not per-port, so it opens all of loopback.**
`CheckNetIsolation` / `NetworkIsolationSetAppContainerConfig` exempt a *container
SID*, with no port argument — so the container can reach every `127.0.0.1`
listener on the box, not only ours. That is a confused-deputy egress channel: any
local dev server, debug endpoint, or service that itself has network access and
will forward a request becomes an off-box path around the proxy's allowlist.
Phase 1 must therefore state this all-loopback caveat rather than claim the proxy
is the sole socket; making the proxy the *only* reachable loopback peer requires
a **port-scoped WFP filter**, the elevated Phase 2 install. Probe 1's last two
steps measure the blast radius (unrelated port reachable? can the agent bind its
own listener?).

Whether the container can reach loopback *at all* at zero capability is the
pivot. The loopback documentation is written around *enabling* loopback for apps
that already have capabilities; nothing states whether the exemption
short-circuits the capability check or is `AND`-ed with it. That is
[Probe 1](#probe-1-the-pivot--zero-capability-loopback).

### Loopback is blocked by default, and the exemption is a dev tool

> "Network communications using an IP loopback address cannot be used for
> interprocess communication (between two different apps) in a Windows Runtime
> app since this is restricted by network isolation."
>
> "**Note** Loopback is permitted only for development purposes. Usage by a
> Windows Runtime app installed outside of Visual Studio is not permitted.
> Further, a Windows Runtime app can use an IP loopback only as the target
> address for a client network request."

— **SOURCED**, [How to enable loopback and troubleshoot network isolation](https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10))

That page is archived (Windows 8 era), so cross-cite the current one, which says
the same thing and gives the commands: "By default, UWP applications aren't
allowed to receive loopback traffic," and to enable outbound,
`CheckNetIsolation.exe LoopbackExempt -a -n=<AppContainer or Package Family>`
(**SOURCED**, [troubleshooting-uwp-firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)).

The programmatic form is `NetworkIsolationSetAppContainerConfig`, documented as
taking "the security identifiers (SIDs) of app containers that are allowed to
send loopback traffic. Used for debugging purposes," shipping in
`Firewallapi.dll` (**SOURCED**,
[NetworkIsolationSetAppContainerConfig](https://learn.microsoft.com/en-us/windows/win32/api/networkisolation/nf-networkisolation-networkisolationsetappcontainerconfig)).

Two honest caveats, both material:

- **Elevation is not documented either way.** The API page is silent; the
  exemption list is machine-wide, which *points* at admin, but that is inference,
  not a source. **UNVERIFIED**, [Probe 2](#probe-2-does-the-exemption-need-elevation).
- **"Development purposes" is a supportability statement, not an enforcement
  one.** We would be relying on a documented-as-dev-only mechanism in a shipping
  security product. That is Risk 1 below.

### The three July DNS tricks

All three collapse onto the same question, and the answer is clean: **the tricks
are defeated because no *off-box* socket opens** — every off-box address dies on
the default block filter, and the proxy re-resolves names itself. The all-loopback
caveat above does not reopen them: a resolver the agent stands up on `127.0.0.1`
still cannot reach a nameserver off-box. (What the caveat *does* leave open is
reaching a *different* local service that already has network — the
confused-deputy class, not these DNS tricks.) That off-box-drop property is
assumed once here rather than repeated per row.

| Trick | Windows outcome |
|---|---|
| Agent runs its own resolver query (UDP/53 or DoH) | **Defeated.** Off-box drop as above — a nameserver is just another off-box address, and a resolver the agent binds on `127.0.0.1` has nowhere to send. Same mechanism as the Linux netns drop; Probe 1 records whether the agent can bind a local listener. |
| Pins `C:\Windows\System32\drivers\etc\hosts` | **Defeated.** That path is under `%SystemRoot%\System32`; an unprivileged agent cannot write it, and inside a Low-IL AppContainer, doubly not. Mirrors how Linux defeats it — by file ownership, the child being non-root — rather than by the egress drop. |
| Changes resolver configuration | **Defeated.** Interface DNS settings are machine state requiring admin (**UNVERIFIED** background); per-process resolver override doesn't exist. |

This is strictly better than macOS today, where all three work because nothing
stops a client from ignoring `HTTP_PROXY`. It matches Linux in outcome, by a
different mechanism.

One genuine unknown: Windows resolves DNS through the **DNS Client service**
(`dnscache`) over RPC, not by the app opening a socket. If `dnscache` answers on
behalf of a zero-capability container, the agent gets name resolution even with
no network — harmless for egress (it still cannot connect) but it would leak
*which* names the agent is interested in, and would mean DNS never reaches our
proxy's allowlist. **UNVERIFIED**, [Probe 6](#probe-6-brokered-egress--which-services-answer-for-us).

---

## (c) Process/syscall-ish limits

### Job objects — solid, no admin

Job objects give the process-tree containment NockLock needs, and nothing in the
API requires elevation:

- "After a process is associated with a job, the association cannot be broken."
- "by default any child processes it creates using **CreateProcess** are also
  associated with the job."
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: "closing the last job object handle
  terminates all associated processes and then destroys the job object itself."
  For a nested job, it kills "all processes associated with the job and its
  child jobs in the hierarchy."
- Breakaway can be *prevented*: "Prevent breakaways of any kind by setting
  neither the JOB_OBJECT_LIMIT_BREAKAWAY_OK nor the
  JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK limit."
- UI restrictions via `JOBOBJECT_BASIC_UI_RESTRICTIONS`; active-process cap and
  memory caps via `JOBOBJECT_BASIC_LIMIT_INFORMATION` /
  `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`; CPU rate control via its own
  `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`.
- Nested jobs since Windows 8.

— all **SOURCED**, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus no-breakaway gives the same
kernel-enforced guarantee NockLock already gets on Linux from `Pdeathsig:
SIGKILL` (`internal/cli/sysproc_linux.go`), and extends it: `Pdeathsig` kills the
direct child, whereas kill-on-close tears down the whole job hierarchy. Parity
plus reach, not a new capability.

**One documented hole, and it may be worse than a job leak.** "Child processes
created using **Win32_Process.Create** are not associated with the job" (SOURCED,
same page), so an agent that shells out via WMI escapes the job's accounting and
kill-on-close. The dangerous part is the token: `Win32_Process.Create` is
serviced by the **WMI provider host out of process**, so the child is spawned by
that broker, *not* forked from the agent — and it does **not** necessarily
inherit the AppContainer token. If the broker launches it with the plain user
token instead, the WMI child is outside the file *and* network fence — a full
escape, not a mere accounting leak. This is **UNVERIFIED**: treat a successful WMI
spawn as a possible full escape until
[Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself)
inspects the spawned process's token. If that token is not an AppContainer token,
**Phase 0 does not hold**, and WMI must be blocked (child-process policy) or the
design reconsidered.

### Process mitigation policies — useful, but not seccomp

Set at creation via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, and "The specified
policy overrides the policies set for the application and the system and cannot
be changed after the child process starts running" (**SOURCED**,
[UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)).
Relevant ones: `WIN32K_SYSTEM_CALL_DISABLE`, `PROHIBIT_DYNAMIC_CODE`,
`BLOCK_NON_MICROSOFT_BINARIES`, `EXTENSION_POINT_DISABLE` (which blocks AppInit
DLLs, Winsock LSPs, and global hooks), `IMAGE_LOAD_NO_REMOTE`,
`IMAGE_LOAD_NO_LOW_LABEL`, and `POLICY2_FSCTL_SYSTEM_CALL_DISABLE` (blocks
`NtFsControlFile`).

Child-process creation can be blocked outright with
`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` = `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`,
and the docs note the synergy with our design directly:

> "this restriction is only effective in sandboxed applications (such as
> AppContainer) which ensure privileged process handles are not accessible to
> the process."

— **SOURCED**, same page. (We would not enable it — a coding agent must spawn
compilers — but it is available for a future exec-deny mode, and it only
works *because* we are in an AppContainer.)

### What is simply not available

**There is no seccomp analog on Windows from user mode.** Arbitrary per-process
NT syscall filtering does not exist without a kernel driver. `SetProcessMitigationPolicy`'s
`ProcessSystemCallDisablePolicy` is the closest-sounding option and it is not
close: it "Disables the ability to use NTUser/GDI functions at the lowest layer"
(**SOURCED**,
[SetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy))
— win32k lockdown only, one subsystem, not a syscall allowlist.

The honest analog set is: win32k lockdown + FSCTL lockdown + child-process policy
+ job active-process limit + binary-signature and dynamic-code policies. That is
a hardening bundle, not a syscall fence — which is exactly how macOS's opt-in
`filesystem.hardened` bundle is treated today, so the table applies one standard
to both.

---

## (d) Secret fence and the audit chain

### Secret fence: portable as-is

The secret fence filters the child's environment block. `CreateProcess` takes an
explicit environment pointer; there is no platform obstacle. The one Windows
nuance is that environment variable names are case-insensitive, so the allowlist
match must be case-folded. No admin. No design change.

### Audit chain: better than Linux and macOS by default

The audit log is a SHA-256 hash chain (v1) with Ed25519 signatures over the rows
and the chain head (v1.1) and an external chain-head anchor (v1.2) — see
[`ARCHITECTURE.md`](../../ARCHITECTURE.md). Its existing answer to a same-uid
tamperer is *not* path rules: the signing key lives outside the database at
`~/.config/nocklock/signing-ed25519.key` "so a db-only attacker cannot sign," and
off-box anchoring makes truncation observable.

Windows converges with the audit-state layout Linux and macOS adopted in
#120/#131: **the audit DB lives outside the project, in the per-user state dir**
(`%LOCALAPPDATA%\nocklock`, the Windows analog of `$XDG_STATE_HOME/nocklock` /
`~/.local/state/nocklock`), written by the unfenced parent. `.nock/` inside the
project holds nothing security-relevant.

This is a correction, not a bonus layer. An earlier draft kept the DB at `.nock/`
in the project and argued the intersection rule alone protected it — the child
holds no package-SID ACE on `.nock/`, so its writes fail. That covers writes
*inside* `.nock/` but not the directory entry itself. Phase 0 grants the package
SID recursive Modify on `filesystem.root` (sizing step 2), and Modify credibly
carries `FILE_DELETE_CHILD` on the granted root — which would let the child
**rename, delete, or replace `.nock/` from the parent** even though `.nock/` has
no writable ACE of its own. Writing into a directory and deleting that directory
via its parent are distinct rights. This delete-via-parent hole is **UNVERIFIED**
and is a new step in [Probe 4](#probe-4-acl-grant-and-the-deny-default); the DB
moves out *either way*, because staking the audit trail on a same-directory ACL
subtlety is the wrong bet whatever the probe returns.

With the DB outside `filesystem.root` the child has **no package-SID ACE on the
audit path and no granted ancestor of it**, so no `FILE_DELETE_CHILD` is
reachable — the same lesson Linux learned in #120, where Landlock checks
`MAKE_REG`/`REMOVE_FILE` against the directory holding the entry, granting the
root's existing children but never the root entry itself. The child's redirected
`LOCALAPPDATA` (section (a)) is a secondary barrier, not the load-bearing one, and
is itself UNVERIFIED when an explicit environment block is passed (summary
row 12). Concretely: keep the audit DB in the per-user state dir, grant the
package SID nothing there, and the child has no path to it — write, rename, or
delete. [Probe 4](#probe-4-acl-grant-and-the-deny-default) settles the
delete-via-parent question.

### Event listener: named pipes, and a gap

For the fence→listener channel, use a **named pipe** with a security descriptor
granting the package SID write access. AF_UNIX exists on Windows 10 1803+, but
Go's support for it on Windows is **UNVERIFIED** and named pipes are the native
idiom. Note that Go's standard library has no named-pipe support — the usual
answer is `github.com/Microsoft/go-winio`, which would be a **new external
dependency and needs discussion** per CLAUDE.md. Flagging, not assuming.

**The real gap:** there is no Windows equivalent of
`internal/fence/fs/interposer`. The file fence is purely token + ACL, enforced by
the kernel with no callback to us — which means **blocked file accesses produce
no events**. The Linux event listener has no Windows sibling. Denials are
correct but silent; the agent sees `ERROR_ACCESS_DENIED` and NockLock logs
nothing.

The candidate fix is the ETW `Microsoft-Windows-Kernel-File` provider, but
subscribing to a kernel provider very likely requires membership in
*Performance Log Users* or admin. **UNVERIFIED**,
[Probe 7](#probe-7-etw-file-events-unelevated). If it needs elevation, file-event
logging is a Phase 2 item and the enforcement table must say so rather than
implying parity.

---

## (e) Packaging

- **Cross-compile.** Go supports `windows/amd64` and `windows/arm64` (also
  `386`, `arm`) — **SOURCED**,
  [Installing Go from source](https://go.dev/doc/install/source). `CGO_ENABLED=0`
  builds cross-compile cleanly from the Linux CI runners. Note the current Linux
  fence ships a **C interposer** (file events, and mapping the advertised
  loopback proxy address onto a Unix socket). It does not cross-compile and has
  no Windows counterpart — the Windows backend is pure Go over Win32, so the
  build stays CGO-free, but see [(d)](#d-secret-fence-and-the-audit-chain): that
  absence costs us the file-event stream.
- **Signing.** **Azure Artifact Signing** — the renamed Trusted Signing (the old
  `azure/trusted-signing/overview` URL 301-redirects to it; the page itself does
  not state the rename, and does not use the word "Authenticode", listing Public
  Trust, Private Trust, VBS enclave, CI policy and test signing instead): "Microsoft fully managed, end-to-end signing solution," with
  "zero-touch certificate lifecycle management inside FIPS 140-3 level 3
  certified HSMs" and content-confidential digest signing where "Your file never
  leaves your endpoint." Basic and Premium SKUs — **SOURCED**,
  [What is Artifact Signing?](https://learn.microsoft.com/en-us/azure/artifact-signing/overview).
  This avoids buying and custodying an EV hardware token. Identity validation
  appears as one of the two resources in an account; that it gates issuance and
  carries lead time is **UNVERIFIED** and worth confirming before planning a
  release date. Unsigned binaries will draw
  SmartScreen warnings, which for a *security* product is a credibility problem,
  so signing is not optional.
- **Install path.** `winget` supports `--scope` to "specify if the installer
  should target user or machine scope" (**SOURCED**,
  [winget install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install)).
  Recommend shipping a **portable/user-scope** package first: scoop and
  user-scope winget both install under the user profile with no elevation, which
  matches the Phase 0 "no admin anywhere" promise. An MSI with a machine-scope
  install is the Phase 1+ vehicle, because that is when there is something
  genuinely worth elevating for. Exact no-admin behaviour of both managers is
  **UNVERIFIED** ([Probe 8](#probe-8-packaging-no-admin)).
- **What needs elevation.** Phase 0: nothing. Phase 1: registering the loopback
  exemption once (pending Probe 2). Phase 2: installing a WFP provider/sublayer
  and a service — unambiguously admin, per the BFE default DACL above.

---

## Proposed per-platform enforcement table

This is the table to publish. Windows column reflects **Phase 1** (one-time
elevated install); Phase 0 differences are noted.

| | Linux | macOS | Windows (proposed) |
|---|---|---|---|
| **Files** | Kernel allowlist (Landlock) | Kernel Seatbelt, writes + credential paths | Kernel token+DACL (AppContainer package SID); deny-by-default, holes are explicit ACEs |
| **Network egress floor** | **Opt-in** netns + nftables default-drop; needs the privileged egress helper | **None** — proxy is an env var, bypassable | WFP default-block on a zero-capability AppContainer; off-box egress dropped, loopback proxy reachable (Phase 1 opens *all* loopback — a port-scoped WFP filter to make the proxy the sole peer is Phase 2). *Phase 0: all-or-nothing deny* |
| **DNS-trick resistance** | Yes, in netns mode — no direct socket; `resolv.conf`/`hosts` root-owned and the child is non-root | **No** — all three tricks work | Yes *pending [Probe 6](#probe-6-brokered-egress--which-services-answer-for-us)* — no direct socket; hosts file needs admin. *Phase 0: n/a (no network at all)* |
| **Syscall limits** | seccomp allowlist | Opt-in `filesystem.hardened` bundle — approximation, not an allowlist | **—** — win32k/FSCTL lockdown + child-process policy only; same category as the macOS bundle |
| **Audit** | SHA-256 chain + Ed25519 signatures + anchor; interposer file events | Same chain, no file events | Same chain; **audit DB in the per-user state dir outside `filesystem.root`** (no package-SID ACE, no granted ancestor — matches Linux/macOS after #120/#131); **no file-event stream** (ETW is Phase 2) |
| **Process tree** | `Setpgid` + `Pdeathsig: SIGKILL` | process group | Job object, kill-on-close across the hierarchy, no breakaway (WMI-spawned children escape the job; whether they also escape the AppContainer token is **UNVERIFIED** — see Probe 10) |

---

## Phased plan and sizing

**Phase 0 — MVP, zero admin (~4–5 PR rounds), gated on [Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself)(b)**

Do not commit to Phase 0 until Probe 10's WMI-token half returns an AppContainer
token for the `Win32_Process.Create` child. If that child runs under the plain
user token, it is outside both the file and the network fence (see
[(c)](#c-processsyscall-ish-limits) and summary row 14) and Phase 0 does not
hold — WMI must be blocked with the child-process policy first, or the design
reconsidered.

1. `internal/fence/windows/appcontainer`: profile create/derive, capability
    construction, `STARTUPINFOEX` launch. (1–2 rounds)
2. ACL application: package-SID ACEs for `filesystem.root`, `filesystem.allow`,
    and the toolchain cache dirs. The audit DB lives in the per-user state dir
    outside `filesystem.root`, never in-project (see
    [(d)](#d-secret-fence-and-the-audit-chain)): granting the root recursive
    Modify would otherwise expose an in-project `.nock/` to delete-via-parent.
    (1 round)
3. Job object: kill-on-close, no breakaway, active-process cap. (1 round)
4. `network.allow = []` wired to "launch with zero capabilities"; secret fence
    env plumbing; `nocklock status` reports the Windows backend honestly. (1 round)

**Phase 1 — selective egress (~2–3 PR rounds)**, gated on Probe 1
5. Fixed moniker + loopback exemption registration at `nocklock init`
    (elevating once if Probe 2 says so); proxy on loopback; fail-closed if the
    exemption is absent. Phase 1 accepts the all-loopback caveat — the exemption
    opens every `127.0.0.1` listener, not just the proxy; the port-scoped WFP
    filter that closes it is Phase 2. (1–2 rounds)
6. CI escape job mirroring PR #124's macOS DNS-escape test, asserting the
    Windows container *cannot* reach a non-allowlisted address directly. (1 round)

**Phase 2 — deferred, elevated (~3–4 PR rounds)** — becomes mandatory if Probe 1 fails or Risk 2 materialises
7. WFP provider + persistent filters scoped by package SID; ETW file events.

Total to a shippable Windows fence at Phase 1 parity: **~6–8 PR rounds**
(Phase 0's 4–5 plus Phase 1's 2–3). Phase 0 is gated on
[Probe 10](#probe-10-container-escape--can-the-agent-re-container-itself)(b) (the
WMI-token escape) and Phase 1 on
[Probe 1](#probe-1-the-pivot--zero-capability-loopback), as noted above.

---

## Risks

1. **Probe 1 comes back negative** — the loopback exemption requires
   `internetClient`, so there is no "proxy only" cell. Then Windows egress
   degrades to macOS parity (env-var proxy, bypassable) unless we go straight to
   Phase 2's elevated WFP provider. *Mitigation:* run Probe 1 before committing
   to Phase 1; if negative, re-scope Phase 1 as the WFP service and be explicit
   that selective egress on Windows costs an elevated install.
2. **Reliance on a documented-as-development-only mechanism.** "Loopback is
   permitted only for development purposes." Microsoft could tighten or remove
   the exemption, and we would have no notice. *Mitigation:* treat Phase 2's WFP
   provider as the durable answer rather than an optional extra — it is also the
   only thing that scopes the exemption to the proxy's port and closes the
   all-loopback confused-deputy channel — and fail closed with a clear error if
   the exemption stops working.
3. **AppContainer breaks the toolchain badly enough that users disable the
   fence.** The `LOCALAPPDATA`/`TEMP` redirection is certain; what it does to
   npm/pip/cargo/MSVC in practice is not. A fence users turn off protects
   nothing. *Mitigation:* Probe 5 early, and budget the cache-directory ACL work
   into Phase 0 rather than discovering it in Phase 1.

4. **The whole floor may be fail-open.** The AppContainer block filters are owned
   by the Windows Firewall service (`FWPM_PROVIDER_MPSSVC_WSH`). If a user
   disables the firewall, the isolation filters may go with it — a fail-open we
   would not detect (**UNVERIFIED**). The same shape applies to a project root on
   exFAT/FAT32 or a network share with no ACL support: the file fence silently
   enforces nothing. *Mitigation:* both want the same fix — check firewall state
   and filesystem ACL support at launch, and refuse to start rather than fence
   nothing. [Probe 9](#probe-9-fail-open-with-the-firewall-off) settles the
   firewall half.

---

## Probes to run on a real Windows box

**The desktop probe shell is elevated** (see
[Elevation on the desktop](#elevation-on-the-desktop--corrected-premise)). Steps
whose answer depends on running *non*-elevated go through the scaffold's
limited-token task, and each probe names which token and which launcher it uses.
Nothing here runs on the Linux build host. **These run on a real Windows desktop,
so no probe may write, delete, rename, or change registry/firewall/machine state
outside its own probe root** — the exceptions are called out below and each is
undone in teardown.

### Probe classification

Every probe is one of two classes. **DESKTOP-SAFE** probes create only inside the
probe root, install nothing, change no machine-wide state except the
AppContainer profiles, the loopback exemption, and the run's limited-token
scheduled task (all torn down by exact name), and can be fully cleaned up by
deleting the probe root and running the global teardown.
**DISPOSABLE-BOX ONLY** probes install software, change machine or user-scope
package state, need a reboot, or cannot be fully torn down — run them in Windows
Sandbox or a throwaway VM, never on the desktop.

"Launcher" below is the scaffold's in-memory `Add-Type` launcher
([`NockProbe.AC`](#launcher-desktop-path-add-type-pinvoke)); "limited task" is the
scaffold's [limited-token runner](#limited-token-runner-desktop); "elevated shell"
is the SSH session itself.

| Probe | Class | Reason | Desktop launcher / token |
|---|---|---|---|
| 1 — zero-capability loopback | DESKTOP-SAFE | Listeners inside probe root; loopback exemption torn down | Launcher from the elevated shell; the `LoopbackExempt -a` step via the **limited task** |
| 2 — exemption elevation | DESKTOP-SAFE | Read-only check of Probe 1's exemption | No launch; scored from Probe 1's `VERDICT(1-exempt)` |
| 3 — AppContainer launch | DESKTOP-SAFE | Transient container process; its own profile torn down | **Entirely in the limited task**, launcher loaded there |
| 4 — ACL grant and deny | DESKTOP-SAFE | ACLs and dirs under probe root | Launcher from the elevated shell |
| 5 (a) — toolchain offline | DESKTOP-SAFE | Runs pre-installed tools; artifacts under probe root | Launcher from the elevated shell |
| 5 (b) — toolchain network-fetch | DISPOSABLE-BOX ONLY | `npm install`, `pip install` write only into the probe root, but exercise the package-manager install path | Not run on the desktop |
| 6 — brokered egress † | DESKTOP-SAFE † | † The `Start-Process "https://…"` step opens the operator's real browser and is DISPOSABLE-BOX ONLY; the remaining steps (nslookup, BITS, Invoke-WebRequest, curl) are desktop-safe | Launcher from the elevated shell |
| 7 — ETW file events ‡ | DESKTOP-SAFE ‡ | ‡ Non-elevated `logman create/stop` only; the "add user to Performance Log Users" retry is DISPOSABLE-BOX ONLY (persistent group membership change) | No launch; the `logman` attempt via the **limited task** |
| 8 — packaging no-admin | DISPOSABLE-BOX ONLY | Installs user-scope packages (winget, scoop) | Not run on the desktop |
| 9 — fail-open firewall | DISPOSABLE-BOX ONLY | Disables the firewall — VM-only | Not run on the desktop (the VM uses the same launcher) |
| 10 — container escape | DESKTOP-SAFE | Container profiles and WMI child torn down | Launcher from the elevated shell *and* inside the container (10(a)); token read by the launcher's `TokenSummary` (10(b)) |
| 11 — named pipe | DESKTOP-SAFE | Pipe server disposed in teardown | Launcher from the elevated shell; pipe server is in-box .NET |
| Box setup | DISPOSABLE-BOX ONLY | Installs Git, Node, Python via winget | — |

### Elevation on the desktop — corrected premise

An earlier revision said "OpenSSH on Windows gives a non-elevated shell." **That
is false on Kevin's desktop.** For a member of the Administrators group, an
OpenSSH logon receives the *full* (unfiltered) token — UAC's split token applies
to interactive logons, not to this one. Mira's read-only precheck on the desktop
(2026-09-27 23:3xZ), verbatim:

```
ps=5.1.26100.9549 | ntobj=False | python=C:\Users\kkwil\AppData\Local\Programs\Python\Python312\python.exe | curl=C:\Windows\system32\curl.exe | elevated=True | loopbackexempt_count=0 | ports_in_use(8899,9999,9998)=0
```

Left uncorrected, `elevated=True` produces three wrong-reason results: Probe 1's
"register the exemption non-elevated first" silently runs elevated, so Probe 2
records "admin not required" for the wrong reason; and Probe 3's
`findstr "High Mandatory"` precondition fails before any container launches.
Probe 7's "non-elevated" `logman create` has the same shape as Probe 1's.

So: steps marked ELEVATED run directly in the SSH shell. Steps that must run
non-elevated — Probe 1's `LoopbackExempt -a`, all of Probe 3, and Probe 7's
`logman` attempt — run through
**one** mechanism, a Scheduled Task registered for the same user with
`-RunLevel Limited` and triggered with `schtasks /Run`, which runs under the
filtered (Medium-IL, Administrators deny-only) token. A positive control proves
that token before anything routed through it is scored. `runas
/trustlevel:0x20000` is not used: this revision could not show it yields a
Medium-IL, non-admin token without a password prompt.

### Desktop BEFORE baseline

The precheck above is the documented BEFORE state for the desktop run:
**0 loopback exemptions, ports 8899/9999/9998 free, NtObjectManager absent,
session elevated.** The scaffold re-measures the first two at the start of the
run, and the global teardown asserts both are restored.

On the desktop run, required tools (python, git, node, curl) must already be
present. The shared scaffold checks with `Get-Command` and records
**SETUP-FAULT** for any probe whose prerequisites are missing — it never
installs. Disposable-box probes run on a throwaway VM where the teardown is
"discard the box."

**Target shell: Windows PowerShell 5.1** (`powershell.exe`, not `pwsh`).
Do not use PS 7-only constructs: trailing `&`, `&&`, `||`, ternary `? :`,
null-coalescing `??`, `-Parallel`, `Split-Path -LeafBase`, or `Clean` blocks.
The launcher's C# is compiled by PS 5.1's `Add-Type`, which uses the .NET
Framework 4.x compiler (C# 5): no `$"…"` interpolation, `?.`, `out var`, or
expression-bodied members. **Neither `pwsh` nor a Windows host was available to
this revision**, so the PowerShell and C# below were hand-checked against PS 5.1
/ C# 5 rules, not executed; the first desktop run is their first execution.

**Shared scaffold — set once at the top of the run.** Everything a probe creates
lives under a fresh, run-unique root (a GUID), and the AppContainer moniker
carries the same suffix so a rerun never inherits a previous run's package-SID
ACEs (the stale-ACE hazard of a fixed moniker in
[the recommendation](#recommendation) applies to the probes too — inherited ACEs
are exactly how a "MUST fail" assertion passes for the wrong reason):

```powershell
$runId     = (New-Guid).ToString('N')   # run-unique; a 1-second timestamp collides on a fast rerun
$probeRoot = Join-Path $env:TEMP "nocklock-probe-$runId"
$moniker   = "nocklock-probe-$runId"
# Fail-if-exists (no -Force, -ErrorAction Stop): never adopt a pre-existing root.
# With a GUID a collision is effectively impossible, which is the point — if it
# happens it is a bug, not a directory to reuse and inherit stale ACEs from.
New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop | Out-Null

# --- Run mode (-Mode Desktop|DisposableBox, default Desktop) ---
# Desktop: NOTHING is downloaded or installed; absent prerequisites = SETUP-FAULT.
# DisposableBox: may Save-Module, bootstrap NuGet, and fetch software.
if (-not $Mode) { $Mode = 'Desktop' }

# --- Tool prerequisites (desktop run) ---
# On the desktop, required tools must already be present. Each probe declares
# which commands it needs; a missing command records SETUP-FAULT for that probe
# and the probe is not scored. Never install on the desktop.
$requiredTools = @{
  'Probe 1'  = @('python','curl.exe')
  'Probe 5a' = @('git','node','python')
  'Probe 5b' = @('git','node','python','npm','pip')   # disposable-box only
  'Probe 6'  = @('curl.exe','nslookup')
  'Probe 10' = @('curl.exe')
}
$setupFaults = @()
$checkedTools = @{}
foreach ($probe in $requiredTools.Keys) {
  foreach ($cmd in $requiredTools[$probe]) {
    if (-not $checkedTools.ContainsKey($cmd)) {
      $loc = Get-Command $cmd -ErrorAction SilentlyContinue
      $checkedTools[$cmd] = $loc
      if ($loc) { "$cmd -> $($loc.Source)" }
    }
    if (-not $checkedTools[$cmd]) {
      $setupFaults += "$probe requires $cmd"
      "SETUP-FAULT: $probe requires $cmd — tool not found, probe not scored"
    }
  }
}

# --- BEFORE baseline (documented desktop precheck: 0 exemptions, ports free) ---
$probePorts = 8899, 9999, 9998
function Get-ExemptCount { @(CheckNetIsolation.exe LoopbackExempt -s | Select-String -Pattern 'S-1-15-2-').Count }
function Test-ExemptListed { [bool](CheckNetIsolation.exe LoopbackExempt -s | Select-String -SimpleMatch $sid) }   # this run's entry, by SID
function Get-BusyPorts   { @(Get-NetTCPConnection -State Listen -LocalPort $probePorts -ErrorAction SilentlyContinue).Count }
$baseExempt = Get-ExemptCount
$basePorts  = Get-BusyPorts
"BEFORE: loopbackexempt_count=$baseExempt ports_in_use(8899,9999,9998)=$basePorts (documented desktop baseline: 0, 0)"
if ($basePorts -ne 0) {
  # A foreign listener on a probe port would answer Probe 1's curls: a wrong-reason pass.
  $setupFaults += 'Probe 1 requires ports 8899/9999/9998 free'
  "SETUP-FAULT: a probe port is already listening — Probe 1 not scored"
}

# --- NtObjectManager: disposable box only, never on the desktop ---
# The scripted steps use the Add-Type launcher below on BOTH boxes. On a throwaway
# VM, NtObjectManager may be fetched into the probe root for interactive
# cross-checks; the desktop run never loads or installs it (precheck: ntobj=False).
if ($Mode -eq 'DisposableBox') {
  Save-Module -Name NtObjectManager -Path (Join-Path $probeRoot 'modules') -Force
  Import-Module (Join-Path $probeRoot 'modules\NtObjectManager')
}

# Denial helper used by every "MUST fail" step. It discriminates the HResult:
# only E_ACCESSDENIED (0x80070005) is a pass; not-found (0x80070002/3) is a
# FAILED probe — that is the exact bug this round fixes.
# HResult of the innermost exception, formatted '0x80070005'. A denial from a .NET
# method call (the launcher, a pipe Connect) arrives wrapped in PowerShell's
# MethodInvocationException, so the outer exception's HResult is the wrong one.
function Get-BaseHResult($ErrorRecord) { '0x{0:X8}' -f $ErrorRecord.Exception.GetBaseException().HResult }

function Assert-AccessDenied {
  param([scriptblock]$Action, [string]$Label)
  # Access-denied from Set-Content/Get-Content is NON-terminating, so it must be
  # forced to terminate or the catch never runs and the helper prints FAIL(no-error)
  # on a real denial. Each call site passes -ErrorAction Stop, which is the
  # guaranteed path regardless of how $ErrorActionPreference scopes into a
  # scriptblock invoked with `&`; this sets the preference too as a backstop.
  $ErrorActionPreference = 'Stop'
  try { & $Action | Out-Null; "FAIL(no-error): $Label" }
  catch [System.UnauthorizedAccessException] { "PASS(denied): $Label" }
  catch {
    $h = Get-BaseHResult $_
    if ($h -eq '0x80070005') { "PASS(denied): $Label" }
    else { "FAIL(wrong-error): $Label -> $($_.Exception.GetBaseException().GetType().FullName) HResult=$h" }
  }
}

# Process-identity helpers. Bare PID cleanup can kill an unrelated process after
# PID reuse; these record and verify PID + StartTime + Path before acting.
function Write-ProcessIdentity {
  param([System.Diagnostics.Process]$Proc, [string]$FilePath)
  $info = '{0}|{1}|{2}' -f $Proc.Id, $Proc.StartTime.ToString('o'), $Proc.Path
  Set-Content -Path $FilePath -Value $info
}
function Stop-VerifiedProcess {
  param([string]$IdentityFile)
  $raw = Get-Content $IdentityFile -ErrorAction SilentlyContinue
  if (-not $raw -or $raw -like 'EXITED:*') { return }
  $parts = $raw -split '\|',3
  # A record without all three fields (a partial write, or a bare PID) cannot be
  # verified. Skip it with a line rather than let [datetime]$null throw and abort the
  # teardown loop before $probeRoot is removed — leftover state is the worse failure.
  if ($parts.Count -lt 3) {
    "TEARDOWN: $IdentityFile holds no verifiable identity — process not stopped"
    return
  }
  $probePid = [int]$parts[0]; $startTime = [datetime]$parts[1]; $path = $parts[2]
  $proc = Get-Process -Id $probePid -ErrorAction SilentlyContinue
  if ($proc -and $proc.StartTime.ToString('o') -eq $startTime.ToString('o') -and $proc.Path -eq $path) {
    Stop-Process -Id $probePid -ErrorAction SilentlyContinue
  }
}
```

**Three things the probe root cannot contain** — all unavoidable, all removed by
exact name in the global teardown, never left behind:

- `CreateAppContainerProfile` (the launcher's `CreateProfile`) materialises
  `%LOCALAPPDATA%\Packages\<moniker>\` and a per-user `AppContainer\Mappings`
  registry key, outside the root. The run-unique (GUID) monikers —
  `nocklock-probe-$runId`, Probe 3's `nocklock-p3-$runId`, Probe 10's
  `agent-escape-$runId` — keep reruns from colliding; teardown deletes each.
- The loopback exemption list is machine-wide; teardown clears the entry.
- The limited-token scheduled task `nocklock-probe-limited-$runId`; teardown
  stops and unregisters it by that exact name. (Task Scheduler's own history log
  may record its runs; that is log content, not configuration, and is left as-is.)

**Getting the scaffold *into* the container.** The launcher starts a *fresh*
process, so none of `$probeRoot`, `$moniker`, `$sid`, `$runId`, `$out`,
or `Assert-AccessDenied` crosses into it — every "from INSIDE the container"
snippet below assumes they have been re-established there. `run-probe.ps1` does this
by writing a bootstrap `_inside.ps1` into `$probeRoot` (which it ACLs to the
package SID, like any other granted path) that re-derives all paths from
`$PSScriptRoot` and re-defines `Get-BaseHResult` and `Assert-AccessDenied`:

```powershell
$probeRoot = $PSScriptRoot
$runId     = (Split-Path -Leaf $probeRoot) -replace '^nocklock-probe-',''
$moniker   = "nocklock-probe-$runId"
$out       = Get-Item (Join-Path $probeRoot 'out')
```

Probes that need additional paths (e.g. Probe 4's `$project`, `$sentinel`) derive
them from `$probeRoot` the same way. Each inside-container step runs as:

```powershell
# Quote the script path: $probeRoot can contain a space (C:\Users\John Doe\...),
# which would otherwise split the command line and break every inside launch.
# Zero capabilities (@()) unless a probe says otherwise; waits up to 5 min, returns the exit code.
[NockProbe.AC]::Run($sid, @(), ('powershell -NoProfile -ExecutionPolicy Bypass -File "' +
  (Join-Path $probeRoot '_inside.ps1') + '" -Phase <name>'), 300000)
```

The `-Phase` argument selects which
body to run, so a probe that needs two container launches (Probe 4, `4a`/`4b`)
picks its half unambiguously. Read the inside-container snippets as the *body* of
that bootstrap, not as commands typed into the outer shell.

Because the launcher returns only the exit code, not the child's stdout, `_inside.ps1` tees
its verdict lines to `$out\_inside-<phase>.log` (`Start-Transcript` on entry, or
`Out-File -Append` per line) and the outer session reads those logs to score each
inside probe. Every "from INSIDE the container" verdict below — Probe 4's Phase 4a
`Assert-AccessDenied` results, Probe 10's spawn, and the rest — reaches the operator
this way; a container that just exits with nothing captured is a setup-vs-result
ambiguity of the exact class this round removes.

**DISPOSABLE-BOX ONLY probes run on a throwaway VM, never on the desktop.** See
the [classification table](#probe-classification) above for which probes and
steps belong to which class. Probe 9 (firewall off) is the most dangerous;
Probe 8 (package installs) and the disposable-box steps of Probes 5b, 6, and 7
also belong on the throwaway box.

Follow the house convention in [`docs/probes/n10753/`](../probes/n10753/): commit
a `docs/probes/n10825/run-probe.ps1` plus an `output.txt` carrying environment
stamps (`[Environment]::OSVersion`, build number, edition, architecture, and
whether the session is elevated). That `run-probe.ps1` is where the shared
`$probeRoot` / `$moniker` / `Assert-AccessDenied` scaffold and the teardown blocks
below belong — the reader should not hand-assemble them.

**Box setup** (DISPOSABLE-BOX ONLY — run on a throwaway VM, never on the
desktop):

```powershell
winget install --id Git.Git --scope user
winget install --id OpenJS.NodeJS.LTS --scope user
winget install --id Python.Python.3.12 --scope user
# MSVC only if testing compilers: Visual Studio Build Tools (needs admin)
[Environment]::OSVersion.Version; (Get-ComputerInfo).WindowsProductName
```

On the **desktop**, these tools must already be present. The shared scaffold's
`Get-Command` checks record SETUP-FAULT for any probe whose prerequisites are
missing and also log the resolved path, so the environment stamps are already
captured — no second `Get-Command` loop needed.

**Elevation.** The desktop SSH shell is already elevated — see
[the corrected premise](#elevation-on-the-desktop--corrected-premise). Steps
marked ELEVATED run in it directly; steps that must run non-elevated go through
the [limited-token runner](#limited-token-runner-desktop).

#### Launcher (desktop path): Add-Type P/Invoke

Probes 1, 3, 4, 5, 6, 9, 10 and 11 need a tool that creates an AppContainer
profile with a chosen capability set and runs a command in it. NtObjectManager is
**absent on the desktop** (precheck `ntobj=False`) and nothing is installed there,
so the launcher is an in-memory `Add-Type` P/Invoke over the launch sequence in
[(a)](#a-filesystem-confinement-for-a-child-process-tree). It is the path every
scripted step uses on both boxes; NtObjectManager stays a disposable-box
cross-check. It is throwaway probe scaffolding, not product code.

`run-probe.ps1` writes `_launcher.cs` into `$probeRoot`; the scaffold compiles it
**once** to `_launcher.dll` and grants the package SID read on the DLL (as it does
`_inside.ps1`), because the limited task and Probe 10(a) *inside* the container
load the same compiled launcher rather than recompiling. `_launcher.cs`:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace NockProbe {
  public static class AC {
    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
      public int cb; public string lpReserved, lpDesktop, lpTitle;
      public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
      public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION with BasicLimitInformation and IoInfo inlined
    // (same layout on x86 and x64: the IoInfo ulongs realign exactly as the nested struct pads).
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
      public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
      public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount,
                   ReadTransferCount, WriteTransferCount, OtherTransferCount;
      public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeleteAppContainerProfile(string name);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int GetAppContainerFolderPath(string sid, out IntPtr path);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSidToSid(string s, out IntPtr sid);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcess(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags,
      IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr sa, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int cls, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint len);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int retLen);

    // Win32 failure -> HRESULT_FROM_WIN32 exception, so E_ACCESSDENIED surfaces as
    // UnauthorizedAccessException with HResult 0x80070005 (callers use GetBaseException()).
    static void Check(bool ok) {
      if (!ok) Marshal.ThrowExceptionForHR(unchecked((int)0x80070000) | Marshal.GetLastWin32Error());
    }

    // CreateAppContainerProfile with no capabilities; returns the package SID string.
    // Throws if the profile already exists: with a GUID moniker that is a bug, not a profile to adopt.
    public static string CreateProfile(string name) {
      IntPtr sid;
      Marshal.ThrowExceptionForHR(CreateAppContainerProfile(name, name, name, IntPtr.Zero, 0, out sid));
      try { return new SecurityIdentifier(sid).Value; } finally { FreeSid(sid); }
    }

    // DeleteAppContainerProfile; returns the HRESULT (teardown prints it, never throws).
    public static int DeleteProfile(string name) { return DeleteAppContainerProfile(name); }

    // The child's explicit environment block (CREATE_UNICODE_ENVIRONMENT): TEMP, TMP,
    // LOCALAPPDATA, APPDATA and USERPROFILE all point at the profile's own AC folder
    // (%LOCALAPPDATA%\Packages\<moniker>\AC, which CreateAppContainerProfile creates and
    // grants to the package SID), so no probe reads or writes the operator's real
    // profile dirs through them. Only the variables tools need to start are copied through.
    // Layout "K=V\0...K=V\0", sorted case-insensitively; StringToHGlobalUni adds the final \0.
    // Returns IntPtr.Zero (inherit) only when the CALLER is itself an AppContainer
    // (Probe 10(a)'s re-container): its own block is already its container's redirected one,
    // and a lookup failure must not hide an escape. Otherwise a failure throws
    // InvalidOperationException with NO inner exception, so it is never read as a launch
    // denial (0x80070005).
    static IntPtr BuildEnvironment(string packageSid) {
      IntPtr p;
      int hr = GetAppContainerFolderPath(packageSid, out p);
      if (hr != 0) {
        bool callerIsAc = false;
        try { callerIsAc = TokenSummary(System.Diagnostics.Process.GetCurrentProcess().Id).StartsWith("AppContainer=True"); }
        catch { }                                   // unreadable own token: treat as not-AC and throw below
        if (callerIsAc) return IntPtr.Zero;
        throw new InvalidOperationException(string.Format("environment block: GetAppContainerFolderPath HRESULT 0x{0:X8}", hr));
      }
      string acDir;
      try { acDir = Marshal.PtrToStringUni(p); } finally { Marshal.FreeCoTaskMem(p); }
      string[] redirected = { "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE" };
      string[] copied = { "SystemRoot", "windir", "SystemDrive", "ComSpec", "PATH", "PATHEXT", "PSModulePath",
                          "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS", "USERNAME", "COMPUTERNAME",
                          "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
                          "CommonProgramFiles(x86)", "ProgramData", "ALLUSERSPROFILE" };
      var vars = new System.Collections.Generic.SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      foreach (string n in redirected) vars[n] = acDir;
      foreach (string n in copied) { string v = Environment.GetEnvironmentVariable(n); if (v != null) vars[n] = v; }
      StringBuilder b = new StringBuilder();
      foreach (var kv in vars) b.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
      return Marshal.StringToHGlobalUni(b.ToString());
    }

    // Starts cmdLine as an AppContainer process for packageSid holding exactly capabilitySids
    // (empty = zero capabilities), cwd = System32 (readable by ALL APPLICATION PACKAGES),
    // environment = BuildEnvironment's explicit block (inherited only when the caller is
    // itself an AppContainer, see BuildEnvironment).
    // Waits up to timeoutMs and returns the exit code. The child starts suspended inside an
    // anonymous job, so a timeout kills its WHOLE tree (TerminateJobObject), not just the
    // direct child, then throws. KILL_ON_JOB_CLOSE is opt-in (killOnClose): off by default
    // because on a normal return descendants a probe keeps on purpose (Probe 1's 9998
    // listener, launched from the elevated shell) must survive and are reaped by teardown's
    // verified-identity stop. Launches from inside the limited task (Probe 3) pass true: if
    // the task is stopped mid-Run, this process dies before its own TerminateJobObject, and
    // the kernel closing the job handle then kills the container tree instead of orphaning it.
    public static int Run(string packageSid, string[] capabilitySids, string cmdLine, int timeoutMs,
                          bool killOnClose = false) {
      IntPtr acSid = IntPtr.Zero, caps = IntPtr.Zero, sc = IntPtr.Zero, list = IntPtr.Zero, env = IntPtr.Zero;
      IntPtr[] capPtrs = new IntPtr[capabilitySids.Length];
      bool listInit = false;
      try {
        env = BuildEnvironment(packageSid);
        Check(ConvertStringSidToSid(packageSid, out acSid));
        int saSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
        if (capabilitySids.Length > 0) {
          caps = Marshal.AllocHGlobal(saSize * capabilitySids.Length);
          for (int i = 0; i < capabilitySids.Length; i++) {
            Check(ConvertStringSidToSid(capabilitySids[i], out capPtrs[i]));
            SID_AND_ATTRIBUTES sa = new SID_AND_ATTRIBUTES();
            sa.Sid = capPtrs[i]; sa.Attributes = 0x4;   // SE_GROUP_ENABLED
            Marshal.StructureToPtr(sa, caps + i * saSize, false);
          }
        }
        SECURITY_CAPABILITIES s = new SECURITY_CAPABILITIES();
        s.AppContainerSid = acSid; s.Capabilities = caps; s.CapabilityCount = (uint)capabilitySids.Length;
        sc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
        Marshal.StructureToPtr(s, sc, false);

        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);   // sizing call; fails by design
        list = Marshal.AllocHGlobal(size);
        Check(InitializeProcThreadAttributeList(list, 1, 0, ref size));
        listInit = true;
        Check(UpdateProcThreadAttribute(list, 0, (IntPtr)0x00020009,        // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
          sc, (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero));

        STARTUPINFOEX si = new STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        si.lpAttributeList = list;
        PROCESS_INFORMATION pi;
        Check(CreateProcess(null, new StringBuilder(cmdLine), IntPtr.Zero, IntPtr.Zero, false,
          0x00080000 | 0x08000000 | 0x00000004 | 0x00000400,   // EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
                                                                // | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
          env, Environment.SystemDirectory, ref si, out pi));
        IntPtr job = IntPtr.Zero;
        try {
          job = CreateJobObject(IntPtr.Zero, null);
          if (job == IntPtr.Zero || (killOnClose && !SetKillOnClose(job)) || !AssignProcessToJobObject(job, pi.hProcess)) {
            int err = Marshal.GetLastWin32Error();
            TerminateProcess(pi.hProcess, 1);                               // never let an untracked child run
            Marshal.ThrowExceptionForHR(unchecked((int)0x80070000) | err);
          }
          ResumeThread(pi.hThread);
          if (WaitForSingleObject(pi.hProcess, (uint)timeoutMs) != 0) {
            TerminateJobObject(job, 1);
            throw new TimeoutException("container process exceeded " + timeoutMs + " ms; its job was terminated");
          }
          uint code;
          Check(GetExitCodeProcess(pi.hProcess, out code));
          return (int)code;
        } finally {
          if (job != IntPtr.Zero) CloseHandle(job);
          CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
      } finally {
        if (listInit) DeleteProcThreadAttributeList(list);
        if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
        if (sc != IntPtr.Zero) Marshal.FreeHGlobal(sc);
        if (caps != IntPtr.Zero) Marshal.FreeHGlobal(caps);
        foreach (IntPtr p in capPtrs) if (p != IntPtr.Zero) LocalFree(p);
        if (acSid != IntPtr.Zero) LocalFree(acSid);
        if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
      }
    }

    // Sets JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000), every other limit left zero.
    // False on failure, with GetLastError intact for the caller.
    static bool SetKillOnClose(IntPtr job) {
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      li.LimitFlags = 0x2000;
      return SetInformationJobObject(job, 9, ref li,                     // JobObjectExtendedLimitInformation
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
    }

    // A live process's token: AppContainer flag, package SID, integrity-level SID
    // (S-1-16-4096 Low, -8192 Medium, -12288 High). Throws if it cannot be opened.
    public static string TokenSummary(int pid) {
      IntPtr h = OpenProcess(0x1000, false, pid);                         // PROCESS_QUERY_LIMITED_INFORMATION
      Check(h != IntPtr.Zero);
      IntPtr tok = IntPtr.Zero, buf = Marshal.AllocHGlobal(256);
      try {
        int len;
        Check(OpenProcessToken(h, 0x0008, out tok));                       // TOKEN_QUERY
        Check(GetTokenInformation(tok, 29, buf, 4, out len));             // TokenIsAppContainer
        bool isAc = Marshal.ReadInt32(buf) != 0;
        Check(GetTokenInformation(tok, 31, buf, 256, out len));           // TokenAppContainerSid
        IntPtr pkg = Marshal.ReadIntPtr(buf);
        string pkgSid = pkg == IntPtr.Zero ? "-" : new SecurityIdentifier(pkg).Value;
        Check(GetTokenInformation(tok, 25, buf, 256, out len));           // TokenIntegrityLevel
        string il = new SecurityIdentifier(Marshal.ReadIntPtr(buf)).Value;
        return "AppContainer=" + isAc + " PackageSid=" + pkgSid + " IntegrityLevel=" + il;
      } finally {
        if (tok != IntPtr.Zero) CloseHandle(tok);
        CloseHandle(h);
        Marshal.FreeHGlobal(buf);
      }
    }
  }
}
```

**The child's environment is explicit, not inherited.** Passing `NULL` hands the
child a copy of the elevated operator's block; whether Windows then rewrites `TEMP`
and `LOCALAPPDATA` for an AppContainer (section (a) cites `AC` / `AC\Temp`) is exactly
UNVERIFIED #12, and `USERPROFILE`/`APPDATA` are not documented as rewritten at all. So
the probes do not rely on it: `BuildEnvironment` sets `TEMP`, `TMP`, `LOCALAPPDATA`,
`APPDATA` and `USERPROFILE` to the profile's AC folder (`GetAppContainerFolderPath`,
i.e. `%LOCALAPPDATA%\Packages\<moniker>\AC`) — the folder root rather than
`AC\Temp`, because `CreateAppContainerProfile` creates and ACLs the root but the
launcher creates no directories. The other variables are copied from the launcher's
own environment so `cmd`, PowerShell, git, node, python and MSVC discovery can start:
`SystemRoot`, `windir`, `SystemDrive`, `ComSpec`, `PATH`, `PATHEXT`, `PSModulePath`
(in-box modules such as `Resolve-DnsName`), `PROCESSOR_ARCHITECTURE`,
`NUMBER_OF_PROCESSORS`, `OS`, `USERNAME`, `COMPUTERNAME`, and the machine-wide
`ProgramFiles`/`ProgramFiles(x86)`/`ProgramW6432`/`CommonProgramFiles`/`CommonProgramFiles(x86)`/`ProgramData`/`ALLUSERSPROFILE`
— none of which names a per-user directory. Inside a container (Probe 10(a)) the
launcher inherits its caller's block, which is already that container's redirected one.
The scaffold's first zero-capability launch checks that the child's `TEMP` and
`LOCALAPPDATA` lie under the AC folder and stops the run as SETUP-FAULT if not; Probe 3
repeats the check on its limited-token launch, and Probes 3 and 5 print both values as
evidence.

PS 5.1's `Add-Type` compiles through CodeDom/`csc.exe`, which writes transient
`.cs`/`.cmdline` files to `Path.GetTempPath()` (TMP, then TEMP) — so the one
compile is pointed at a scratch dir **inside the probe root**, and nothing lands
outside it. Every process then loads the DLL **from its bytes**
(`Assembly.Load(byte[])`), not by path: a path-loaded assembly stays file-locked
for the life of the elevated session, and teardown's `Remove-Item $probeRoot`
would fail on it. The one-line loader, used by the scaffold, `_limited.ps1`, and
`_inside.ps1`:

```powershell
[void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes((Join-Path $probeRoot '_launcher.dll')))
```

Scaffold use, in the elevated shell:

```powershell
# A launcher that will not compile, load, or register the profile means no launcher
# probe can run: stop here. The run's try/finally still runs the global teardown.
$launcherDll = Join-Path $probeRoot '_launcher.dll'
try {
  $scratch = New-Item -ItemType Directory -Path (Join-Path $probeRoot 'csc-tmp') -ErrorAction Stop
  $oldTmp = $env:TMP; $oldTemp = $env:TEMP
  $env:TMP = $scratch.FullName; $env:TEMP = $scratch.FullName
  try {
    Add-Type -TypeDefinition (Get-Content -Raw (Join-Path $probeRoot '_launcher.cs')) `
      -OutputAssembly $launcherDll -OutputType Library -IgnoreWarnings -ErrorAction Stop   # private P/Invoke structs raise CS0649
  } finally {
    $env:TMP = $oldTmp; $env:TEMP = $oldTemp
  }
  [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($launcherDll))
  # Registers the profile (CreateAppContainerProfile): the %LOCALAPPDATA%\Packages\<moniker>\
  # redirection the probes rely on, and what teardown's DeleteProfile removes.
  $sid = [NockProbe.AC]::CreateProfile($moniker)   # SID string; reused by Probes 4, 10, 11
} catch {
  "SETUP-FAULT: launcher unavailable -> $($_.Exception.GetBaseException().Message); probes 1, 3, 4, 5, 6, 10, 11 not scored"
  throw
}
$sid                                               # record this SID string; the icacls probes need it
icacls $launcherDll /grant "*${sid}:(R)"          # Probe 10(a) loads it inside the container
# One SID-writable drop dir, created and ACL'd from the OUTER shell (which holds
# WRITE_DAC; the Low-IL container does not). Inside-container steps hand their verdict
# logs and any value back out through it — every inside probe's `_inside-<phase>.log`
# and Probe 10's WMI child PID (see the bootstrap note above):
$out = New-Item -ItemType Directory -Force -Path (Join-Path $probeRoot 'out')
icacls $out.FullName /grant "*${sid}:(OI)(CI)(M)"
# zero-capability container — the default, and the study's pivot. It doubles as the
# environment self-check every launcher probe relies on: the child's TEMP and
# LOCALAPPDATA must lie under this profile's AC folder, or the run stops here.
# Returns "TEMP=<v> LOCALAPPDATA=<v>" from a `cmd /c set` capture, and $true in
# $script:redirected only if both are AC or under it (AC\Temp counts). Probe 3 reuses it.
function Test-Redirected([object[]]$Lines, [string]$AcDir) {
  $script:redirected = $true
  $shown = foreach ($n in 'TEMP', 'LOCALAPPDATA') {
    # -join makes a plain string, so an absent line is '' and fails the test below.
    $v = (((@($Lines) -match "^$n=") -replace "^$n=",'') -join ';').TrimEnd('\')
    if (-not ($v -eq $AcDir -or $v.StartsWith("$AcDir\", [StringComparison]::OrdinalIgnoreCase))) { $script:redirected = $false }
    "$n=$v"
  }
  $shown -join ' '
}
$envSmoke = Join-Path $out.FullName 'env-smoke.txt'
$rcSmoke  = [NockProbe.AC]::Run($sid, @(), ('cmd.exe /c set > "' + $envSmoke + '"'), 30000)
$acDir    = (Join-Path $env:LOCALAPPDATA "Packages\$moniker\AC").TrimEnd('\')
$envShown = Test-Redirected (Get-Content $envSmoke -ErrorAction SilentlyContinue) $acDir
if (-not (Test-Path $envSmoke)) {
  "SETUP-FAULT: zero-capability launch wrote no environment capture (exit $rcSmoke); run stopped before any probe"
  throw 'launcher environment self-check failed'
} elseif (-not $redirected) {
  "SETUP-FAULT: container environment not under $acDir ($envShown); run stopped before any probe"
  throw 'launcher environment self-check failed'
}
"LAUNCHER-ENV: PASS - $envShown"
# one capability (internetClient, S-1-15-3-1), for the contrast case:
[NockProbe.AC]::Run($sid, @('S-1-15-3-1'), 'cmd.exe /c exit 0', 30000)
```

Container launches from the elevated shell (Probes 1, 4, 5, 6, 10, 11) still
yield a Low-IL AppContainer token, but the token is derived from the elevated
parent, so it may carry groups (Administrators) that a product launch from a
normal Medium-IL shell would not. That is an **assumption, not a measurement**:
the verdicts those probes score (loopback reach, package-SID ACEs, AppContainer
flag of a WMI child) turn on the package SID and capabilities, not on the user
groups, and Probe 3 is the unelevated-parent evidence. If a result looks
parent-dependent, re-run that phase through the limited task.

#### Limited-token runner (desktop)

One Scheduled Task per run, registered for the current user with
`-RunLevel Limited` and `-LogonType Interactive` (no stored password; Kevin must
be logged on at the console, otherwise the task never starts and every routed
step records SETUP-FAULT). Its action is fixed at registration with the absolute,
quoted path of `_limited.ps1`; the phase to run is handed over in
`limited\request.txt` together with a **per-invocation id** (`<phase>-<GUID>`).
Every file the phase writes (`<id>.token.txt`, `<id>.log`, `<id>.done`, and Probe 3's
`p3\<id>\`) is named by that id, so a repeated phase (re-running the exemption
step, say) can only ever be scored from its own files, never from an earlier run's
`.done`, token, or log. A console window may flash briefly on the desktop when it
runs.

`_limited.ps1` (written into `$probeRoot` by `run-probe.ps1`):

```powershell
$probeRoot = $PSScriptRoot
$runId     = (Split-Path -Leaf $probeRoot) -replace '^nocklock-probe-',''
$moniker   = "nocklock-probe-$runId"
$lim       = Join-Path $probeRoot 'limited'
# Line 1 = phase, line 2 = this invocation's id; every result path below is keyed by the id.
$phase, $inv = Get-Content (Join-Path $lim 'request.txt') -ErrorAction Stop
$log       = Join-Path $lim "$inv.log"
$step      = 'setup'
# This invocation's OWN token, so each phase is scored against the token it actually ran under.
whoami /groups | Out-File -FilePath (Join-Path $lim "$inv.token.txt") -Encoding utf8
"PHASE $phase" | Out-File -FilePath $log -Encoding utf8
try {
  switch ($phase) {
    'control' { }   # the whoami above is the whole positive control
    'exempt'  {     # Probe 1's non-elevated exemption step
      CheckNetIsolation.exe LoopbackExempt -a "-n=$moniker" 2>&1 | Out-File $log -Append -Encoding utf8
      "exit=$LASTEXITCODE" | Out-File $log -Append -Encoding utf8
    }
    'probe3'  { <Probe 3 body, below> }
    'probe7'  { <Probe 7 body, below> }
  }
} catch {
  $e = $_.Exception.GetBaseException()
  # $step (set by a phase body before each call) says WHICH call failed, so a denial on
  # a setup step is never read as the answer to the probe's question.
  ('ERROR: step={0} HResult=0x{1:X8} {2}' -f $step, $e.HResult, $e.Message) | Out-File $log -Append -Encoding utf8
} finally {
  # Completion sentinel, written LAST: the outer session never scores a half-written log.
  Set-Content -Path (Join-Path $lim "$inv.done") -Value 'done'
}
```

Scaffold, in the elevated shell — registration, the runner, and the positive
control that must pass before anything routed through the task is scored:

```powershell
$taskName   = "nocklock-probe-limited-$runId"
$limitedDir = Join-Path $probeRoot 'limited'
New-Item -ItemType Directory -Path $limitedDir -ErrorAction Stop | Out-Null
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
  '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $probeRoot '_limited.ps1') + '"')
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
  -LogonType Interactive -RunLevel Limited
$taskCreated = $false
# Defaults would skip a start on battery; IgnoreNew is kept, so Invoke-LimitedPhase
# stops AND awaits any still-running instance before each /Run (else the /Run is
# silently ignored).
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
$taskCreated = $true

# Stops the task and WAITS (up to 30 s) until it is no longer Running; returns its state.
function Stop-LimitedTask {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  for ($i = 0; ($st = (Get-ScheduledTask -TaskName $taskName).State) -eq 'Running' -and $i -lt 30; $i++) { Start-Sleep 1 }
  $st
}

# Runs one _limited.ps1 phase under a fresh invocation id ($limitedInv, "<phase>-<GUID>")
# and returns that invocation's log lines ONLY if it completed (its own <id>.done present)
# AND its own token is proven limited: Medium Mandatory Level (S-1-16-8192) present, High
# Mandatory Level (S-1-16-12288) absent. Otherwise returns $null with the reason in
# $limitedFault; callers turn $null into SETUP-FAULT, never into a scored result.
# `schtasks /Run` returns immediately, hence the bounded poll.
function Invoke-LimitedPhase {
  param([string]$Phase, [int]$TimeoutSec = 120)
  # A failed positive control (or a timed-out task that would not stop) fails every
  # later phase at once, instead of each waiting out its own timeout or overlapping it.
  $script:limitedInv = $null         # never left pointing at an earlier invocation
  if ($script:limitedDead) { $script:limitedFault = "limited task unusable ($script:limitedDead)"; return $null }
  $script:limitedFault = $null
  $inv = '{0}-{1}' -f $Phase, [guid]::NewGuid().ToString('N')
  $script:limitedInv = $inv
  $done  = Join-Path $limitedDir "$inv.done"
  $token = Join-Path $limitedDir "$inv.token.txt"
  # A timed-out earlier phase may still be running: stop it before handing over the new
  # request, so no old instance can pick it up.
  if ((Stop-LimitedTask) -eq 'Running') {
    $script:limitedFault = "an earlier instance of $taskName is still running 30 s after Stop-ScheduledTask"
    return $null
  }
  Set-Content -Path (Join-Path $limitedDir 'request.txt') -Value @($Phase, $inv)
  schtasks /Run /TN $taskName | Out-Null
  if ($LASTEXITCODE -ne 0) { $script:limitedFault = "schtasks /Run exit $LASTEXITCODE"; return $null }
  for ($i = 0; $i -lt $TimeoutSec -and -not (Test-Path $done); $i++) { Start-Sleep 1 }
  if (-not (Test-Path $done)) {
    # TIMEOUT. Stop the task and wait until it is no longer Running BEFORE returning, so a
    # late phase cannot keep adding exemptions / profiles / ETW sessions while the caller's
    # fallback or teardown runs. Probe 3's container child dies with it (kill-on-close job).
    # Always $null, even if .done lands after the stop: a timed-out phase is never scored.
    $st = Stop-LimitedTask
    $script:limitedFault = "timeout: phase $Phase ($inv) wrote no .done within $TimeoutSec s (task not started — console session logged off?); task stopped, state $st"
    # A task that will not stop must not run alongside anything else: fail every later phase.
    if ($st -eq 'Running') { $script:limitedDead = $script:limitedFault }
    return $null
  }
  $medium = [bool](Select-String -Path $token -SimpleMatch 'S-1-16-8192' -ErrorAction SilentlyContinue)
  $high   = [bool](Select-String -Path $token -SimpleMatch 'S-1-16-12288' -ErrorAction SilentlyContinue)
  if (-not $medium -or $high) {
    $script:limitedFault = "phase $Phase ($inv) token not proven limited (Medium present=$medium, High present=$high)"
    return $null
  }
  Get-Content (Join-Path $limitedDir "$inv.log")
}

# POSITIVE CONTROL. limited\control-<GUID>.token.txt is kept verbatim as evidence (the
# Administrators line should read deny-only); only the two Mandatory Level SIDs are scored.
if (Invoke-LimitedPhase 'control') {
  "LIMITED-TOKEN: PASS — task token is Medium IL with High absent"
} else {
  $limitedDead = $limitedFault
  "LIMITED-TOKEN: FAIL — $limitedFault; Probe 1's exemption step, Probe 3 and Probe 7 will record SETUP-FAULT"
}
```

### Probe 1: the pivot — zero-capability loopback

**Question:** can a container with *no* capabilities reach `127.0.0.1` at all
once loopback-exempted, and how wide does the exemption open? (Sole-socket egress
is a Phase 2 property, not something this probe can confirm — see
[(b)](#b-network-egress-floor).) This subsumes the elevation question, so run it
before Probe 2's persistence checks.

```powershell
# A busy probe port (scaffold BEFORE check) means a foreign listener could answer
# every curl below: do not run Probe 1 at all, so nothing prints as if scored.
# (`return` leaves this probe's own block in run-probe.ps1, as in Probe 10.)
if ($setupFaults -match '^Probe 1 ') { "VERDICT(1): SETUP-FAULT - $($setupFaults -match '^Probe 1 ' -join '; '); Probe 1 and Probe 2 not run"; return }

# terminal A - two listeners OUTSIDE any container (both serve from the probe root).
# 8899 is the primary target; 9999 is a SECOND real listener so the unrelated-port
# check below has something to reach — without it, curl to 9999 fails with
# "connection refused" no matter what the loopback policy does, which is the exact
# wrong-reason verdict this round removes.
$job8899 = Start-Job { python -m http.server 8899 --bind 127.0.0.1 --directory $using:probeRoot }
$job9999 = Start-Job { python -m http.server 9999 --bind 127.0.0.1 --directory $using:probeRoot }

# terminal A - POSITIVE CONTROLS from OUTSIDE the container: poll each listener
# up to 10 s (1 s intervals) to confirm it is live before reading inside verdicts.
# If a listener never answers, record SETUP-FAULT — the inside verdict is unscored.
foreach ($port in @(8899, 9999)) {
  $up = $false
  for ($i = 0; $i -lt 10; $i++) {
    curl.exe -sS -m 1 -o NUL http://127.0.0.1:${port}/ 2>$null
    if ($LASTEXITCODE -eq 0) { $up = $true; break }
    Start-Sleep 1
  }
  if ($up) { "outside $port -> live" }
  else     { "outside $port -> SETUP-FAULT (listener not ready after 10 s)" }
}

# terminal B - register the exemption NON-ELEVATED first, through the limited-token
# task (the SSH shell is elevated, so running -a here would answer Probe 2 for the
# wrong reason). Presence is read by this run's SID (scaffold's Test-ExemptListed).
# CLEAN STATE FIRST: a repeated attempt would otherwise find the entry an earlier
# (possibly elevated-fallback) attempt left, and score it as the limited add's. So remove
# THIS run's entry by moniker and prove it absent; if it will not go, nothing is measured.
# The if/elseif chain is ONE expression assigned once, so exactly one verdict prints.
CheckNetIsolation.exe LoopbackExempt -d "-n=$moniker" | Out-Null
$preClean    = -not (Test-ExemptListed)
$nonElevated = if ($preClean) { Invoke-LimitedPhase 'exempt' }
$limitedRc   = (@($nonElevated) -match '^(exit=|ERROR:)') -join '; '
# Scored on the limited -a's own exit code (exactly `exit=0`, no ERROR line) AND the
# entry being present afterwards — never on the log merely being non-empty.
$limOk  = $preClean -and $limitedRc -eq 'exit=0' -and (Test-ExemptListed)
$elevOk = $false
if (-not $limOk) {
  # Not proven limited, or the limited -a failed or did not list it: add it ELEVATED so the
  # rest of Probe 1 can still run.
  CheckNetIsolation.exe LoopbackExempt -a "-n=$moniker" | Out-Null
  $elevOk = Test-ExemptListed
}
$verdict1x = if (-not $preClean) {
    "SETUP-FAULT - this run's entry still listed after -d, so a limited add cannot be measured; Probe 2 not scored"
  } elseif (-not $nonElevated -and $elevOk) {
    "SETUP-FAULT - limited token not proven ($limitedFault); exemption added ELEVATED, Probe 2 not scored"
  } elseif (-not $nonElevated) {
    "SETUP-FAULT - limited token not proven ($limitedFault) and elevated -a did not list the entry; Probe 1 not scored"
  } elseif ($limOk) {
    "NON-ELEVATED OK - limited-token -a exited 0 and listed the entry (Probe 2: admin not required) [$limitedRc]"
  } elseif ($elevOk) {
    "ADMIN REQUIRED - limited-token -a failed or did not list the entry, elevated -a did (Probe 2: admin required) [limited: $limitedRc]"
  } else {
    "SETUP-FAULT - entry absent after limited AND elevated -a [limited: $limitedRc]; Probe 1 not scored"
  }
"VERDICT(1-exempt): $verdict1x"

# then, inside a ZERO-capability container (desktop path: the launcher from the
# elevated shell, [NockProbe.AC]::Run($sid, @(), <_inside.ps1 -Phase 1>, ...)). Capture the verbatim curl error text and
# exit code for each — the verdict is read from the recorded output, not inferred:
curl.exe -sS -m 5 http://127.0.0.1:8899/ 2>&1; "8899 exit=$LASTEXITCODE"  # MUST succeed, or Phase 1 is dead
curl.exe -sS -m 5 https://example.com/   2>&1; "example exit=$LASTEXITCODE"  # MUST fail (Block Outbound Default Rule)
curl.exe -sS -m 5 http://127.0.0.1:9999/ 2>&1; "9999 exit=$LASTEXITCODE"  # unrelated loopback port: EXPECTED reachable
# agent binds its own listener (Start-Process, not Start-Job — the container's
# job objects are not reachable from the outer session). The Process object from
# -PassThru is not accessible to the outer session (different process), so write
# PID + StartTime + Path to the drop dir. The outer teardown verifies all three
# before stopping — bare PID reuse across the ~minutes a probe run takes can
# kill an unrelated process.
$listener = Start-Process -PassThru python -ArgumentList "-m","http.server","9998","--bind","127.0.0.1","--directory",$probeRoot
Write-ProcessIdentity -Proc $listener -FilePath (Join-Path $out.FullName 'own-listener.txt')
```

The first two must hold. The unrelated-port check (9999) is the all-loopback
blast-radius test: because the exemption is per-identity, not per-port
([(b)](#b-network-egress-floor)), the *expectation* is that a **live** unrelated
port is reachable. Read its verdict against the outside positive control, not from
the error class — an AppContainer block may fail `connect()` fast (WSAEACCES)
rather than blackhole, so "slow ⇒ blocked, fast ⇒ refused" is not reliable on
Windows. Instead:

- outside control on 9999 succeeded **and** inside curl succeeded → reachable, per-identity model holds.
- outside control succeeded **and** inside curl failed → the listener is live, so the failure is the fence: loopback is narrower than the per-identity model predicts. **Flag it**, and record the verbatim curl error and exit code for the report.
- outside control on 9999 *failed* → the listener never came up: this is a **setup fault**, not a verdict — restart the 9999 job and rerun, do not score it.

The agent's own `127.0.0.1:9998` listener is a separate blast-radius check, but
**the loopback exemption covers the container as a client, not as a server** (the
cited source in [(b)](#b-network-egress-floor): "a Windows Runtime app can use an
IP loopback only as the target address for a *client* network request"). So an
exempted container can *reach* loopback but may not be able to *receive* loopback
connections — polling 9998 from OUTSIDE the container may always read
SETUP-FAULT regardless of policy. This probe therefore scopes the claim to
**outbound-only**: `bind()` + `listen()` succeeded inside the container, and the
agent reached the *outside* listeners (8899, 9999). Whether the agent can also
receive inbound loopback is left UNVERIFIED — it is not load-bearing for the
proxy design, which only needs the container to reach out to the proxy.

If the first `curl` fails, the recommendation's Phase 1 is dead and Phase 2
becomes mandatory — report immediately, do not run the rest.

**Teardown.** Stop all three `python` listeners: the two outer jobs by handle
(`$job8899, $job9999 | Stop-Job -PassThru | Remove-Job`) and the inside 9998
listener via the scaffold's `Stop-VerifiedProcess` (reads `own-listener.txt`,
confirms PID + StartTime + Path still match the live process, skips if missing
or mismatched):

```powershell
Stop-VerifiedProcess -IdentityFile (Join-Path $out.FullName 'own-listener.txt')
```

Never `Get-Job | Stop-Job` — that kills every job in the operator's session. The
loopback exemption is machine-wide session state shared by every probe, so it is
**left in place until the global teardown** removes it with
`CheckNetIsolation.exe LoopbackExempt -d "-n=$moniker"`. The one exception is the
measured step itself: each exemption attempt first removes this run's entry and
proves it absent, so a repeated attempt never scores an earlier attempt's entry. The limited task that
ran the `exempt` phase is shared with Probe 3 and likewise removed by the global
teardown.

| State touched | Detail |
|---|---|
| Creates | 2 outer jobs (`$job8899`, `$job9999`); 1 inside listener process (identity in `own-listener.txt`); loopback exemption (machine-wide; removed and proven absent before each measured attempt, then added by the limited task or the elevated retry, kept until global teardown); `limited\exempt-<GUID>.*` files under `$probeRoot` (one run of the scaffold's scheduled task) |
| Removes | the 2 outer jobs (by handle); inside listener (by verified PID+StartTime+Path) |
| Must never touch | other user jobs; loopback exemptions not created by this run; scheduled tasks other than `nocklock-probe-limited-$runId` |

### Probe 2: does the exemption need elevation?

Probe 1's `VERDICT(1-exempt)` line is Probe 2's answer, because only that step ran
under a proven limited token: **NON-ELEVATED OK** scores "admin not required",
**ADMIN REQUIRED** scores "admin required", and **SETUP-FAULT** leaves Probe 2
unscored. Whether the elevated SSH shell can add the entry says nothing about the
question — it is elevated. This probe then confirms the entry is present within
the session:

```powershell
CheckNetIsolation.exe LoopbackExempt -s      # entry present in this session?
```

Report Probe 1's `VERDICT(1-exempt)` line (it carries the limited-token exit code)
and whether `-s` listed the entry.

**Reboot durability is deliberately UNVERIFIED this run.** A reboot cannot sit
inside the single `try/finally` that wraps the probe run, and this run does **not**
reboot Kevin's desktop. Verifying that the exemption (and the AppContainer profile)
survive a reboot would be a **separate, optional script, not part of this run**: it
would first write a recovery manifest recording `$runId`/`$moniker`/`$probeRoot` so
a fresh post-reboot session can find and clean the pre-reboot state, then reboot,
then re-check `LoopbackExempt -s`, then run its own post-reboot cleanup. Until that
script is run, reboot survival (and "survives a Windows Update") stays an open item
in the UNVERIFIED table, not a scored result.

**Teardown.** None of its own — the exemption it inspects is removed by the
global teardown.

| State touched | Detail |
|---|---|
| Creates | nothing |
| Removes | nothing |
| Must never touch | loopback exemption entries (read-only `LoopbackExempt -s`) |

### Probe 3: AppContainer launch unelevated

**Desktop path: entirely in the limited task.** The SSH shell is elevated, so the
old `whoami /groups | findstr "High Mandatory"` precondition would fail there before
any launch. Instead the whole probe — loading the launcher, *creating its own
profile*, and launching — runs as the `probe3` phase of `_limited.ps1`, whose token
the runner has already proven Medium-IL with High absent. It uses its own moniker
`nocklock-p3-$runId`, because the scaffold's profile was created elevated and
creating one unelevated is part of the question (`CreateAppContainerProfile`
documents `E_ACCESSDENIED`).

The `probe3` body inside `_limited.ps1`:

```powershell
$step = 'load'
[void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes((Join-Path $probeRoot '_launcher.dll')))
$step = 'createprofile'
$sid3 = [NockProbe.AC]::CreateProfile("nocklock-p3-$runId")      # throws -> ERROR line (caught above)
"profile=CREATED sid=$sid3" | Out-File $log -Append -Encoding utf8
$step = 'grant'
$d3 = New-Item -ItemType Directory -Path (Join-Path $probeRoot "p3\$inv") -ErrorAction Stop   # this invocation's own dir
icacls $d3.FullName /grant "*${sid3}:(OI)(CI)(M)" | Out-Null   # the limited token owns p3\<id>\, so it holds WRITE_DAC
$step = 'run'
# `set` records the container's own environment, so the verdict shows TEMP/LOCALAPPDATA were redirected.
$rc = [NockProbe.AC]::Run($sid3, @(),
  ('cmd.exe /c whoami /all > "' + (Join-Path $d3.FullName 'whoami-inside.txt') +
   '" & set > "' + (Join-Path $d3.FullName 'env-inside.txt') + '"'), 60000, $true)   # kill-on-close: a stopped task takes the container with it
"launch=OK exit=$rc" | Out-File $log -Append -Encoding utf8
```

Scored in the elevated shell, one verdict line:

```powershell
$p3 = Invoke-LimitedPhase 'probe3'
$inv3 = $limitedInv                  # this call's id, captured once
# Read ONLY this invocation's dir; with no proven run, read nothing.
$d3  = if ($p3) { Join-Path $probeRoot "p3\$inv3" }
$w   = if ($d3) { Get-Content (Join-Path $d3 'whoami-inside.txt') -ErrorAction SilentlyContinue }
$e3  = if ($d3) { Get-Content (Join-Path $d3 'env-inside.txt') -ErrorAction SilentlyContinue }
# The launcher's redirect target, checked with the scaffold's Test-Redirected.
$ac3  = (Join-Path $env:LOCALAPPDATA "Packages\nocklock-p3-$runId\AC").TrimEnd('\')
$env3 = "container " + (Test-Redirected $e3 $ac3)
$p3err = (@($p3) -match '^ERROR:') -join '; '
if (-not $p3) {
  "VERDICT(3): SETUP-FAULT - $limitedFault; not scored"
} elseif ($p3 | Select-String -Pattern '^ERROR: step=(createprofile|run) HResult=0x80070005') {
  # CreateProfile or Run itself was DENIED under the limited token: the answer is "needs admin".
  # A denial on load/grant is a setup problem and falls through to INDETERMINATE.
  "VERDICT(3): FAILS UNELEVATED - $p3err"
} elseif (-not ($p3 | Select-String -SimpleMatch 'launch=OK')) {
  # Any other failure (launcher did not compile, timeout, ...) is not a denial.
  "VERDICT(3): INDETERMINATE - $p3err"
} elseif (-not (($w | Select-String -SimpleMatch 'S-1-16-4096') -and ($w | Select-String -Pattern 'S-1-15-2-1\b'))) {
  "VERDICT(3): INDETERMINATE - launched, but p3\$inv3\whoami-inside.txt shows no Low IL (S-1-16-4096) plus ALL APPLICATION PACKAGES (S-1-15-2-1)"
} elseif (-not $redirected) {
  # A Low-IL child that still sees host TEMP/LOCALAPPDATA means the launcher's environment block is wrong.
  "VERDICT(3): INDETERMINATE - Low-IL AppContainer child launched, but it was not redirected to $ac3 ($env3)"
} else {
  "VERDICT(3): WORKS UNELEVATED - limited-token parent created the profile and launched a Low-IL AppContainer child ($env3)"
}
```

Re-running `probe3` within the same run prints its own verdict from its own
`p3\<id>\` files: the profile already exists, so it reads `INDETERMINATE` with
`step=createprofile` (HResult `0x800700B7`, not a denial), never the first run's result.

**Teardown.** The container process exits on its own; the global teardown deletes
the `nocklock-p3-$runId` profile and the scheduled task by exact name; every
invocation's `p3\<id>\` and `limited\<id>.*` files go with `$probeRoot`.

| State touched | Detail |
|---|---|
| Creates | AppContainer profile `nocklock-p3-$runId` (per-user, outside the root); transient container process; `p3\<id>\` and `limited\probe3-<GUID>.*` under `$probeRoot`; one run of the scheduled task |
| Removes | nothing itself (profile and task removed by the global teardown, by exact name) |
| Must never touch | user token; system groups; the scaffold's `nocklock-probe-$runId` profile |

### Probe 4: ACL grant and the deny-default

Covers the plain grant/deny, the ALL APPLICATION PACKAGES read hole, the explicit
DENY that closes it, ACE inheritance leaking into the audit directory, and — new
this round — whether a package SID granted recursive Modify on the project root
can **rename, delete, or replace an in-project `.nock/` via the parent** despite
`.nock/` carrying no writable ACE (the delete-via-parent hole that moves the audit
DB out of the project, [(d)](#d-secret-fence-and-the-audit-chain)). **The
deny-target sentinel is a *fake* home inside the probe root — never the real
`$env:USERPROFILE`** — so no probe can touch a real key, and its "MUST fail" read
cannot pass merely because the file is absent.

**Every ACL change runs from the OUTER user shell.** A Low-IL AppContainer process
has no `WRITE_DAC`, so an `icacls` grant or deny issued *inside* the container is
silently a no-op — the ACE never lands, and the follow-up assertion passes or fails
for the wrong reason. So this probe is two container launches with all ACL edits
between them in the outer shell, and the DENY ACE is verified present before the
inside read runs. **Desktop path:** both launches (`-Phase 4a`, `-Phase 4b`) use
the launcher from the elevated shell, zero capabilities.

**Step 1 — OUTER SHELL** (has WRITE_DAC): create the directories, grant the
package SID on the project root, simulate the ALL APPLICATION PACKAGES read hole,
and verify the sentinel exists before any container launch:

```powershell
$project  = New-Item -ItemType Directory -Force -Path (Join-Path $probeRoot 'project')
$other    = New-Item -ItemType Directory -Force -Path (Join-Path $probeRoot 'other-project')
$fakeHome = New-Item -ItemType Directory -Force -Path (Join-Path $probeRoot 'home\.ssh')
$sentinel = Join-Path $fakeHome 'id_rsa'
Set-Content -Path $sentinel -Value 'FAKE-not-a-real-key'

if (Test-Path $sentinel) { "PASS(control): sentinel readable outside" } else { "FAIL(control): sentinel missing" }

icacls $project.FullName /grant "*${sid}:(OI)(CI)(M)"
$nock = New-Item -ItemType Directory -Force -Path (Join-Path $project.FullName '.nock')
icacls $nock.FullName                       # inspect: inherited ACE present?
icacls $nock.FullName /inheritance:r /remove "*${sid}"
icacls $fakeHome /grant "*S-1-15-2-1:(OI)(CI)(R)"
```

**Step 2 — INSIDE the container (Phase 4a):** the read hole is still open, so the
sentinel is readable. The project write and audit/cross-project denials are also
tested here:

```powershell
Set-Content (Join-Path $project.FullName 'write-test.txt') 'ok'        # MUST succeed
Assert-AccessDenied { Set-Content (Join-Path $nock.FullName 'tamper.txt') 'bad' -ErrorAction Stop } 'write INSIDE .nock denied (no package-SID ACE)'
Assert-AccessDenied { Set-Content (Join-Path $other.FullName 'leak.txt') 'bad' -ErrorAction Stop }  'cross-project isolation'
Get-Content $sentinel   # EXPECTED TO SUCCEED — the ALL APPLICATION PACKAGES read hole is open

# delete-via-parent: .nock/ carries no writable ACE, but the project root was
# granted recursive Modify, which credibly carries FILE_DELETE_CHILD on the root —
# so the child may rename, delete or replace .nock/ THROUGH the parent even though
# it cannot write a file INSIDE it. Writing into a dir and deleting that dir via
# its parent are distinct rights. EXPECTED TO SUCCEED, which is exactly why the
# audit DB lives in the per-user state dir, not in-project (see (d)). Record the
# verbatim result of each; do NOT assert denial here.
Rename-Item $nock.FullName -NewName '.nock-moved' 2>&1                     # rename via parent
Remove-Item -Recurse -Force (Join-Path $project.FullName '.nock-moved') 2>&1  # delete via parent
New-Item -ItemType Directory -Force -Path $nock.FullName 2>&1              # replace via parent
# NOTE: this recreated .nock/ INHERITS the project root's (OI)(CI)(M) package-SID
# ACE (Step 1's /inheritance:r removal applied only to the ORIGINAL directory) —
# so the child now holds Modify on its own replacement audit dir. That is not a
# gap to fix; it is further proof the audit DB cannot live under filesystem.root.
# It also means no later step may re-test "write inside .nock denied" against this
# recreated dir — nothing here does (Phase 4b tests $sentinel, not .nock).
"delete-via-parent: record whether rename/delete/replace of .nock via the project root succeeded"
```

**Step 3 — OUTER SHELL** (has WRITE_DAC): apply the explicit DENY ACE, then gate
on it existing. The deny ACE MUST be present before Phase 4b runs; otherwise the
inside `Get-Content` succeeds and `Assert-AccessDenied` reports `FAIL(no-error)` —
the exact wrong-reason verdict a Low-IL container produces when `icacls /deny` is
run from *inside* (no `WRITE_DAC`, so the ACE silently never lands):

```powershell
icacls $fakeHome /deny "*${sid}:(OI)(CI)(R)"
$acl = icacls $fakeHome 2>&1
$denyAce = $acl | Where-Object { $_ -match [regex]::Escape($sid.ToString()) -and $_ -match '\(DENY\)' }
if ($denyAce) {
  "PASS(setup): deny ACE present for $sid — running Phase 4b"
} else {
  "FAIL(setup): deny ACE absent for $sid — Phase 4b NOT RUN (do not score the close)"
}
```

**Step 4 — INSIDE the container (Phase 4b):** only if the gate passed. A fresh
container launch confirms the explicit DENY closes the read hole:

```powershell
Assert-AccessDenied { Get-Content $sentinel -ErrorAction Stop } 'explicit DENY closes the read hole'
```

The point is the last pair: confirm the standing ALL APPLICATION PACKAGES read
hole is open (Phase 4a reads the sentinel), then confirm an explicit DENY ACE
closes it (Phase 4b). `Assert-AccessDenied` makes each "MUST fail" a *specific*
access-denied assertion (E_ACCESSDENIED `0x80070005`) — a not-found result is
scored `FAIL`, which is exactly the wrong-reason pass this round removes.

The delete-via-parent steps in Phase 4a are the opposite polarity: they are
*expected to succeed*, so they are recorded verbatim rather than asserted denied.
A success confirms the hole that moves the audit DB out of the project
([(d)](#d-secret-fence-and-the-audit-chain)); a denial would be the surprising
result worth flagging. This distinguishes "cannot write inside `.nock/`" (true,
via the intersection rule) from "cannot delete `.nock/` via the parent" (the open
question), which is why the audit DB does not rely on either.

**Teardown.** All artifacts are under `$probeRoot` and go with the global
`Remove-Item`. (For a system path you would `icacls … /remove:d`; here the DENY
lives inside the root, so deleting the root suffices.)

| State touched | Detail |
|---|---|
| Creates | dirs and ACLs under `$probeRoot` (`project/`, `other-project/`, `home/.ssh/`); renames/deletes/recreates the in-project `.nock/` (delete-via-parent step, all under `$probeRoot`); container processes |
| Removes | nothing (all under `$probeRoot`, removed globally) |
| Must never touch | `$env:USERPROFILE` ACLs; real `~/.ssh`; the real audit DB in the per-user state dir |

### Probe 5: toolchain survival

Split deliberately into two classes. Part (a) is **DESKTOP-SAFE**: the offline
steps are the real toolchain-survival signal and need no network. Part (b) is
**DISPOSABLE-BOX ONLY**: the network-fetch steps exercise `npm install` and
`pip install` into the probe root — project-local, but the install commands
exercise the package-manager path that only belongs on a throwaway box.

The network-fetch steps are gated on a *genuine CONNECT-capable* proxy.
Probe 1's listener is a plain HTTP file server (`GET` only, no `CONNECT`), so
pointing `HTTPS_PROXY` at it makes `git clone https://…` fail at the TLS
tunnel — a proxy artefact, not a broken toolchain. Use NockLock's own
re-resolving proxy (`internal/fence/network`) or another real forward proxy
for part (b); do not reuse the Probe 1 file server. **Desktop path:** part (a)
runs as an `_inside.ps1` phase through the launcher from the elevated shell, zero
capabilities.

```powershell
# (a) OFFLINE (DESKTOP-SAFE) — inside the container, no proxy needed.
# This is the survival signal. Required tools must already be present on the
# desktop (checked by the shared scaffold); if any are absent, record
# SETUP-FAULT for this probe and skip it.
# The launcher's explicit environment block: both MUST lie under ...\Packages\<moniker>\AC
# (the scaffold's profile folder), never the operator's own TEMP/LOCALAPPDATA.
"container TEMP=$env:TEMP LOCALAPPDATA=$env:LOCALAPPDATA"
$repo = Join-Path $probeRoot 'project\repo'
git --version; git init $repo; git -C $repo status
node -e "console.log(JSON.stringify(process.env).slice(0,400))"
python -c "import sys; print(sys.prefix)"
cl.exe /? 2>&1 | Select-Object -First 3      # only if Build Tools installed

# (b) NETWORK-FETCH (DISPOSABLE-BOX ONLY) — only on a throwaway VM with a
# real CONNECT-capable proxy on 127.0.0.1:<port>. Keep every cache and target
# inside the probe root so nothing lands in the profile.
$env:HTTPS_PROXY = 'http://127.0.0.1:<connect-proxy-port>'
$env:GIT_CLONE_PROTECTION_ACTIVE = 'false'
git clone https://github.com/octocat/Hello-World.git (Join-Path $probeRoot 'project\hw')
$env:npm_config_cache = Join-Path $probeRoot 'npm-cache'
npm --version; npm install --prefix (Join-Path $probeRoot 'npm-proj') lodash
$env:PIP_CACHE_DIR = Join-Path $probeRoot 'pip-cache'
python -m venv (Join-Path $probeRoot 'venv'); & (Join-Path $probeRoot 'venv\Scripts\pip.exe') install requests
```

Record which fail, and whether failures are ACL-related (fixable with a grant) or
architectural (COM / named pipe / Low IL) — and separate those from part (b)
failures that are merely "no real proxy was supplied." Explicitly note **where
npm and pip actually wrote their caches** (the overrides above force them into the
probe root). The launcher passes an explicit environment block with `TEMP`, `TMP`,
`LOCALAPPDATA`, `APPDATA` and `USERPROFILE` set to the profile's AC folder (see
[the launcher](#launcher-desktop-path-add-type-pinvoke)), so the first line above
shows what the tools saw (the scaffold's environment self-check has already
stopped the run if the block was not redirected). Because `USERPROFILE` and `APPDATA`
are redirected too, git here finds neither the host's global config nor its credential
store — a probe-launcher choice, not necessarily what the product will pass. Whether Windows would redirect
those variables *itself* when handed an explicit block (UNVERIFIED #12) is a product
question the probe launcher deliberately sidesteps.

**Teardown.** Everything is under `$probeRoot`; the global `Remove-Item` is the
only cleanup. On a disposable box, part (b)'s artifacts go with it.

| State touched | Detail |
|---|---|
| Creates | dirs under `$probeRoot` (`repo/`, `venv/`, `npm-cache/`, `npm-proj/`, `pip-cache/`, `hw/`); env vars in session |
| Removes | nothing (all under `$probeRoot`, removed globally) |
| Must never touch | user-profile npm/pip caches; global node_modules |

### Probe 6: brokered egress — which services answer for us?

Generalises the DNS question to the whole confused-deputy class. All from inside
a **zero-capability** container, with no loopback exemption. The probe is
**DESKTOP-SAFE** except for the `Start-Process` step, which is
**DISPOSABLE-BOX ONLY** because it opens the operator's real browser (outside
the container, with full network access) and teardown is manual. **Desktop
path:** an `_inside.ps1` phase through the launcher from the elevated shell, zero
capabilities, with the `Start-Process` line omitted.

```powershell
# DESKTOP-SAFE steps:
nslookup example.com                                   # DNS Client service
Resolve-DnsName example.com
Start-BitsTransfer -Source https://example.com/ -Destination (Join-Path $probeRoot 'bits.out')   # synchronous — no BITS job outlives this call
Invoke-WebRequest https://example.com/ -UseBasicParsing
curl.exe -sS -m 5 https://example.com/                 # control: MUST fail
# DISPOSABLE-BOX ONLY — opens the operator's real browser:
Start-Process "https://example.com/"                   # shell handoff to a browser
```

Any of these succeeding means a service outside the container performed network
on the agent's behalf and WFP classified *that service's* traffic, not ours. Each
success is a bypass of the egress floor and must be listed. If DNS resolves while
the direct connection fails, note it specifically: egress is still fenced, but
queried names leak and DNS never reaches the proxy's allowlist.

**Teardown.** On a disposable box, `Start-Process` may open a real browser
tab — close it. On the desktop, skip the `Start-Process` step entirely. The
`bits.out` download is under `$probeRoot`; global `Remove-Item` clears it.

| State touched | Detail |
|---|---|
| Creates | `bits.out` under `$probeRoot`; may open a browser tab (disposable-box `Start-Process` step only) |
| Removes | nothing (under `$probeRoot`, removed globally); close the browser tab manually on the disposable box |
| Must never touch | user browser profile; DNS cache entries |

### Probe 7: ETW file events unelevated

**DESKTOP-SAFE** for the non-elevated attempt. The "add user to Performance Log
Users" retry is **DISPOSABLE-BOX ONLY** — group membership is a persistent
machine change the teardown cannot undo. **Desktop path: the limited task**
(`probe7` phase) — in the elevated SSH shell `logman create` would succeed for the
wrong reason, exactly like Probe 1's exemption step.

The `probe7` body inside `_limited.ps1` (run-unique session name, so teardown never
touches a session belonging to a concurrent run or another user):

```powershell
$etwSession = "nocklock-fileprobe-$runId"
logman create trace $etwSession -p Microsoft-Windows-Kernel-File -o (Join-Path $probeRoot 'f.etl') -ets 2>&1 |
  Out-File $log -Append -Encoding utf8
"create-exit=$LASTEXITCODE" | Out-File $log -Append -Encoding utf8
logman stop $etwSession -ets 2>&1 | Out-File $log -Append -Encoding utf8
```

Scored in the elevated shell, one verdict line:

```powershell
$etwSession = "nocklock-fileprobe-$runId"
$p7 = Invoke-LimitedPhase 'probe7'
# Unknown outcome (no proven run) counts as "may exist", so teardown still stops it by exact name.
$etwCreated = (-not $p7) -or [bool](@($p7) -match '^create-exit=0$')
if (-not $p7) {
  "VERDICT(7): SETUP-FAULT - $limitedFault; not scored"
} elseif (@($p7) -match '^create-exit=0$') {
  "VERDICT(7): UNELEVATED OK - a limited token started a Kernel-File trace (Phase 0 material)"
} else {
  "VERDICT(7): NEEDS MORE THAN A LIMITED TOKEN - $((@($p7) -match '^(create-exit=|ERROR:)') -join '; ') (Phase 2)"
}
```

Run non-elevated first. If it succeeds, file-event logging is Phase 0 material.
If it fails, the **DISPOSABLE-BOX ONLY** path is: add the user to *Performance
Log Users* (persistent group membership change) and retry, then retry elevated.
If the non-elevated attempt fails on the desktop, record the result and stop —
the answer is that file-event logging is Phase 2.

**Teardown.** The trace session (`nocklock-fileprobe-$runId`, run-unique) is
machine state and leaks if `stop` is skipped; the global teardown stops it by that
exact name whenever `$etwCreated` is true (created, or outcome unknown). The `.etl` file is under `$probeRoot`. On the disposable
box, group membership changes go with the box.

| State touched | Detail |
|---|---|
| Creates | ETW trace session `nocklock-fileprobe-$runId` (machine state, run-unique); `.etl` file and `limited\probe7-<GUID>.*` under `$probeRoot`; one run of the scheduled task |
| Removes | the trace session (only if this run created it); `.etl` removed globally with `$probeRoot` |
| Must never touch | other ETW sessions; Performance Log Users group membership (desktop run) |

### Probe 8: packaging no-admin

> **DISPOSABLE-BOX ONLY.** This probe installs user-scope packages. Run it on a
> throwaway VM or Windows Sandbox, never on the desktop.

This probe **mutates the user profile by design** — installing to the user scope
without a UAC prompt is the exact behaviour under test, so it cannot be sandboxed
into `$probeRoot` (Save-Module / portable downloads would skip the install-path
code entirely, which is what this probe exists to exercise).

```powershell
winget install --id sharkdp.fd --scope user --exact
scoop install ripgrep
where.exe fd; where.exe rg
```

Confirm both complete with no UAC prompt and land under the user profile.

**Teardown.** Discard the box. The packages are user-scope state on the throwaway
VM — discarding the VM is the complete, fail-safe cleanup. No uninstall path
to get wrong.

| State touched | Detail |
|---|---|
| Creates | user-scope packages (`sharkdp.fd` via winget, `ripgrep` via scoop) |
| Removes | the box (discard the VM) |
| Must never touch | the desktop |

### Probe 9: fail-open with the firewall off

> **⚠ DEFERRED — VM / throwaway box only. Do NOT run this on Kevin's desktop.**
> It disables the firewall, the single most dangerous action in this document.
> Run it only on a disposable VM, and capture the prior per-profile state first so
> it can be restored exactly (`set allprofiles state on` forces every profile on,
> which is *not* necessarily the pre-probe state). **Desktop path: none — not run
> on the desktop.** On the VM the container step uses the same launcher.

```powershell
# ELEVATED, on a throwaway VM only.
# Snapshot each profile's Enabled state FIRST, then restore each one CONDITIONALLY
# from that snapshot in a finally block. `set allprofiles state on` would force
# every profile on, which is NOT necessarily the pre-probe state.
# NetSecurity cmdlets (Win8+, present under PS 5.1). On a GPO-managed VM these
# target the LOCAL store, so a GPO-forced profile restores to its local value,
# not the GPO value (which cannot be overridden anyway); the netsh fallback is
# `netsh advfirewall set <domain|private|public>profile state on|off` per profile.
$fwSnapshot = Get-NetFirewallProfile -Name Domain,Private,Public |
  Select-Object Name, Enabled
$fwSnapshot | Format-Table -AutoSize        # RECORD this — restore to exactly this
try {
  Set-NetFirewallProfile -Name Domain,Private,Public -Enabled False
  # from inside a ZERO-capability container:
  curl.exe -sS -m 5 https://example.com/    # does it now SUCCEED?
} finally {
  foreach ($p in $fwSnapshot) {
    Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled   # restore per profile, to its recorded value
  }
}
```

Also capture the actual drop filter for the record (into the probe root):

```powershell
Push-Location $probeRoot
$wfpStarted = $false
try {
  netsh wfp capture start keywords=19
  if ($LASTEXITCODE -eq 0) { $wfpStarted = $true }
  # reproduce a blocked connection from inside the container
} finally {
  if ($wfpStarted) { netsh wfp capture stop }  # writes wfpdiag.cab in the CWD ($probeRoot)
  Pop-Location                                 # unconditional: always leave $probeRoot
}
# inspect wfpdiag.xml for FWPM_NET_EVENT_TYPE_CLASSIFY_DROP and the filter name
```

If traffic flows with the firewall off, NockLock must verify firewall state at
launch and refuse to start — a fence that silently disappears is worse than no
fence.

**Teardown.** Restore the firewall to the *recorded* per-profile state (above);
`netsh wfp capture stop` must run even if the repro throws, or the capture session
leaks. The `wfpdiag` output is under `$probeRoot`.

| State touched | Detail |
|---|---|
| Creates | `wfpdiag.cab` under `$probeRoot`; WFP capture session; firewall state change (VM only) |
| Removes | WFP capture session; restores firewall to recorded per-profile state |
| Must never touch | Kevin's desktop firewall (VM-only probe) |

---

### Probe 10: container escape — can the agent re-container itself?

The escape question, and the WMI-token question from
[(c)](#c-processsyscall-ish-limits). From inside a **zero-capability** container.
**Desktop path:** the outer launch is the launcher from the elevated shell, zero
capabilities; 10(a) then loads the *same* launcher inside the container (its
`_launcher.dll` is granted read to the package SID, so nothing compiles inside the
container). NtObjectManager is not used — it is absent on
the desktop, and nothing is installed there:

```powershell
# (a) re-container escape: this whole probe runs INSIDE the zero-capability
# container, so — unlike the shared scaffold's outer profile creation — this
# CreateProfile can legitimately return E_ACCESSDENIED (the same
# CreateAppContainerProfile-in-a-restricted-context denial the "What breaks" section
# documents). Each step gets its own try and its own verdict, so a launcher, launch,
# or curl failure is never misread as a profile denial; every path sets $verdictA
# exactly once and prints it once. HResults are read with the scaffold's
# Get-BaseHResult (launcher exceptions arrive wrapped).
# Teardown removes the profile by name if registered.
$escMoniker = "agent-escape-$runId"
$verdictA = $null
try {
  [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes((Join-Path $probeRoot '_launcher.dll')))
} catch {
  $verdictA = "VERDICT(a): INDETERMINATE - launcher did not load inside the container -> $($_.Exception.GetBaseException().Message)"
}
if (-not $verdictA) {
  try {
    $s2 = [NockProbe.AC]::CreateProfile($escMoniker)
  } catch {
    $e = $_.Exception.GetBaseException(); $h = Get-BaseHResult $_
    if ($h -eq '0x80070005') {
      $verdictA = "VERDICT(a): CONTAINED - escape profile creation denied (E_ACCESSDENIED)"
    } else {
      $verdictA = "VERDICT(a): INDETERMINATE - escape profile creation failed, not a denial -> $($e.GetType().FullName) HResult=$h $($e.Message)"
    }
  }
}
if (-not $verdictA) {
  try {
    # Run waits for curl (its -m 5 bounds it) and returns curl's exit code. Inside the
    # container, a failed AC-folder lookup makes Run inherit this container's block
    # rather than throw, so a lookup failure never masks an escape.
    $curlRc = [NockProbe.AC]::Run($s2, @('S-1-15-3-1'), 'curl.exe -sS -m 5 https://example.com/', 30000)
  } catch {
    $e = $_.Exception.GetBaseException(); $h = Get-BaseHResult $_
    if ($h -eq '0x80070005') {
      $verdictA = "VERDICT(a): CONTAINED - profile created, but launching into it was denied (E_ACCESSDENIED)"
    } else {
      $verdictA = "VERDICT(a): INDETERMINATE - profile created, launch failed, not a denial -> $($e.GetType().FullName) HResult=$h $($e.Message)"
    }
  }
}
if (-not $verdictA) {
  if ($curlRc -eq 0) {
    $verdictA = "VERDICT(a): ESCAPED - re-contained child with internetClient reached https://example.com/ (curl exit 0)"
  } else {
    # The re-containment itself succeeded; only the network reach failed (or the
    # host is offline). That is not containment, so it is never scored CONTAINED.
    $verdictA = "VERDICT(a): INDETERMINATE - profile created and child launched, curl exited $curlRc"
  }
}
$verdictA

# (b) WMI broker escape — the out-of-process spawn from (c). Inspect the child's
# TOKEN, not just whether it ran: a WMI child may be spawned by the broker under the
# plain user token, which would be a FULL escape of the fence.
#
# INSIDE the container ($probeRoot and $out are re-established by the _inside.ps1
# bootstrap — see the "Inside-variable bootstrap" note above):
#
# Spawn the child and hand its PID + spawn time OUT through the granted
# drop dir. Do NOT read the child's token here — if the child escaped to Medium IL,
# this Low-IL process cannot open it, so TokenSummary would THROW; a throw read
# as "contained" is the wrong-reason verdict this round removes. Keep the child
# alive long enough for the outer session to inspect it across the manual
# two-shell handoff (Start-Sleep, not `cmd /c timeout`, which needs a console
# and dies immediately when spawned via Win32_Process.Create with no stdin).
# 180s leaves ample room for the shell switch.
#
# Invoke-CimMethod returns only a ProcessId. The child's command line carries a run-unique tag (a trailing PowerShell comment)
# and the spawn time is recorded BEFORE the Create call, so the outer session can
# prove the PID it finds is this child and not a later process that reused the PID.
$childTag  = "nocklock-wmi-child-$runId"
$spawnedAt = (Get-Date).ToUniversalTime().Ticks
$p = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
  -Arguments @{CommandLine=('powershell -NoProfile -Command "Start-Sleep 180 # ' + $childTag + '"')}
# A refused spawn returns ProcessId 0, and Get-Process -Id 0 is the Idle process —
# record it distinctly so it never reaches the outer identity checks.
if ($p.ReturnValue -ne 0 -or -not $p.ProcessId) {
  Set-Content -Path (Join-Path $out.FullName 'wmi-child-pid.txt') -Value "SPAWNFAIL:$($p.ReturnValue)"
  return
}
$wmiChild = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
if ($wmiChild) {
  # Write ONLY ProcessId|spawn-ticks from inside, to a DISTINCT file. Reading
  # $wmiChild.StartTime/.Path here THROWS if the child escaped to Medium IL (a Low-IL
  # process cannot open a higher-IL one) — exactly the full-escape case 10(b) is
  # trying to catch — so a throw would be misread as INDETERMINATE. The outer
  # session below verifies the child and writes the canonical 'wmi-child.txt'
  # that teardown consumes.
  Set-Content -Path (Join-Path $out.FullName 'wmi-child-pid.txt') -Value ('{0}|{1}' -f $p.ProcessId, $spawnedAt)
} else {
  Set-Content -Path (Join-Path $out.FullName 'wmi-child-pid.txt') -Value "EXITED:$($p.ProcessId)"
}

# OUTER SESSION (on the desktop, the elevated SSH shell — see the corrected
# elevation premise): read the PID the inside session recorded, prove it is still
# the probe's child, then capture identity and inspect the token from HERE with the
# launcher's TokenSummary — a Medium- or High-IL child IS openable from the outer
# session (see the inside note above), so this discriminates the three cases.
$idFile = Join-Path $out.FullName 'wmi-child.txt'
$raw = Get-Content (Join-Path $out.FullName 'wmi-child-pid.txt')
if ($raw -like 'SPAWNFAIL:*') {
  "VERDICT(b): WMI refused the spawn (Win32_Process.Create ReturnValue $($raw -replace '^SPAWNFAIL:','')) — INDETERMINATE, not scored"
  return
}
if ($raw -like 'EXITED:*') {
  Set-Content -Path $idFile -Value $raw
  "VERDICT(b): child exited before identity capture — INDETERMINATE"
  return
}
$parts    = $raw -split '\|', 2
$childPid = [int]$parts[0]
# 1s grace for system-clock tick granularity only. The run-unique $childTag in the
# command line is what rules out a PID-reusing process: it starts after our child
# exits, so a start-time floor alone cannot reject it.
$notBefore = [long]$parts[1] - [TimeSpan]::TicksPerSecond
$childTag  = "nocklock-wmi-child-$runId"
# Three outcomes, never collapsed: OURS (tag and start time confirmed), REUSED (the
# PID provably belongs to another process, or is gone), UNREADABLE (a process at or
# after the spawn time that this outer session cannot fully read — the case where
# the child may have run above the outer session, so it must not read as a benign exit).
$state = 'REUSED'
$proc = Get-Process -Id $childPid -ErrorAction SilentlyContinue
if ($proc) {
  # Capture StartTime/Path ONCE, before the command-line read, and record exactly
  # these values: re-reading them later could pick up a process that reused the PID.
  # Each read gets its own try so one failure does not blank the others.
  $childStart = $null; $childPath = $null; $childCmd = $null
  try { $childStart = $proc.StartTime } catch { }
  try { $childPath  = $proc.Path } catch { }
  try { $childCmd   = (Get-CimInstance Win32_Process -Filter "ProcessId=$childPid" -ErrorAction Stop).CommandLine } catch { }
  if (-not $childStart) {
    $state = 'UNREADABLE'
  } elseif (($childStart.ToUniversalTime().Ticks -lt $notBefore) -or
            ($childCmd -and $childCmd -notlike "*$childTag*")) {
    $state = 'REUSED'
  } elseif (-not $childCmd -or -not $childPath) {
    $state = 'UNREADABLE'
  } else {
    $state = 'OURS'
  }
}
if ($state -ne 'OURS') {
  # Record it as exited either way, so teardown never stops whatever holds this PID
  # now (the keepalive self-exits after 180s, so nothing leaks).
  Set-Content -Path $idFile -Value "EXITED:$childPid"
}
if ($state -eq 'REUSED') {
  "VERDICT(b): PID $childPid is no longer the probe's tagged child (exited or PID reused) — INDETERMINATE, re-run with a longer keepalive"
} elseif ($state -eq 'UNREADABLE') {
  "VERDICT(b): process at PID $childPid could not be fully read from the OUTER session (StartTime/Path/CommandLine) -> INDETERMINATE, treat as possible escape above the outer session"
} else {
  Set-Content -Path $idFile -Value ('{0}|{1}|{2}' -f $childPid, $childStart.ToString('o'), $childPath)
  try {
    $tok = [NockProbe.AC]::TokenSummary($childPid)   # "AppContainer=<bool> PackageSid=<sid|-> IntegrityLevel=<sid>"
    # Re-verify AFTER reading the token: if the PID changed hands in between, the
    # token belongs to another process and must not be scored.
    $again = Get-Process -Id $childPid -ErrorAction SilentlyContinue
    if (-not $again -or $again.StartTime -ne $childStart) {
      "VERDICT(b): child $childPid exited while its token was being opened — INDETERMINATE, re-run"
    } elseif ($tok -like 'AppContainer=True *') {
      "VERDICT(b): CONTAINED - WMI child kept an AppContainer token ($tok); only the job accounting leaked"
    } else {
      # Plain user token => FULL escape of the file AND network fence; Phase 0 does not hold.
      "VERDICT(b): ESCAPED - WMI child runs outside the AppContainer ($tok)"
    }
  } catch {
    # Even the outer session could not open it (e.g. it runs as another principal).
    # This is its OWN verdict — never scored as "contained".
    "VERDICT(b): could not open child token from OUTER session -> INDETERMINATE, treat as possible escape ($($_.Exception.Message))"
  }
}
```

Every 10(a) path prints exactly one `VERDICT(a)` line: CONTAINED only for an
E_ACCESSDENIED profile-creation or launch denial; ESCAPED when the re-contained
child reaches the internet; INDETERMINATE for anything else (including a curl
that launched but failed, or a launcher that would not load inside the
container), with the error or exit code printed. Every 10(b) path likewise prints
exactly one `VERDICT(b)` line: CONTAINED, ESCAPED, or INDETERMINATE.
If (a) is ESCAPED, the network fence is escapable by construction and Phase 1
does not hold. If (b)'s WMI child carries a
non-AppContainer token, that is the more serious result: **Phase 0** does not hold
and WMI must be blocked with the child-process policy. If (b) is INDETERMINATE
(child exited early, or even the outer session cannot open it), it is reported as
its own verdict and never counted as contained. This is as important as Probe 1;
run them together.

**Teardown.** The escape container profile is removed by the global teardown below
(`$escMoniker` is assigned inside the container block, so cleanup belongs in the
outer session — same pattern as Probe 3). Kill the keepalive child by verified
identity (PID + StartTime + Path from `wmi-child.txt`). The outer session writes
that record only after proving the PID is this run's tagged child; otherwise it
writes `EXITED:<pid>`, which teardown skips — no process is ever stopped by PID
alone, and a missing or mismatched process means already gone. The `curl` child
from (a) is waited on for its exit code (its `-m 5` timeout bounds it); it is not
tracked by an identity file.

| State touched | Detail |
|---|---|
| Creates | escape container profile (`agent-escape-$runId`); WMI keepalive child process (command line tagged `nocklock-wmi-child-$runId`); `wmi-child-pid.txt` (inside PID + spawn-time handoff) and `wmi-child.txt` (outer verified identity, or `EXITED:<pid>`) in `$out` |
| Removes | keepalive child (by verified PID+StartTime+Path); escape profile (global teardown) |
| Must never touch | other running processes; the primary container profile |

### Probe 11: named pipe into the container

The event listener depends on it.

**Desktop path:** the pipe servers are in-box .NET Framework
(`NamedPipeServerStream` with a `PipeSecurity`), not NtObjectManager's
`New-NtNamedPipeFile`; the inside client is an `_inside.ps1` phase through the
launcher from the elevated shell, zero capabilities.

```powershell
# OUTSIDE (elevated shell): two run-unique pipes — one granting the package SID
# ($sid from the scaffold), one without that ACE as the negative control.
function New-ProbePipe([string]$Name, [bool]$GrantSid) {
  $ps = New-Object System.IO.Pipes.PipeSecurity
  $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule(
    [Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'Allow')))
  if ($GrantSid) {
    $ps.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule(
      (New-Object Security.Principal.SecurityIdentifier $sid), 'ReadWrite', 'Allow')))
  }
  New-Object System.IO.Pipes.NamedPipeServerStream($Name, 'In', 1, 'Byte', 'None', 0, 0, $ps)
}
$pipeGranted = New-ProbePipe "nocklock-probe-pipe-$runId" $true
$pipeNoAce   = New-ProbePipe "nocklock-probe-pipe-noace-$runId" $false

# INSIDE the container (names re-derived from $runId by the bootstrap):
# POSITIVE control first: the negative is scored only if the granted pipe connects, so
# a container-wide pipe denial can never pass as "the ACE gates access".
try {
  [System.IO.Pipes.NamedPipeClientStream]::new('.', "nocklock-probe-pipe-$runId", 'Out').Connect(5000)
  "PASS(control): granted pipe reachable"
  Assert-AccessDenied { [System.IO.Pipes.NamedPipeClientStream]::new('.', "nocklock-probe-pipe-noace-$runId", 'Out').Connect(5000) } 'pipe without the package-SID ACE'
} catch {
  "FAIL(control): granted pipe unreachable -> HResult=$(Get-BaseHResult $_); negative control NOT scored"
}
```

Confirm a package-SID-granted pipe is reachable from inside, and that one without
the ACE is not.

**Teardown.** The named pipes are in-memory kernel objects that vanish when their
server handles close: the global teardown disposes `$pipeGranted` and `$pipeNoAce`.
No on-disk state.

| State touched | Detail |
|---|---|
| Creates | two in-memory named pipes (kernel objects) held by the outer session |
| Removes | both pipe server handles (global teardown; the pipes vanish with them) |
| Must never touch | other named pipes; on-disk state |

### Global teardown and state listing

Run this last, unconditionally (wrap the whole probe run in `try { … } finally {
<teardown> }` so it runs even on failure). It removes everything the run created
and prints a before/after state listing so nothing is left behind:

```powershell
# --- BEFORE (also run this at the very start, to diff against). The scaffold has
# already recorded $baseExempt / $basePorts; the documented desktop baseline is 0 / 0.
CheckNetIsolation.exe LoopbackExempt -s
logman query -ets
netsh advfirewall show allprofiles state
Test-Path $probeRoot

# --- TEARDOWN (desktop run — no package uninstalls). Everything by EXACT name. ---
$profileNames = @($moniker, "nocklock-p3-$runId", "agent-escape-$runId")   # scaffold, Probe 3, Probe 10
if ($taskCreated) {                                        # the limited-token task: exact name, never a wildcard
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
if ($pipeGranted) { $pipeGranted.Dispose() }               # Probe 11
if ($pipeNoAce)   { $pipeNoAce.Dispose() }
CheckNetIsolation.exe LoopbackExempt -d "-n=$moniker" | Out-Null   # machine-wide exemption (Probes 1-2)
if ('NockProbe.AC' -as [type]) {                           # launcher loaded => profiles may exist
  foreach ($n in $profileNames) {                          # DeleteAppContainerProfile; HRESULT printed, never thrown
    'TEARDOWN: DeleteProfile {0} -> 0x{1:X8}' -f $n, [NockProbe.AC]::DeleteProfile($n)
  }
}
if ($etwCreated) { logman stop $etwSession -ets 2>$null }  # only if THIS run created it
# Reap spawned processes BEFORE deleting $probeRoot (identity files live there).
foreach ($idFile in (Get-ChildItem -Path $probeRoot -Filter '*.txt' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '(own-listener|wmi-child)\.txt$' })) {
  Stop-VerifiedProcess -IdentityFile $idFile.FullName
}
# Probe 9 (VM only): restore firewall to the recorded per-profile state
Remove-Item -Recurse -Force $probeRoot                     # everything else lived here

# --- AFTER: ASSERT the BEFORE baseline is restored. One line per check; any
# LEFTOVER line is a failed run, to be cleaned by hand using the name it prints.
function Assert-Restored([string]$Label, [bool]$Ok) { if ($Ok) { "RESTORED: $Label" } else { "LEFTOVER: $Label" } }
$mappings = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
$leftMaps = @(Get-ChildItem $mappings -ErrorAction SilentlyContinue |
  Where-Object { $profileNames -contains (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Moniker })
Assert-Restored "loopback exemptions back to BEFORE ($baseExempt)" ((Get-ExemptCount) -eq $baseExempt)
if ($sid) {        # unset only if the scaffold stopped before the profile existed
  Assert-Restored "this run's SID absent from LoopbackExempt -s" (-not (Test-ExemptListed))
}
Assert-Restored "ports 8899/9999/9998 back to BEFORE ($basePorts listening)" ((Get-BusyPorts) -eq $basePorts)
if ($taskName) {   # unset only if the scaffold stopped before registering the task
  Assert-Restored "scheduled task $taskName absent" (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue))
}
foreach ($n in $profileNames) {
  Assert-Restored "AppContainer profile folder $n absent" (-not (Test-Path (Join-Path $env:LOCALAPPDATA "Packages\$n")))
}
Assert-Restored "AppContainer Mappings keys for this run's monikers absent" ($leftMaps.Count -eq 0)
Assert-Restored "probe root $probeRoot absent" (-not (Test-Path $probeRoot))
logman query -ets                                          # ETW: diff by eye against BEFORE
```

On the desktop the expected AFTER is every line `RESTORED`, which restores the
documented baseline: 0 loopback exemptions and ports 8899/9999/9998 free.

Disposable-box probes (8, 9, and the disposable-box steps of 5b, 6, 7) run on a
throwaway VM. Their teardown is "discard the box" — the VM is the cleanup.

## Summary of UNVERIFIED items

| # | Claim needing verification | Blocks |
|---|---|---|
| 1 | Zero-capability container can reach loopback as a client when exempted (outbound only — inbound reachability is left UNVERIFIED, see Probe 1 scoping note) | **Phase 1 entirely** |
| 2 | Loopback exemption registration needs elevation; and whether the exemption survives a reboot (reboot durability deliberately not run this round — see Probe 2) | Phase 1 install UX |
| 3 | AppContainer launch works unelevated end to end | Phase 0 |
| 4 | Package-SID ACLs grant/deny as the intersection rule implies | Phase 0 |
| 5 | git/node/python/npm/MSVC survive a regular AppContainer | Phase 0 scope |
| 6 | Which brokered services (DNS, BITS, WinHTTP, shell handoff) answer for a zero-capability container | **Egress row's real value** |
| 7 | ETW `Microsoft-Windows-Kernel-File` subscribable unelevated | Audit row: Phase 0 vs 2 |
| 8 | winget `--scope user` / scoop install without UAC | Packaging |
| 9 | AppContainer isolation fails open when the firewall is off | Fail-closed startup check |
| 10 | Whether the agent can create its own AppContainer with `internetClient` | **Phase 1 entirely** — escape by construction |
| 11 | Package-SID-granted named pipe reachable from inside the container | Event listener |
| 12 | Whether Windows itself keeps `LOCALAPPDATA`/`TEMP` redirected when the product passes an explicit environment block (the probe launcher sets them explicitly, so the probes do not answer this) | Reconciles (a) with (d) |
| 13 | Go's AF_UNIX support on Windows (checkable on the Linux build host, not the probe box) | Event-listener transport choice |
| 14 | Whether a WMI (`Win32_Process.Create`) child inherits the AppContainer token or is spawned by the broker under the plain user token | **Phase 0** — full escape if it escapes the token |
| 15 | Whether a package SID granted recursive Modify on `filesystem.root` can rename/delete/replace an in-project `.nock/` via the parent (`FILE_DELETE_CHILD`) — why the audit DB moves to the per-user state dir | Informational — the DB moves out either way; does not gate Phase 0 |

---

## Platform matrix and CI feasibility

Two practical gaps a reader sizing this work needs, both **UNVERIFIED**:

- **Supported surface is unstated.** AppContainer is Windows 8+ and LPAC is
  Windows 10+, but NockLock needs a decided floor: minimum build, Windows 10 vs
  11, Home vs Pro (Home has no Group Policy but AppContainer does not need it),
  Server SKUs, ARM64, and S mode (which blocks unsigned binaries outright).
  Decide before Phase 0 ships, because it determines what the probe box proves.
- **CI cannot verify the no-admin claim.** GitHub's `windows-latest` runners
  execute as an administrator, so a green CI job proves the fence *works*, not
  that it works *without elevation* — which is this document's entire thesis. The
  Phase 1 escape job can run there, but the no-admin assertion needs either a
  self-hosted non-admin runner or a deliberate drop to a standard-user token
  inside the job. Worth designing at the same time as the job itself.

---

## Sources

- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [CreateAppContainerProfile](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
- [AppContainer SID constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-container-sid-constants)
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [Access control (Windows Filtering Platform)](https://learn.microsoft.com/en-us/windows/win32/fwp/access-control)
- [Troubleshooting UWP App Connectivity Issues in Windows Firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)
- [How to enable loopback and troubleshoot network isolation](https://learn.microsoft.com/en-us/previous-versions/windows/apps/hh780593(v=win.10)) *(archived, Win8-era)*
- [NetworkIsolationSetAppContainerConfig](https://learn.microsoft.com/en-us/windows/win32/api/networkisolation/nf-networkisolation-networkisolationsetappcontainerconfig)
- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [SetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [Installing Go from source (GOOS/GOARCH)](https://go.dev/doc/install/source)
- [What is Artifact Signing?](https://learn.microsoft.com/en-us/azure/artifact-signing/overview)
- [winget install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install)
