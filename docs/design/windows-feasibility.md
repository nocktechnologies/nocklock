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
intranet.) If the loopback exemption can be granted
to a zero-capability container, then the proxy is the *only* reachable socket,
and Windows lands **above macOS** on the egress row — a real default-drop floor
with a re-resolving proxy, which is the Linux netns model, not the macOS
`HTTP_PROXY` suggestion.

That single "if" is the pivot of this whole study. It is **UNVERIFIED** and is
[Probe 1](#probe-1-the-pivot--zero-capability-loopback).

The fence decomposes cleanly by what elevation it costs:

| Phase | Needs admin? | What it buys |
|---|---|---|
| **0 (MVP)** | No | Files (AppContainer + per-user ACLs), process tree (job object), `network.allow = []` as a real all-or-nothing floor, audit chain the agent cannot touch |
| **1** | One-time at install, *if [Probe 2](#probe-2-does-the-exemption-need-elevation) says so* | Loopback exemption for a fixed container moniker → selective egress through the proxy, DNS-trick resistance |
| **2** (deferred; mandatory if Probe 1 fails) | One-time, service | WFP provider with persistent filters scoped by package SID → egress floor independent of the proxy; ETW file-event stream |

Phase 0 ships standalone and is honest on its own. Crucially, the loopback
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
the answer is yes the network fence is escapable by construction.

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
| **no** | **yes** | **Only 127.0.0.1 reachable → the proxy is the sole egress path.** **UNVERIFIED** |

The bottom row is the product. The proxy runs *outside* the container as an
ordinary user process with normal network access; the agent runs *inside* with
no capabilities plus a loopback exemption. Direct egress dies on the default
block filter. The proxy re-resolves hostnames itself, exactly as the Linux
transparent proxy does.

Whether that cell exists is the pivot. The loopback documentation is written
around *enabling* loopback for apps that already have capabilities; nothing
states whether the exemption short-circuits the capability check or is
`AND`-ed with it. That is [Probe 1](#probe-1-the-pivot--zero-capability-loopback).

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
are defeated if and only if the container can open no socket except the proxy.**
All three are moot against a proxy that re-resolves names itself, so that
property is assumed once here rather than repeated per row.

| Trick | Windows outcome |
|---|---|
| Agent runs its own resolver query (UDP/53 or DoH) | **Defeated.** Every off-box address is dropped by the default block filter; under the Phase 1 design the only socket that opens at all is to 127.0.0.1, where only our proxy listens. Same mechanism as the Linux netns drop. Probe 1 must confirm the exemption does not also let the agent bind its own loopback resolver. |
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

**One documented hole:** "Child processes created using **Win32_Process.Create**
are not associated with the job" (SOURCED, same page). An agent that shells out
via WMI escapes the job. It does *not* escape the AppContainer — the token is
inherited regardless — so files and network stay fenced; only the job's
accounting and kill-on-close leak. Worth an event, not a redesign.

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

Windows adds a further, independent layer for free. The AppContainer intersection
rule means the child **cannot write `.nock/` unless we add an ACE for its package
SID** — and we simply won't. On Linux the filesystem fence already denies the
audit directory for the default `.nock/events.db` location; on Windows the denial
is a token property the agent cannot shed, and it holds without configuring a
path rule at all. An additional barrier on an already-signed chain, not a fix for
a gap.

Concretely: ACL `.nock/` to the user only, grant the package SID nothing, and the
child's writes fail at the kernel. **UNVERIFIED** in the trivial sense that it
follows from the intersection rule rather than a dedicated doc —
[Probe 4](#probe-4-acl-grant-and-the-deny-default) covers it.

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
| **Network egress floor** | **Opt-in** netns + nftables default-drop; needs the privileged egress helper | **None** — proxy is an env var, bypassable | WFP default-block on a zero-capability AppContainer; only the loopback proxy reachable. *Phase 0: all-or-nothing deny* |
| **DNS-trick resistance** | Yes, in netns mode — no direct socket; `resolv.conf`/`hosts` root-owned and the child is non-root | **No** — all three tricks work | Yes *pending [Probe 6](#probe-6-brokered-egress--which-services-answer-for-us)* — no direct socket; hosts file needs admin. *Phase 0: n/a (no network at all)* |
| **Syscall limits** | seccomp allowlist | Opt-in `filesystem.hardened` bundle — approximation, not an allowlist | **—** — win32k/FSCTL lockdown + child-process policy only; same category as the macOS bundle |
| **Audit** | SHA-256 chain + Ed25519 signatures + anchor; interposer file events | Same chain, no file events | Same chain, plus **tamper-resistance by token** (agent cannot write `.nock/` at all); **no file-event stream** (ETW is Phase 2) |
| **Process tree** | `Setpgid` + `Pdeathsig: SIGKILL` | process group | Job object, kill-on-close across the hierarchy, no breakaway (WMI-spawned children escape the job, not the fence) |

---

## Phased plan and sizing

**Phase 0 — MVP, zero admin (~4–5 PR rounds)**
1. `internal/fence/windows/appcontainer`: profile create/derive, capability
    construction, `STARTUPINFOEX` launch. (1–2 rounds)
2. ACL application: package-SID ACEs for `filesystem.root`, `filesystem.allow`,
    and the toolchain cache dirs; `.nock/` deliberately ungranted. (1 round)
3. Job object: kill-on-close, no breakaway, active-process cap. (1 round)
4. `network.allow = []` wired to "launch with zero capabilities"; secret fence
    env plumbing; `nocklock status` reports the Windows backend honestly. (1 round)

**Phase 1 — selective egress (~2–3 PR rounds)**, gated on Probe 1
5. Fixed moniker + loopback exemption registration at `nocklock init`
    (elevating once if Probe 2 says so); proxy on loopback; fail-closed if the
    exemption is absent. (1–2 rounds)
6. CI escape job mirroring PR #124's macOS DNS-escape test, asserting the
    Windows container *cannot* reach a non-allowlisted address directly. (1 round)

**Phase 2 — deferred, elevated (~3–4 PR rounds)** — becomes mandatory if Probe 1 fails or Risk 2 materialises
7. WFP provider + persistent filters scoped by package SID; ETW file events.

Total to a shippable Windows fence at Phase 1 parity: **~6–8 PR rounds**
(Phase 0's 4–5 plus Phase 1's 2–3), gated on Probe 1 as noted above.

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
   provider as the durable answer rather than an optional extra, and fail closed
   with a clear error if the exemption stops working.
3. **AppContainer breaks the toolchain badly enough that users disable the
   fence.** The `LOCALAPPDATA`/`TEMP` redirection is certain; what it does to
   npm/pip/cargo/MSVC in practice is not. A fence users turn off protects
   nothing. *Mitigation:* Probe 5 early, and budget the cache-directory ACL work
   into Phase 0 rather than discovering it in Phase 1.

**4. The whole floor may be fail-open.** The AppContainer block filters are owned
by the Windows Firewall service (`FWPM_PROVIDER_MPSSVC_WSH`). If a user disables
the firewall, the isolation filters may go with it — a fail-open we would not
detect. **UNVERIFIED.**
[Probe 9](#probe-9-fail-open-with-the-firewall-off) settles it; if it fails open,
NockLock must check firewall state at launch and refuse to start.

---

## Probes to run on a real Windows box

Run as a **standard (non-admin) user** unless a step says elevated. Nothing here
runs on the Linux build host. Suggested scratch dir `C:\probe`, moniker
`nocklock-probe`.

Follow the house convention in [`docs/probes/n10753/`](../probes/n10753/): commit
a `docs/probes/n10825/run-probe.ps1` plus an `output.txt` carrying environment
stamps (`[Environment]::OSVersion`, build number, edition, architecture, and
whether the session is elevated).

**Box setup**, once:

```powershell
winget install --id Git.Git --scope user
winget install --id OpenJS.NodeJS.LTS --scope user
winget install --id Python.Python.3.12 --scope user
# MSVC only if testing compilers: Visual Studio Build Tools (needs admin)
[Environment]::OSVersion.Version; (Get-ComputerInfo).WindowsProductName
```

**Elevation over SSH.** OpenSSH on Windows gives a non-elevated shell, and `runas`
cannot accept a password on stdin. For the steps marked ELEVATED, either (a) run
the OpenSSH service as `LocalSystem` and use `psexec -s -i`, (b) pre-create a
Scheduled Task registered to run with highest privileges and trigger it with
`schtasks /Run`, or (c) have Kevin approve the UAC prompt interactively at the
console. Option (b) is the one to script.

**Launcher prerequisite (probes 1, 3, 4, 5, 6, 9, 10).** These need a tool that
creates an AppContainer profile with a chosen capability set and runs a command
in it. Do **not** write one from scratch — use James Forshaw's
[NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager)
PowerShell module, which exposes this directly and installs per-user:

```powershell
Install-Module NtObjectManager -Scope CurrentUser
$sid = Get-NtSid -PackageName 'nocklock-probe'
$sid.ToString()   # record this; the icacls probes need it
# zero-capability container:
New-Win32Process -CommandLine 'cmd.exe' -AppContainerSid $sid
# with a capability, for the contrast case:
New-Win32Process -CommandLine 'cmd.exe' -AppContainerSid $sid `
  -Capabilities (Get-NtSid -KnownSid CapabilityInternetClient)
```

If the module is unavailable, a ~60-line C P/Invoke following the launch sequence
in [(a)](#a-filesystem-confinement-for-a-child-process-tree) is the fallback.
Either way it is throwaway probe scaffolding, not product code.

### Probe 1: the pivot — zero-capability loopback

**Question:** can a container with *no* capabilities reach `127.0.0.1` once
loopback-exempted, and *only* our proxy? This subsumes the elevation question,
so run it before Probe 2's persistence checks.

```powershell
# terminal A - a listener OUTSIDE any container
python -m http.server 8899 --bind 127.0.0.1

# terminal B - register the exemption NON-ELEVATED first and record the result
CheckNetIsolation.exe LoopbackExempt -a -n=nocklock-probe; "exit=$LASTEXITCODE"
CheckNetIsolation.exe LoopbackExempt -s      # did the entry actually appear?
# if it did not, repeat the -a in an ELEVATED shell and note that Probe 2 = "admin required"

# then, inside a ZERO-capability container:
curl.exe -sS -m 5 http://127.0.0.1:8899/   # MUST succeed, or Phase 1 is dead
curl.exe -sS -m 5 https://example.com/     # MUST fail (Block Outbound Default Rule)
curl.exe -sS -m 5 http://127.0.0.1:9999/   # unrelated loopback port: note reachable or not
python -m http.server 9998 --bind 127.0.0.1  # can the agent BIND its own loopback listener?
```

All of the first two must hold. The last two matter for the DNS row: if the
exemption opens *all* of loopback rather than just our proxy, an agent can stand
up its own resolver or relay on 127.0.0.1 and talk to it. Report each separately.

If the first `curl` fails, the recommendation's Phase 1 is dead and Phase 2
becomes mandatory — report immediately, do not run the rest.

### Probe 2: does the exemption need elevation?

Probe 1 already records the non-elevated exit code. This probe covers durability:

```powershell
CheckNetIsolation.exe LoopbackExempt -s      # before reboot
Restart-Computer
CheckNetIsolation.exe LoopbackExempt -s      # after reboot: entry still present?
```

Report the non-elevated exit code from Probe 1, whether `-s` listed the entry,
and whether it survived the reboot. ("Survives a Windows Update" is an
observation to make over time, not a command to run.)

### Probe 3: AppContainer launch unelevated

```cmd
whoami /groups | findstr /i "High Mandatory"   :: expect NO match (not elevated)
:: run the launcher; then inside the container:
whoami /all
```

Confirm the token shows an AppContainer SID and Low integrity, from a
non-elevated parent.

### Probe 4: ACL grant and the deny-default

Covers the plain grant/deny, the ALL APPLICATION PACKAGES read hole, and ACE
inheritance leaking into the audit directory.

```powershell
mkdir C:\probe\project, C:\probe\.nock, C:\probe\other-project
"secret" > $env:USERPROFILE\.ssh\id_rsa     # create the target the fence must deny
$sid = (Get-NtSid -PackageName 'nocklock-probe').ToString()

icacls C:\probe\project /grant "*${sid}:(OI)(CI)(M)"
# inheritance check: does the (OI)(CI) grant above reach a .nock INSIDE the root?
mkdir C:\probe\project\.nock
icacls C:\probe\project\.nock            # inspect: inherited ACE present?
icacls C:\probe\project\.nock /inheritance:r /remove "*${sid}"

# from INSIDE the container:
echo ok  > C:\probe\project\write-test.txt        # MUST succeed
echo bad > C:\probe\project\.nock\tamper.txt      # MUST fail (audit tamper-resistance)
echo bad > C:\probe\other-project\leak.txt        # MUST fail (cross-project isolation)
type $env:USERPROFILE\.ssh\id_rsa                 # MUST fail
type C:\Windows\System32\drivers\etc\hosts        # EXPECTED TO SUCCEED - the ALL
                                                  # APPLICATION PACKAGES read hole
```

The last line is the point: confirm the size of the standing read hole on system
paths, and confirm an explicit DENY ACE closes it where NockLock needs it to.

### Probe 5: toolchain survival

Run with the proxy from Probe 1 still listening on 127.0.0.1:8899 and
`HTTPS_PROXY` pointed at it, so the network-dependent steps have a path out.

```powershell
# inside the container
git --version; git init C:\probe\project\repo; git -C C:\probe\project\repo status
$env:HTTPS_PROXY = 'http://127.0.0.1:8899'
git clone https://github.com/octocat/Hello-World.git C:\probe\project\hw
node -e "console.log(JSON.stringify(process.env).slice(0,400))"
npm --version; npm install --prefer-offline lodash
python -c "import sys; print(sys.prefix)"
pip install --user requests
cl.exe /? 2>&1 | Select-Object -First 3      # only if Build Tools installed
```

Record which fail, and whether failures are ACL-related (fixable with a grant) or
architectural (COM / named pipe / Low IL). Explicitly note **where npm and pip
actually wrote their caches**, and whether the cache-directory variables are
still redirected when the launcher passes an explicit environment block —
section (a) assumes the redirection happens and section (d) passes an explicit
environment, and those two have not been reconciled against a real run.

### Probe 6: brokered egress — which services answer for us?

Generalises the DNS question to the whole confused-deputy class. All from inside
a **zero-capability** container, with no loopback exemption:

```powershell
nslookup example.com                                   # DNS Client service
Resolve-DnsName example.com
Start-BitsTransfer -Source https://example.com/ -Destination C:\probe\bits.out
Invoke-WebRequest https://example.com/ -UseBasicParsing
Start-Process "https://example.com/"                   # shell handoff to a browser
curl.exe -sS -m 5 https://example.com/                 # control: MUST fail
```

Any of these succeeding means a service outside the container performed network
on the agent's behalf and WFP classified *that service's* traffic, not ours. Each
success is a bypass of the egress floor and must be listed. If DNS resolves while
the direct connection fails, note it specifically: egress is still fenced, but
queried names leak and DNS never reaches the proxy's allowlist.

### Probe 7: ETW file events unelevated

```powershell
logman create trace nocklock-fileprobe -p Microsoft-Windows-Kernel-File -o C:\probe\f.etl -ets
logman stop nocklock-fileprobe -ets
```

Run non-elevated first. If it fails, retry after adding the user to
*Performance Log Users*, then elevated. This decides whether file-event logging
is Phase 0 or Phase 2.

### Probe 8: packaging no-admin

```cmd
winget install --id Git.Git --scope user
scoop install ripgrep
where nocklock
```

Confirm both complete with no UAC prompt and land under the user profile.

### Probe 9: fail-open with the firewall off

```cmd
:: ELEVATED, on a throwaway box only
netsh advfirewall set allprofiles state off
:: from inside a ZERO-capability container:
curl.exe -sS -m 5 https://example.com/      :: does it now SUCCEED?
netsh advfirewall set allprofiles state on
```

Also capture the actual drop filter for the record:

```cmd
netsh wfp capture start keywords=19
:: reproduce a blocked connection from inside the container
netsh wfp capture stop
:: inspect wfpdiag.xml for FWPM_NET_EVENT_TYPE_CLASSIFY_DROP and the filter name
```

If traffic flows with the firewall off, NockLock must verify firewall state at
launch and refuse to start — a fence that silently disappears is worse than no
fence.

---

### Probe 10: container escape — can the agent re-container itself?

The escape question. From inside a **zero-capability** container:

```powershell
Install-Module NtObjectManager -Scope CurrentUser   # does this even work in here?
$s2 = Get-NtSid -PackageName 'agent-escape'
New-Win32Process -CommandLine 'curl.exe -sS -m 5 https://example.com/' `
  -AppContainerSid $s2 -Capabilities (Get-NtSid -KnownSid CapabilityInternetClient)

# and the job-object escape the doc already flags:
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
  -Arguments @{CommandLine='cmd.exe /c curl.exe -sS -m 5 https://example.com/'}
# inspect the spawned process token: AppContainer SID present? job assigned?
```

If either spawns a process that reaches the internet, the network fence is
escapable by construction and Phase 1 does not hold. This is as important as
Probe 1; run them together.

### Probe 11: named pipe into the container

The event listener depends on it.

```powershell
# OUTSIDE: create a pipe whose ACL grants the package SID
$sid = (Get-NtSid -PackageName 'nocklock-probe').ToString()
# (NtObjectManager: New-NtNamedPipeFile with an explicit SD granting $sid write)

# INSIDE the container:
[System.IO.Pipes.NamedPipeClientStream]::new('.','nocklock-probe-pipe','Out').Connect(5000)
```

Confirm a package-SID-granted pipe is reachable from inside, and that one without
the ACE is not.

## Summary of UNVERIFIED items

| # | Claim needing verification | Blocks |
|---|---|---|
| 1 | Zero-capability container can reach loopback when exempted | **Phase 1 entirely** |
| 2 | Loopback exemption registration needs elevation | Phase 1 install UX |
| 3 | AppContainer launch works unelevated end to end | Phase 0 |
| 4 | Package-SID ACLs grant/deny as the intersection rule implies | Phase 0 |
| 5 | git/node/python/npm/MSVC survive a regular AppContainer | Phase 0 scope |
| 6 | Which brokered services (DNS, BITS, WinHTTP, shell handoff) answer for a zero-capability container | **Egress row's real value** |
| 7 | ETW `Microsoft-Windows-Kernel-File` subscribable unelevated | Audit row: Phase 0 vs 2 |
| 8 | winget `--scope user` / scoop install without UAC | Packaging |
| 9 | AppContainer isolation fails open when the firewall is off | Fail-closed startup check |
| 10 | Whether the agent can create its own AppContainer with `internetClient` | **Phase 1 entirely** — escape by construction |
| 11 | Package-SID-granted named pipe reachable from inside the container | Event listener |
| 12 | Whether `LOCALAPPDATA`/`TEMP` stay redirected when an explicit environment block is passed | Reconciles (a) with (d) |
| 13 | Go's AF_UNIX support on Windows (checkable on the Linux build host, not the probe box) | Event-listener transport choice |

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
