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
proxy.** An AppContainer with no `internetClient` capability is dropped by WFP's
"Block Outbound Default Rule" on every outbound packet, at the same kernel choke
point Windows uses for UWP isolation. If the loopback exemption can be granted
to a zero-capability container, then the proxy is the *only* reachable socket,
and Windows lands **above macOS** on the egress row — a real default-drop floor
with a re-resolving proxy, which is the Linux netns model, not the macOS
`HTTP_PROXY` suggestion.

That single "if" is the pivot of this whole study. It is **UNVERIFIED** and is
[Probe 1](#probe-1-the-pivot--zero-capability-loopback).

The fence decomposes cleanly by what elevation it costs:

| Phase | Needs admin? | What it buys |
|---|---|---|
| **0 (MVP)** | No | Files (AppContainer + per-user ACLs), process tree (job object), `network = "deny"` as a real all-or-nothing floor, audit chain the agent cannot touch |
| **1** | One-time, at install | Loopback exemption for a fixed container moniker → selective egress through the proxy, DNS-trick resistance |
| **2** (optional) | One-time, service | WFP provider with persistent filters scoped by package SID → egress floor independent of the proxy; ETW file-event stream |

Phase 0 ships standalone and is honest on its own. Crucially, the loopback
exemption in Phase 1 is keyed to a **container moniker**, and NockLock can pick
a fixed one (`nocklock-fence`) — so even if it turns out to need elevation, it
is genuinely one-time at `nocklock init`, never per-session, never per-project.
That is what lets this be one recommendation instead of a menu.

### Why not the alternatives

- **LPAC instead of AppContainer.** LPAC needs explicit capabilities even to
  read the registry or use COM (SOURCED). Agent toolchains — git, node, python,
  MSVC — will not survive that. Use a regular AppContainer, which already has
  read/execute on system directories.
- **An LD_PRELOAD analog.** There isn't one worth having. `AppInit_DLLs` needs
  admin and is disabled under Secure Boot; Detours-style injection is not a
  security boundary. This has a real consequence for the audit row — see
  [(d)](#d-secret-fence-and-the-audit-chain).
- **A kernel minifilter driver.** Requires a signed driver and elevated install.
  Out of scope; it is what Phase 2 stops short of.

---

## Background: the floor on each platform today

| | Linux (today) | macOS (today) | Windows (this study) |
|---|---|---|---|
| Files | Landlock kernel allowlist | Seatbelt / `sandbox-exec` | AppContainer token + DACLs |
| Egress | netns + nftables default-drop + transparent proxy | `HTTP_PROXY` env var only | *this document* |
| Syscalls | seccomp | — | — (no analog; see [(c)](#c-processsyscall-ish-limits)) |

macOS is the cautionary tale: NockLock's SBPL profile carries no network rules,
so a client that ignores `HTTP_PROXY` reaches any address. PR #124's macOS
DNS-escape CI job proves it. The Windows design must not reproduce that shape,
and the AppContainer capability model is what makes it possible not to.

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
must grant its package SID. Nothing on a normal disk grants an ad-hoc package
SID. So the default is deny, and NockLock opens holes by adding one ACE per
allowed path — which a non-admin user can do on any path they own.

AppContainers also run at **Low integrity level** (SOURCED, same page), which
independently blocks writes to medium-IL objects.

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
per-user. **UNVERIFIED** only in the trivial sense that nothing states "works
unelevated" in so many words — [Probe 3](#probe-3-appcontainer-launch-unelevated)
settles it in one command.

Granting the project directory is `icacls` with the package SID; the user
already owns the directory, so no elevation. **UNVERIFIED**,
[Probe 4](#probe-4-acl-grant-and-the-deny-default).

### Restricted tokens and job objects (the adjuncts)

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

`OPEN` lets a standard user open a BFE session and *read*; it does not let them
add a filter. **A standard user cannot install WFP filters.** That is the hard
boundary, and it is what makes Phase 2 an elevated phase.

### The 2×2 that decides the design

| `internetClient`? | loopback exempt? | Result |
|---|---|---|
| no | no | No network at all. Blunt but real floor. **SOURCED** |
| yes | no | Unrestricted egress *and* the proxy is unreachable. Worst cell. **SOURCED** |
| yes | yes | Proxy reachable, but the agent can bypass it. Useless without WFP. **SOURCED** |
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
> "**Note** Loopback is permitted only for development purposes."

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

| Trick | Windows outcome |
|---|---|
| Agent runs its own resolver query (UDP/53 or DoH) | **Defeated.** Needs a socket that classifies against the default block filter. No capability, no socket. Same mechanism as the Linux netns drop. |
| Pins `C:\Windows\System32\drivers\etc\hosts` | **Defeated twice over.** That path is under `%SystemRoot%\System32`; an unprivileged agent cannot write it (and inside a Low-IL AppContainer, doubly not). And NockLock's proxy re-resolves names itself, so a hosts pin would not steer it anyway. |
| Changes resolver configuration | **Defeated.** Interface DNS settings are machine state requiring admin; per-process resolver override doesn't exist. Again moot against a re-resolving proxy. |

This is strictly better than macOS today, where all three work because nothing
stops a client from ignoring `HTTP_PROXY`. It matches Linux in outcome, by a
different mechanism.

One genuine unknown: Windows resolves DNS through the **DNS Client service**
(`dnscache`) over RPC, not by the app opening a socket. If `dnscache` answers on
behalf of a zero-capability container, the agent gets name resolution even with
no network — harmless for egress (it still cannot connect) but it would leak
*which* names the agent is interested in, and would mean DNS never reaches our
proxy's allowlist. **UNVERIFIED**, [Probe 6](#probe-6-dns-through-dnscache).

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
  memory/CPU caps via `JOBOBJECT_BASIC_LIMIT_INFORMATION` /
  `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
- Nested jobs since Windows 8.

— all **SOURCED**, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus no-breakaway is a better cleanup story
than anything NockLock has on Linux: if `nocklock` dies, the whole agent tree
dies with it, enforced by the kernel.

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
compilers — but it is available for a future `exec = "deny"` mode, and it only
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
a hardening bundle, not a syscall fence. **The per-platform table must say "—"
for Windows syscalls, not "partial."**

---

## (d) Secret fence and the audit chain

### Secret fence: portable as-is

The secret fence filters the child's environment block. `CreateProcess` takes an
explicit environment pointer; there is no platform obstacle. The one Windows
nuance is that environment variable names are case-insensitive, so the allowlist
match must be case-folded. No admin. No design change.

### Audit chain: better than Linux and macOS by default

Here Windows is a genuine win. The AppContainer intersection rule means the child
**cannot write `.nock/` unless we add an ACE for its package SID** — and we
simply won't. On Linux and macOS the agent runs as the same uid as the fence and
tamper-resistance depends on path rules; on Windows it is a token property the
agent cannot shed. The Ed25519 chain is harder to tamper with on Windows than on
either existing platform, for free.

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
  builds cross-compile cleanly from the Linux CI runners. Note the current
  Linux filesystem fence ships a **C interposer**, which does not cross-compile
  and is not needed on Windows — the Windows backend is pure Go over Win32, so
  the build stays CGO-free.
- **Signing.** Authenticode via **Azure Artifact Signing** (the renamed Trusted
  Signing): "Microsoft fully managed, end-to-end signing solution," with
  "zero-touch certificate lifecycle management inside FIPS 140-3 level 3
  certified HSMs" and content-confidential digest signing where "Your file never
  leaves your endpoint." Basic and Premium SKUs — **SOURCED**,
  [What is Artifact Signing?](https://learn.microsoft.com/en-us/azure/artifact-signing/overview).
  This avoids buying and custodying an EV hardware token. Identity validation is
  required before issuance; budget lead time. Unsigned binaries will draw
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
| **Network egress floor** | netns + nftables default-drop | **None** — proxy is an env var, bypassable | WFP default-block on a zero-capability AppContainer; only the loopback proxy reachable. *Phase 0: all-or-nothing deny* |
| **DNS-trick resistance** | Yes — proxy re-resolves, no direct socket | **No** — all three tricks work | Yes — no socket to resolve with; hosts file needs admin; proxy re-resolves. *Phase 0: n/a (no network at all)* |
| **Syscall limits** | seccomp allowlist | — | **—** (no analog; win32k/FSCTL lockdown + child-process policy only) |
| **Audit** | Ed25519 chain + interposer file events | Ed25519 chain, no file events | Ed25519 chain, **tamper-resistant by token** (agent cannot write `.nock/`); **no file-event stream** (ETW is Phase 2) |
| **Process tree** | cgroup/pid | process group | Job object, kill-on-close, no breakaway (WMI-spawned children escape the job, not the fence) |

---

## Phased plan and sizing

**Phase 0 — MVP, zero admin (~4–5 PR rounds)**
1. `internal/fence/windows/appcontainer`: profile create/derive, capability
    construction, `STARTUPINFOEX` launch. (1–2 rounds)
2. ACL application: package-SID ACEs for `filesystem.root`, `filesystem.allow`,
    and the toolchain cache dirs; `.nock/` deliberately ungranted. (1 round)
3. Job object: kill-on-close, no breakaway, active-process cap. (1 round)
4. `network = "deny"` wired to "launch with zero capabilities"; secret fence
    env plumbing; `nocklock status` reports the Windows backend honestly. (1 round)

**Phase 1 — selective egress (~2–3 PR rounds)**, gated on Probe 1
5. Fixed moniker + loopback exemption registration at `nocklock init`
    (elevating once if Probe 2 says so); proxy on loopback; fail-closed if the
    exemption is absent. (1–2 rounds)
6. CI escape job mirroring PR #124's macOS DNS-escape test, asserting the
    Windows container *cannot* reach a non-allowlisted address directly. (1 round)

**Phase 2 — optional, elevated (~3–4 PR rounds)**
7. WFP provider + persistent filters scoped by package SID; ETW file events.

Total to a shippable Windows fence at Phase 1 parity: **~7–8 PR rounds**, with
Probe 1 as a hard gate before any of Phase 1 is written.

---

## Top 3 risks

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

A fourth worth watching: the AppContainer block filters are owned by the Windows
Firewall service (`FWPM_PROVIDER_MPSSVC_WSH`). If a user disables the firewall,
the isolation filters may go with it — a **fail-open** we would not detect.
[Probe 9](#probe-9-fail-open-with-the-firewall-off) settles it; if it fails open,
NockLock must check firewall state at launch and refuse to start.

---

## Probes to run on a real Windows box

Run as a **standard (non-admin) user** unless a step says elevated. Nothing here
runs on the Linux build host. Suggested scratch dir `C:\probe`, moniker
`nocklock-probe`.

Prerequisite for probes 1–6: a tiny launcher that creates an AppContainer with a
chosen capability set and runs a command. Ship it as a throwaway; it is not
product code.

### Probe 1: the pivot — zero-capability loopback

**Question:** can a container with *no* capabilities reach `127.0.0.1` once
loopback-exempted?

```cmd
:: terminal A - a listener OUTSIDE any container
python -m http.server 8899 --bind 127.0.0.1

:: terminal B
CheckNetIsolation.exe LoopbackExempt -a -n=nocklock-probe
CheckNetIsolation.exe LoopbackExempt -s

:: launch with ZERO capabilities, then from inside:
curl.exe -sS -m 5 http://127.0.0.1:8899/    :: MUST succeed for the design to work
curl.exe -sS -m 5 https://example.com/      :: MUST fail (Block Outbound Default Rule)
```

Both conditions must hold. If the first fails, the recommendation's Phase 1 is
dead and Phase 2 becomes mandatory — report immediately.

### Probe 2: does the exemption need elevation?

```cmd
:: non-elevated
CheckNetIsolation.exe LoopbackExempt -a -n=nocklock-probe
echo exit=%ERRORLEVEL%
CheckNetIsolation.exe LoopbackExempt -s

:: then repeat in an ELEVATED prompt and compare
```

Also check persistence across reboot, and whether the list survives a Windows
Update. Report the exit code and whether `-s` actually lists the entry.

### Probe 3: AppContainer launch unelevated

```cmd
whoami /groups | findstr /i "High Mandatory"   :: expect NO match (not elevated)
:: run the launcher; then inside the container:
whoami /all
```

Confirm the token shows an AppContainer SID and Low integrity, from a
non-elevated parent.

### Probe 4: ACL grant and the deny-default

```cmd
:: derive the package SID (launcher prints it), then:
icacls C:\probe\project /grant "*S-1-15-2-<...>":(OI)(CI)(M)
icacls C:\probe\.nock   /remove "*S-1-15-2-<...>"

:: from inside the container:
echo ok  > C:\probe\project\write-test.txt   :: MUST succeed
echo bad > C:\probe\.nock\tamper.txt         :: MUST fail (audit tamper-resistance)
type %USERPROFILE%\.ssh\id_rsa               :: MUST fail
```

### Probe 5: toolchain survival

```cmd
:: inside the container
git --version && git status && git clone https://github.com/... (via proxy)
node -e "console.log(process.env.LOCALAPPDATA, process.env.TEMP)"
npm install --prefer-offline
python -c "import sys; print(sys.prefix)"
pip install --user requests
cl.exe /? 2>&1 | more
```

Record which fail, and whether failures are ACL-related (fixable with a grant)
or architectural (COM/named-pipe/Low-IL). Explicitly note where npm/pip write
their caches given the redirected `LOCALAPPDATA`.

### Probe 6: DNS through dnscache

```cmd
:: inside a ZERO-capability container
nslookup example.com
powershell -c "Resolve-DnsName example.com"
curl.exe -sS -m 5 https://example.com/
```

If resolution succeeds while the connection fails, `dnscache` is answering
outside the capability check. Note it — egress is still fenced, but DNS bypasses
the proxy allowlist and leaks queried names.

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
winget install --id <pkg> --scope user
scoop install <pkg>
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

## Summary of UNVERIFIED items

| # | Claim needing verification | Blocks |
|---|---|---|
| 1 | Zero-capability container can reach loopback when exempted | **Phase 1 entirely** |
| 2 | Loopback exemption registration needs elevation | Phase 1 install UX |
| 3 | AppContainer launch works unelevated end to end | Phase 0 |
| 4 | Package-SID ACLs grant/deny as the intersection rule implies | Phase 0 |
| 5 | git/node/python/npm/MSVC survive a regular AppContainer | Phase 0 scope |
| 6 | DNS resolves via `dnscache` for a zero-capability container | DNS allowlist completeness |
| 7 | ETW `Microsoft-Windows-Kernel-File` subscribable unelevated | Audit row: Phase 0 vs 2 |
| 8 | winget `--scope user` / scoop install without UAC | Packaging |
| 9 | AppContainer isolation fails open when the firewall is off | Fail-closed startup check |

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
