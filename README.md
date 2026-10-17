# NockLock™

Fence, not guardrails. Sandbox your AI agents without changing how they work.

NockLock puts a fence around your AI coding agent. It controls which secrets the agent can see, which files it can touch, and which domains it can reach. Inside the fence, the agent runs with full permissions. The enforced boundary depends on the platform and configuration; the limits are described below.

See the [setup guide](docs/setup.md), [CLI reference](docs/reference/cli.md), or [documentation index](docs/README.md).

## Why NockLock

Your AI agent runs with full shell access to your environment, your filesystem, and your network. NockLock leaves the way your agent works alone and controls what it can reach.

The default secret fence filters environment variables: your agent sees `PATH` and `HOME`, while `AWS_SECRET_ACCESS_KEY` is removed. Runtime presets pass only their configured provider credentials.

The filesystem fence is built differently on each platform. Linux uses a kernel root allowlist (Landlock) with LD_PRELOAD event logging. macOS uses kernel Seatbelt (`sandbox-exec`) to confine writes to `filesystem.root` plus required runtime paths, and it denies credential and sensitive paths such as `~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, and `~/Library/Keychains` for both reads and writes.

The default network policy uses a proxy with a domain allowlist. With the default fences enabled, macOS Seatbelt blocks connections that bypass the proxy, and Linux syscall confinement blocks direct IP socket creation. Linux `CONFINED` still permits other Unix sockets below Landlock ABI 9; `doctor` reports this as `PARTIAL`. In `ADVISORY` mode, a client can bypass the proxy by ignoring `HTTP_PROXY`. On Linux, `nocklock wrap --net-fence=netns` instead uses a network namespace with an nftables default-drop floor and a transparent HTTP(S) and DNS allowlist. See [egress levels and limits](#what-network-fence-active-means).

## Quick start

On macOS, install with Homebrew and initialize your project with the preset for your agent. This example uses Claude Code; see the credential step below before launching it. Linux users should first follow the [source installation steps](docs/setup.md#1-install).

```bash
brew install nocktechnologies/tap/nocklock
cd your-project
nocklock init --runtime claude-code
```

On a new project, `init` writes `.nock/config.toml`. On macOS that is the whole install. On Linux the Homebrew formula installs only the `nocklock` binary, and the default config's `wrap` refuses to start without `libfence_fs.so`. Until packaging lands (N11643, `docs/ROADMAP.md` bar 3), install from source: run `make build-all` as your user, then `sudo install -m 0755 nocklock /usr/local/bin/nocklock`, then copy `libfence_fs.so` to `/usr/local/lib/nocklock/` by hand (steps in `docs/setup.md`).

**macOS and Claude Code:** Claude Code keeps a `claude.ai` login in the macOS login keychain, and the fence denies `~/Library/Keychains` (Seatbelt cannot scope to one keychain item, so NockLock does not open it). The login has to arrive through the environment, and the default secret fence blocks `*_TOKEN*`, so plain `nocklock init` strips an exported `CLAUDE_CODE_OAUTH_TOKEN`. Use the `claude-code` preset:

```bash
claude setup-token
export CLAUDE_CODE_OAUTH_TOKEN="paste-token-here"   # or set ANTHROPIC_API_KEY
nocklock wrap -- claude
```

`wrap` resolves a bare command such as `claude` using the caller's `PATH` before adding fence helpers. It refuses implicit current-directory lookup; use `./tool` for an intentional relative executable. The selected path becomes argv[0], and subsequent arguments are passed unchanged. Missing or non-executable commands exit 1 with a `resolve command` error.

The `claude-code` preset passes both variables through the secret fence. If `.nock/config.toml` already exists, `init` refuses to overwrite it: run `nocklock init --runtime claude-code --diff`, review the changes, and edit the existing config. With a custom config, remove the matching pattern from `secrets.block` (for example `*_TOKEN*`) and add the exact name to `secrets.pass`; block outranks pass, so adding to pass alone does not work. If `wrap` sees `claude` on macOS with neither variable reaching the child, it prints a one-line hint (stripped by the fence, or unset so run `claude setup-token`; never the value) and still launches. Claude Code's `--bare` mode does not read `CLAUDE_CODE_OAUTH_TOKEN`; use `ANTHROPIC_API_KEY` there.

On Linux, the generic config (`nocklock init` without a preset) grants read-only access to binaries and libraries, plus
`/etc/ld.so.cache` (loader cache), `passwd` and `group` (identity lookup),
`nsswitch.conf`, `hosts`, and `resolv.conf` (name resolution), `localtime`
(timezone), and public CA trust in the Debian/Alpine (`/etc/ssl/certs/`)
and RHEL/Fedora (`/etc/pki/tls/certs/`, `/etc/pki/ca-trust/extracted/`)
layouts. They do not grant all of
`/etc/`: files such as `/etc/environment` and TLS private keys stay outside
the default allowlist. Loader configuration (`ld.so.conf*`), CA maintenance
configuration, and alternatives directories are not needed by these runtime
checks; symlinks into the allowed binary/library trees already resolve. Missing
optional paths are skipped. Add distro-specific runtime files explicitly if needed.

On macOS, `nocklock init` writes the same default `filesystem.root = "."`, and `nocklock wrap` enforces it as a kernel Seatbelt write boundary. Writes outside the root, `.nock`, and essential per-user runtime paths are denied. The built-in credential and sensitive paths (`~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/Library/Keychains`, plus your `filesystem.deny` paths) are denied for reads and writes. Reads outside the root are not confined, and `filesystem.allow` and `filesystem.allow_rw` are not enforced on macOS. `filesystem.mode = "read-only"` is enforced: it drops the write allow for the root. See "Filesystem platform boundary" below.

For another runtime, choose one of these commands instead of the Claude Code initialization above. Run only the one you need in a new project; use `--diff` to compare a preset with an existing config:

```bash
nocklock init --runtime codex
nocklock init --runtime aider
nocklock init --runtime gemini-cli
nocklock init --runtime opencode
nocklock init --runtime goose
```

## How it works

`nocklock wrap` does three things before it starts your agent.

It filters environment variables against the pass and block lists, which accept glob patterns. This runs on Linux and macOS.

It fences the filesystem. On Linux, Landlock applies a kernel allowlist and LD_PRELOAD records blocked-access events. On macOS, Seatbelt denies writes by default, then permits only `filesystem.root`, NockLock state, and essential per-user runtime paths; its sensitive-path denies also block reads. Every child process inherits the profile. Before launch, NockLock validates the generated profile, so a requested macOS fence either engages or refuses to start. It never silently degrades.

It routes network traffic through a local proxy that enforces a domain allowlist. On Linux, in proxy mode with syscall enforcement and the filesystem interposer enabled, IP socket creation is denied in the child; proxy-aware HTTP(S) clients connect to an advertised loopback proxy address that the interposer maps onto a Unix socket. Direct IP sockets, including `--noproxy` bypass attempts, fail closed. For HTTPS, only the hostname is inspected. There is no certificate injection and no payload decryption. If the proxy is not confirmed healthy, the agent does not start.

On Linux you can instead pass `--net-fence=netns`. The child then runs in its own network namespace behind a kernel default-drop floor, keeps its configured IP socket families, and reaches only `network.allow` hosts through a transparent HTTP(S) proxy and a fixed-answer DNS stub that answers DNS over UDP and TCP port 53 inside the namespace. All other traffic leaving the namespace is dropped in the kernel, including direct DNS to other resolvers, non-DNS UDP, QUIC (UDP/443), SCTP and raw IP. This mode needs the privileged egress helper described under "Linux network-egress helper" and fails closed without it.

### What “network fence active” means

`wrap` prints and signs the effective egress level for each session. The proxy checks hostnames only for clients that use it; it does not decrypt HTTPS.

| Level | Boundary |
|---|---|
| `KERNEL` | Linux netns with a kernel default-drop floor and the configured HTTP(S)/DNS allowlist. |
| `CONFINED` | Linux proxy with syscall enforcement and the filesystem interposer bridge. The kernel rejects direct AF_INET/AF_INET6 socket creation; the interposer remaps proxy TCP streams to AF_UNIX. Below Landlock ABI 9, the default non-strict `wrap` warns once and records that pathname and abstract Unix sockets remain reachable; `network.require_unix_socket_isolation = true` makes it refuse. At ABI 9 or later, the rules permit only the exact proxy and filesystem event sockets; that branch has not yet been exercised on a real kernel. |
| `SEATBELT` | macOS proxy with a Seatbelt kernel floor (needs `filesystem.root`): the profile denies every outbound network connect except to the proxy's loopback port, and allows no Unix-socket connect, so a client that ignores `HTTP_PROXY` is denied by the kernel. It is not `CONFINED`, which is defined by the Linux syscall and interposer bridge, and look-back rules (Linux CONFINED only) are refused at `SEATBELT`. |
| `ADVISORY` | Userspace proxy only. A client that ignores `HTTP_PROXY` can reach any host. The wrap warning names this limitation. |
| `OFF` | `network.allow_all = true`; any host is reachable. |
| `UNREACHABLE` | Syscall enforcement restricts proxy traffic to Unix sockets, but the filesystem interposer bridge is disabled, so the allowlist cannot be reached. Wrap refuses to start. |

Set `network.require_enforced = true` in `.nock/config.toml` or pass `--require-enforced-egress` to refuse `ADVISORY`, `OFF`, and `UNREACHABLE` levels. Linux can use `--net-fence=netns`; macOS meets the requirement through the `SEATBELT` floor.

The macOS floor is the Seatbelt profile that `filesystem.root` already requires: `(deny network-outbound)` plus a TCP-only allow (`remote tcp`) for `localhost:<proxy port>`, and a deny of the resolver's Mach services (`com.apple.mDNSResponder`, `com.apple.mDNSResponderHelper`). `getaddrinfo` reaches mDNSResponder over Mach, not a socket, so without that deny a fenced agent could put data into DNS queries; with it, the agent cannot resolve names itself, and proxy-aware clients send the hostname to the proxy, which resolves it outside the profile. NockLock holds the proxy's port on `[::1]` too (wrap refuses to start if that port is taken), because `localhost` in the rule admits both loopback families. The proxy runs outside the profile, so its upstream connects are unaffected. If the profile is rejected or the proxy is unhealthy, wrap refuses to start, and the signed fence-state row records the floor. The honest limits: Apple deprecates `sandbox-exec`; reads outside `filesystem.root` are not confined; with `filesystem.root = ""` there is no profile and egress is `ADVISORY`; the proxy's loopback port is the only local destination; `/etc/hosts` lookups stay allowed (a local file read, no query leaves the host); a tool that must resolve a public name itself (not through the proxy) fails inside the fence; and the Mach deny covers the resolver services named above, so a resolver service not on that list is not claimed closed.

#### Look-back rules (Linux, CONFINED only)

A look-back rule narrows egress after a denied file open. It never adds an allow:

```toml
[[network.lookback]]
name   = "probe-then-silence"
on     = "file_blocked"   # only trigger supported today
within = "10m"            # optional; default is the rest of the session
then   = "deny_egress"
```

After the interposer reports a denied open, the proxy closes open tunnels and requests and denies new ones, each logged as a signed `network_blocked` row citing the rule and the trigger row. `wrap` refuses to start with a rule unless the egress level is `CONFINED`. Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass the interposer, so they never trip the rule. See `docs/design/look-back-rules.md`.

On Linux, blocked file accesses the interposer sees are logged to the event log (see "Event log" for where it lives); the cases it misses are listed in [What the signed log proves](#what-the-signed-log-proves). On macOS, Seatbelt returns its native permission error and a best-effort tailer records file denials as `file_blocked` rows (see "Filesystem platform boundary"). Blocked domains get a 403.

### What the signed log proves

Kernel enforcement and event collection have different coverage. A signed, hash-chained log proves the integrity of the rows it holds. It does not prove that every attempt was observed. These produce no row:

- Allowed file reads and writes.
- File denials that bypass the Linux interposer (static binaries, raw syscalls, children that clear `LD_PRELOAD`). Where Landlock is engaged, the kernel still denies those opens but writes no row. Where Landlock is off or degraded, they are not denied either (see "Philosophy").
- macOS file denials the unified log drops under load. Capture there is best effort.
- Packets dropped by the kernel floor (the netns default-drop floor at `KERNEL` egress, and the Seatbelt network deny). No per-attempt row today (design card N11634).
- Seccomp `socket()` denials. The filter returns a plain `EPERM` with no log action, so the child sees the error and no row is written (`internal/fence/syscallfence/seccomp_linux.go`).
- The Seatbelt `mach-lookup` deny of `com.apple.mDNSResponder` and `com.apple.mDNSResponderHelper`. The denial tailer keeps only `file-*` operations (`internal/fence/fs/denylog.go`).
- `ADVISORY` egress bypass. A client that ignores `HTTP_PROXY` never reaches the proxy, so the bypass is not seen.
- Linux `CONFINED` AF_UNIX connects. Below Landlock ABI 9 they remain reachable; at ABI 9 or later Landlock applies the Unix-socket rules. Neither path has per-connect audit rows.
- Secret use. Secrets are logged once at startup as removed variable names, not when read.

A missing row is therefore not proof that nothing happened. Signed history proves what was recorded, not complete observation.

### Filesystem platform boundary

Linux supplies root-only filesystem isolation. macOS supplies a kernel-enforced
write boundary. Seatbelt deliberately keeps `(allow default)`, because a
`(deny default)` profile aborts common processes, then applies `(deny
file-write*)` with narrow write allows for the canonical `filesystem.root`,
`.nock`, `/private/tmp`, the invoking user's temp and cache paths, and required
`/dev` pseudo-devices. The built-in and configured sensitive paths remain
denied for both reads and writes, even when they sit under the configured root. Reads outside the
root are not confined; NockLock does not claim macOS read isolation. Every
emitted path is canonicalized, and an unresolvable path or a rejected profile
fails closed before the agent starts.

Apple deprecates `sandbox-exec`, but it is still present and working on
macOS 26.5. NockLock tests it in macOS CI and will track its availability. Its
per-file deny events are best-effort on macOS via the unified log: the profile
tags each file-deny rule with the session id, and a background `log stream`
tailer records the matching denials as `file_blocked` rows (each operation and path once, at most 500 per
session, then one row counting the rest). Only kernel-originated records count: a record that a process
inside the fence logs under the `Sandbox` sender name is ignored. The unified log can drop lines under
load, so a missing row is not proof that no denial happened, and a tailer that
cannot start becomes one warning row without affecting the wrapped command.
Every macOS wrap also records exactly one filesystem-fence state in the event
log: `ENGAGED`, `REFUSED-TO-START`, or `DEGRADED`.

The v0.5 `filesystem.macos_allow_unfenced = true` escape hatch was removed in
v0.6.0. When Seatbelt cannot be applied, wrap always records
`REFUSED-TO-START` and does not launch the child. A config that sets the key to
`true` fails to load; `= false` is still accepted.

## Tamper-evident audit log (v1)

### Forward fence decisions to Command

Add this to `.nock/config.toml` to forward recorded fence decisions to Command's ops log. This covers observed file denials, proxy allow/block decisions, and startup environment filtering; it does not add the missing observations listed above:

```toml
[audit.forward]
enabled = true
url = "https://cc.nocktechnologies.io"
api_key_env = "NOCKLOCK_FORWARD_KEY"
```

Set `NOCKLOCK_FORWARD_URL` to the same approved Command origin and set the dedicated `NOCKLOCK_FORWARD_KEY` before `nocklock wrap`. Both values must come from the operator environment; the project config cannot select another credential name or redirect the key to another host. NockLock always strips both variables from the fenced child, records the removal in `events.db`, and never stores the key value in config or the audit log. Other inherited credentials remain governed by the secret fence. Forwarding is off by default. Each ops-log entry includes the action, target, decision, session ID, and committed audit-chain entry hash. Blocked decisions use `high` severity; allowed decisions use `info`. Command currently accepts these as `event_type = "other"` with `source = "nocklock"` in `data_blob`.

Delivery uses a bounded background queue with short retries. Network failures do not change fence decisions or remove events from `events.db`; one teardown warning summarizes failed or dropped deliveries. The queue is not durable, so events that cannot be sent during the current session remain available only in the local audit log.

`nocklock verify --audit` walks the SHA-256 hash chain in the event log and reports whether it is intact. Each row carries a SHA-256 hash of its contents, linked to the previous row's hash. A verification run on the signing machine looks like this:

```
$ nocklock verify --audit
AUDIT: AUTHENTIC — 247 entries verified, 247 Ed25519-signed and valid, chain_head signature valid
Head hash: fe48c7a11e02b9ebe9ba07eb7df01e1e3c5b18f3fcb31af8f0eb5d8b4f1e7a4c
```

Without `--ed25519-pub`, `verify --audit` uses the public half of the local managed key (`~/.config/nocklock/signing-ed25519.key`) when that file exists (`resolveVerifyPublicKey` in `internal/cli/verify.go`). A clean run on the signing machine therefore prints `AUTHENTIC` with no flag, as above, provided the log has signed rows and the signatures and `chain_head` signature check out against that key. The local key is not an independent anchor: it only shows the log was signed by the key on this host. On a machine without the key file (a copied log) and with no `--ed25519-pub`, or for a log that was never signed, the same intact chain prints the weaker verdict:

```
AUDIT: CONSISTENT — 247 events verified, hash chain intact (not externally anchored)
```

Supplying `--ed25519-pub` also declares that the log must be signed: a log with no signatures then prints `SUSPECT` and exits 1, where the local-key run would print `CONSISTENT`.

This means the logged events have not been altered, deleted (except possibly the most recent), or reordered since they were recorded. An intentional compaction (`--prune`) re-anchors the chain and still verifies as consistent, but it is never silent: verify prints a `NOTE:` line that reports when the prune happened and how many events it removed. The chain is not externally anchored. An attacker with write access to the SQLite file can defeat this check by rewriting the chain and `chain_head` in the same transaction. A passing audit verification means the stored rows and their integrity metadata are internally consistent. It does not prove the history is authentic, or that NockLock itself recorded the entries.

v1 is a tamper-evident log, not an unforgeable receipt. The hash chain alone cannot resist an active file writer.

## Signed audit log (v1.1: Ed25519)

v1.1 layers an Ed25519 signature over the same canonical bytes the hash chain already covers. Signing adds authenticity: it proves that NockLock, as holder of the private key, wrote each row. The unkeyed hash chain cannot prove that. Because the chain algorithm is public and keyless, an active writer with access to the event log can recompute every hash and rewrite `chain_head` in lockstep, and v1 verification still passes. A signature the attacker cannot produce without the key defeats exactly that writer.

The key is a NockLock-managed file at `~/.config/nocklock/signing-ed25519.key` (mode `0600`, generated on first use, and kept outside the database so a db-only attacker cannot sign). The key directory is resolved canonically and must end at a directory owned by the current user and not group- or world-accessible. A benign user-owned symlink in the path is accepted, since macOS temp dirs and a symlinked `~/.config` are normal on every platform. A symlink whose target is owned by another user, or is group- or world-accessible, is rejected. The versioned `chain_head` signature binds the head, the prune boundary, the signing-adoption boundary, and the public-key fingerprint. An adopted log refuses writes unless its managed key matches that fingerprint and verifies the existing head.

Every `wrap` also signs a `config.digest` row for its resolved policy; a changed policy warns before the child starts, and `verify --audit` reports its history and rejects sessions missing that row.

`nocklock verify --audit` reports four states and never conflates them. AUTHENTIC means signed and valid. CONSISTENT means the hash chain is intact but unsigned, or signed with no key supplied to check it. FORGED means a signature does not verify, or signing artifacts remain without their adoption marker. SUSPECT means a signed check was explicitly required via `--ed25519-pub` but the log carries no signatures and no adoption markers, whether or not any events remain; this could be a full strip of every signing artifact, or a deletion of every row with the head reset, and it is reported non-zero, never as a clean pass.

Supplying `--ed25519-pub` states the external expectation that the log is signed. Without it, a genuinely unsigned or pre-adoption log reads CONSISTENT. With it, a completely erased signing record reads SUSPECT. Telling a never-signed log apart from a fully stripped one cryptographically requires anchoring the signed head off-box, which is what the v1.2 external chain-head anchor below does. Signing is adopted going forward, so rows written before adoption verify as consistent-but-unsigned, not forged. Run `nocklock verify --export-pubkey` to publish the public key for out-of-band checking.

Because the head is signed, deleting the newest rows and rewriting `chain_head` in lockstep, the attack the unkeyed chain cannot resist, is now caught as FORGED: the attacker cannot re-sign the shortened head. The remaining gap is rollback. An attacker who restores an earlier, legitimately signed snapshot of the whole database presents a shorter log that still verifies, because its head was validly signed at the time. Detecting that requires anchoring the signed head off-box, which is exactly what the external chain-head anchor adds.

## External chain-head anchors

An off-box anchor pins a signed audit chain head and row count, making rollback to an earlier valid database snapshot observable. V2 anchors sign both the key fingerprint (`agent_id`) and an independent random `chain_id`, so projects sharing one managed signing key have separate remote streams. The signature also binds an immutable legacy migration witness. V2 uses domain byte `0x06`; explicit legacy v1 files retain `0x05`.

`nocklock anchor emit --out anchor.json` verifies the existing signed local chain and emits v2 when a trusted identity exists, or v1 for a wholly legacy chain. It requires the original signing key and never adopts or re-signs an unsigned or stripped database. `nocklock verify --against-anchor anchor.json` supports both formats; v2 additionally requires trusted local identity agreement. A valid anchor from another project fails identity checking before any row-count verdict. Fewer local rows is `ANCHOR: TRUNCATION`; a divergent prefix is `ANCHOR: TAMPERED`. Every non-OK verdict exits non-zero.

The local `chain-anchor.json` alone cannot defeat an attacker who replaces it together with the DB. Rollback protection requires a pin in an independent store the agent cannot alter. The trusted identity and original registration request live outside the project and DB; `wrap` protects that directory even for a configured in-project database.

### Enroll, migrate and push off-box

Configure an upgraded v2 anchor store:

- `NOCKLOCK_ANCHOR_URL`: HTTPS base URL; plain HTTP is accepted only on loopback for development/tests.
- `NOCKLOCK_ANCHOR_TOKEN`: bearer token from the environment only, never a flag or config key. Both variables are removed from the fenced child's environment.
- `NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL` (optional): upload the committed head during the run at this interval, such as `60s`. Off by default. `NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE` bounds each upload. Both are removed from the child too. A checkpoint shows the store held that head when it confirmed the upload; it is not an independent signed timestamp, and rows after the last confirmed pin are not protected off-box. See [audit log](docs/how-it-works/audit-log.md#in-run-checkpoints-opt-in).

After creating a signed audit trail with `wrap`, select the current project explicitly:

```bash
nocklock anchor enroll                       # establish a new remote pin
nocklock verify --against-remote-anchor
nocklock anchor emit --out anchor.json
nocklock anchor push --file anchor.json
```

If the signing key already has a legacy v1 pin, back up the DB, anchor and trusted state, select its actual owning project, and run `nocklock anchor migrate`. Migration verifies the exact legacy prefix and witness, conditionally creates the v2 stream, and requires remote verification before reporting completion. For an unrelated project that has no claim to that history, use `anchor enroll --acknowledge-no-legacy-history`. This establishes a new pin without claiming earlier rollback protection. The upgraded store retains legacy history and freezes ordinary v1 access after v2 registration; explicit legacy-file verification still works.

Registration durably stores its exact signed request and `pending` state before network transmission. After a timeout or crash, retry the same command and mode: the original timestamp/signature are reused. Pending never resets to none. `log --prune` refuses pending/enrolled chains; archive the old chain and explicitly enroll a fresh one to bound growth. Legacy and never-registered chains can still prune only when no original registration request is retained, invalidating their earlier anchors. A retained request blocks prune even if an interrupted durable write left registration at `none`; retry the original enrollment or migration without replacing that request. Follow the [offline state-move procedure](docs/runbooks/chain-identity-move.md) when moving a project; never regenerate a missing identity.

`anchor push`, including `--file`, authenticates the candidate and trusted pair, verifies its local prefix and the previous remote head, then sends a compare-and-swap update. It cannot recreate a missing pin or overwrite a newer one. Remote verification requires the expected pair; missing identity, missing/unsupported routes, invalid signatures, mismatches and unavailable stores all fail. No v1 downgrade is attempted.

`wrap` writes a local anchor on teardown and, for enrolled v2 chains with a configured URL, pushes under a five-second timeout. A push failure warns loudly and preserves the child's exit code. A legacy chain with a configured URL warns that explicit enrollment or migration is required. Interactive commands use a 30-second deadline. Redirects are refused and responses are capped at 64 KiB. The [audit-log reference](docs/how-it-works/audit-log.md) describes the v2 routes, trust boundary, and tested client contract.

## Secret preflight scanning

Check selected local files before giving them to an agent:

```bash
nocklock scan src .env
nocklock scan --json src
nocklock scan --env src   # also inspect the invoking environment, without filtering
```

No config or account is required. Paths are relative to the current directory;
omitting them scans `.`. Exit status is zero only when the scan completes with
no findings. JSON reports distinguish `complete` from `findings`, because a
complete scan can still find a credential. Reports show detector IDs and
locations, never matching values or source lines. Recognized credential formats
in filenames or environment names are also replaced with `[redacted]` in report
locations.

The initial detectors recognize AWS access-key IDs (`AKIA`/`ASIA`), GitHub token
formats (classic, OAuth, app, refresh and fine-grained), and PEM private-key
headers. These are format checks; they do not check that a credential is valid.
Unrecognized, encoded or compressed secrets can go undetected.

To require preflight before every `wrap` launch, add settings to your existing
`[secrets]` table:

```toml
[secrets]
# Keep your existing pass/block rules here.
scan_env = true
scan_paths = ["src", ".env"]
# Optional exact names intentionally available to the agent:
scan_env_allow = []
```

`wrap` checks environment values after pass/block filtering and after removing
its own anchor credentials. `scan_env_allow` exempts exact names from value
scanning only; it never overrides a block rule. Scan paths are relative to the
project containing `.nock/config.toml`, even when launched from a subdirectory.
With a profile and no project config, the root is the current directory.
Profile overlays can add paths or enable scanning, but they cannot disable a
base scan, remove its paths or add environment exceptions. An absent or false
`scan_env` and empty `scan_paths` leave existing behavior unchanged. `--dry-run`
displays the configured policy without scanning.

There are no implicit exclusions: hidden and binary files are inspected, and
ignore files are not consulted. Use explicit paths to choose the scope.
Symlinks, special files, unreadable or missing inputs, and detected concurrent
changes make the scan incomplete. Bounds are 1 MiB per file or environment
value, 32 MiB of content, 10,000 entries (unique traversed paths plus
environment values), 10,000 selected-path arguments and 64 levels below each
selected path. An explicit path is counted once; duplicate paths are not
scanned again. Exceeding a bound is an incomplete scan, not a silent skip. Safe
file opens are supported on Linux and macOS. Recursive traversal uses open
directory handles, so replacing a directory path cannot redirect a child read.
Identity, metadata and bounded content rereads detect observed changes; they do
not provide an atomic snapshot or rule out every concurrent write.

A required scan that finds something, or that comes back incomplete, prevents
child execution and is recorded in the local audit log. Failure to record that
result also prevents launch. This is a point-in-time preflight check. It does
not redact reads, monitor agent context, protect paths outside the selected
scope, or prevent files from changing after the scan. Runtime secret-file
protection is separate.

## Configuration

`nocklock init` creates `.nock/config.toml` with safe defaults:

```toml
[project]
name = ""
root = "."

[filesystem]
root = "."
mode = "read-write"
linux_enforcement = "required"
allow = [
    "~/.claude/",
    "/tmp/",
    "/usr/",
    "/bin/",
    "/lib/",
    "/lib64/",
    "/etc/ld.so.cache",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ssl/certs/",
    "/etc/pki/tls/certs/",
    "/etc/pki/ca-trust/extracted/",
]
# Linux only: these paths are explicitly read-write; allow stays read-only.
allow_rw = []
deny = [
    "~/.ssh/",
    "~/.aws/",
    "~/.gnupg/",
    "~/.nock/",
]

[network]
allow = [
    "github.com",
    "api.github.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
    "rubygems.org",
    "crates.io",
]
allow_all = false
require_enforced = false

[syscall]
enforcement = "required"
allow_namespaces = false
socket_families = [
    "unix",
    "inet",
    "inet6",
]

[secrets]
pass = [
    "HOME",
    "PATH",
    "SHELL",
    "USER",
    "LANG",
    "TERM",
]
block = [
    "AWS_*",
    "STRIPE_*",
    "DATABASE_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "*_SECRET*",
    "*_PASSWORD*",
    "*_TOKEN*",
]

[logging]
# A relative db goes to NockLock's audit state directory outside the project;
# an absolute path must be inside this project or its audit state directory. See "Event log".
db = "events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
```

The defaults are deliberately restrictive. Adjust them per project. `[cloud]` is a legacy section and sends nothing, even with `enabled = true` and a key; an enabled section without a key fails validation. Use `[audit.forward]` for optional Command delivery.

On Linux, `filesystem.allow` grants read-only access. Use
`filesystem.allow_rw` only for paths a tool must modify, such as a runtime's
state directory. Both lists are ignored on macOS, whose Seatbelt backend uses
the configured root as its write boundary instead.

The default Linux policy includes the system binary, library, and configuration
paths needed to launch a shell. Missing read-only paths, such as `~/.claude/`
in a new home, grant nothing for that session and do not prevent a wrap.

Runtime presets exist for `claude-code`, `codex`, `aider`, `gemini-cli`, `opencode`, and `goose`. Each preset keeps the network default-deny, blocks private ranges, keeps Linux filesystem and syscall enforcement required, and passes only the runtime's documented first-party provider key or keys. `claude-code` also passes `CLAUDE_CODE_OAUTH_TOKEN` (see the macOS note under Quick start). `codex` keeps its login in a file under `~/.codex`; the built-in macOS deny list does not include `~/.codex`, so reads are not blocked, but Codex's token-refresh writes outside the project root would be, and this has not been verified on a macOS runner. Use `OPENAI_API_KEY` if a refresh fails. `gemini-cli` targets the API-key path; OAuth and Vertex AI setups need explicit operator review before widening the filesystem or egress. `opencode` targets OpenCode Zen/Go through `opencode.ai`; direct third-party providers should use a reviewed custom config. `goose` is a multi-provider preset covering Anthropic, OpenAI, Gemini, Groq, and OpenRouter; only the provider key the user has set is live, and the rest are unset and harmless. MCP extensions that reach additional hosts need an operator overlay.

Two candidate runtimes are deliberately left without a preset:

- `cursor-agent`: its first-party egress endpoints are not documented clearly enough to pin without guessing.
- `continue`: its provider endpoints are user-configurable and can include hosted or self-hosted providers, so no single default allowlist would be accurate.

## Commands

| Command | Description |
|---------|-------------|
| `nocklock init` | Create `.nock/config.toml` with safe defaults |
| `nocklock init --runtime <name>` | Create `.nock/config.toml` from an embedded runtime preset; fails if one exists. Add `--diff` to print the preset's policy changes against the existing config (no write) |
| `nocklock wrap -- <cmd>` | Run a command inside the fence |
| `nocklock wrap --net-fence=netns -- <cmd>` | Linux only: run inside the kernel-enforced netns egress fence (needs the privileged helper) |
| `nocklock wrap --require-enforced-egress -- <cmd>` | Refuse to start unless egress is `KERNEL`, `CONFINED` or `SEATBELT` |
| `nocklock wrap --profile list` | List embedded runtime presets |
| `nocklock wrap --dry-run` | Validate config without starting fences or a command |
| `nocklock scan [path ...]` | Scan selected local files; `--env` adds environment values and `--json` prints structured results |
| `nocklock validate [config-path]` | Validate a config file and print the effective policy |
| `nocklock doctor` | Check whether each fence is enforced on this host; exit 0 PROTECTED, 2 GAPS FOUND, 3 PARTIAL, 4 UNPROTECTED (see below) |
| `nocklock verify` | Run the adversarial fence self-test (proof of block) |
| `nocklock verify --audit` | Verify the audit log hash chain and signatures |
| `nocklock verify --against-anchor <file>` | Verify the audit chain against an external chain-head anchor file |
| `nocklock verify --against-remote-anchor` | Verify the audit chain against the latest anchor in the off-box store |
| `nocklock verify --export-pubkey` | Print the Ed25519 audit-log public key for out-of-band verification |
| `nocklock anchor emit [--out <file>]` | Verify and emit a signed chain-head anchor |
| `nocklock anchor enroll [--acknowledge-no-legacy-history]` | Explicitly register this project's v2 remote pin |
| `nocklock anchor migrate` | Explicitly migrate this project's retained legacy pin to v2 |
| `nocklock anchor push [--file <file>]` | Push an anchor to the off-box store at `NOCKLOCK_ANCHOR_URL` |
| `nocklock egress-probe` | Probe Linux network-egress enforcement feasibility on this host (structured `--json`) |
| `nocklock status` | Show configured fences and event log summary (does not track running sessions) |
| `nocklock log` | View fence event history |
| `nocklock log --blocked` | Show only blocked events |
| `nocklock log --stats` | Show aggregate statistics |
| `nocklock config` | Display current configuration |
| `nocklock version` | Show version |

## Installation

### Homebrew (macOS, recommended)

```bash
brew install nocktechnologies/tap/nocklock
```

On Linux the formula installs only the `nocklock` binary, not `libfence_fs.so`; build from source and place `libfence_fs.so` by hand (see `docs/setup.md`) until packaging lands (N11643).

### From source

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
make build-all
```

Requires Go 1.26 or newer. The binary is built to `./nocklock`; building does not install it on `PATH`. Follow [the complete source installation steps](docs/setup.md#1-install) to install the binary and, on Linux, its required library. On Linux, `build-all` also compiles the filesystem fence interposer library (`libfence_fs.so`). On macOS, the library build is skipped automatically, and the filesystem fence uses the built-in Seatbelt sandbox (`sandbox-exec`).

### Verify the installation

```bash
nocklock version
```

### Linux network-egress helper (privileged)

On Linux, the opt-in network-egress fence (`nocklock wrap --net-fence=netns`,
netns transparent redirect) needs a small root-owned helper plus a constrained
NOPASSWD sudoers grant. `nocklock wrap`
runs unprivileged and hands the composed child to that helper over passwordless
sudo. The child's argv, env, and the credential to drop to travel in a 0600
per-session request file, and only the file path rides argv, so the fixed
`check` / `setup --request-file <path>` sudoers policy is a real privilege
boundary rather than an argument-injection surface. Keeping the request off
stdin lets sudo pass the caller's real stdin (a TTY or a pipe) straight through
to the fenced child, so interactive and piped agents keep their input stream.
Without the helper, the egress fence fails closed at runtime.

Install the binary, then the helper:

```bash
sudo install -m 0755 nocklock /usr/local/bin/nocklock   # after make build-all as your user
sudo make install-egress-helper                # installs the root-owned helper + sudoers grant
# or, to name the unprivileged wrap user explicitly:
sudo NOCKLOCK_EGRESS_USER=<user> scripts/install-egress-helper.sh
```

The installer writes a root-owned shim to `/usr/libexec/nocklock-egress-helper`
and this constrained grant to `/etc/sudoers.d/nocklock-egress`. The grant is
validated with `visudo -cf` before it is moved into place, so a broken file is
never left behind. `<user>` is the unprivileged user that runs `nocklock wrap`:

```sudoers
Cmnd_Alias NOCKLOCK_EGRESS = /usr/libexec/nocklock-egress-helper check, \
                             /usr/libexec/nocklock-egress-helper setup --request-file *
<user> ALL = (root) NOPASSWD: NOCKLOCK_EGRESS
```

Verify it as the wrap user:

```bash
sudo -n /usr/libexec/nocklock-egress-helper check   # prints nothing and exits 0
nocklock doctor                                     # egress-helper check reports ok
```

## Works with

NockLock does not care which agent you run. It wraps any CLI tool that respects standard environment variables.

```bash
nocklock wrap -- claude                          # Claude Code
nocklock wrap -- cursor                          # Cursor
nocklock wrap -- codex                           # Codex CLI
nocklock wrap -- aider                           # Aider
nocklock wrap -- your-custom-agent               # Anything
```

## Event log

Fence decisions are recorded in an SQLite event log, but not all of them (see [What the signed log proves](#what-the-signed-log-proves)).

For a NEW project the log does **not** live in your project. It lives in
NockLock's audit state directory,
`$XDG_STATE_HOME/nocklock/<project-key>/` (or
`~/.local/state/nocklock/<project-key>/`), where `<project-key>` is derived from
the project's path. The chain anchor sits beside it.

That is a security boundary, not a preference. The fence grants your project
root to the agent so it can create and delete files there, and Landlock cannot
exclude a path underneath a granted directory — an event log stored in the
project would be editable by the very agent it records.

If you already have a log at `.nock/events.db`, NockLock keeps using it there.
It will not move an existing audit chain for you: relocating a live SQLite
database, its write-ahead-log sidecars and its chain anchor is one operation
that has to either fully succeed or not start, and a half-finished move leaves a
chain that still verifies while missing its most recent entries. The trade is
that while the log sits inside the fence root, the agent cannot create or remove
entries directly in the root — everything inside existing subdirectories still
works, and `nocklock wrap` says so on stderr each run. To lift the restriction,
move the audit directory (`events.db`, its `-wal`/`-shm` sidecars and
`chain-anchor.json` together) outside the fence root while no session is
running; `nocklock state migrate` will do that for you in a later release.

`logging.db` set to a relative path uses its filename in the audit state
directory, except that an existing log at the explicitly configured in-project
path is retained for compatibility. An absolute path is accepted only inside
your project or the audit state directory; anywhere else is rejected when the
config loads, because `logging.db` is a setting a repository can ship. Changing
the filename does not hide an existing default-name chain: if both the old
default location and the newly configured destination are candidates, NockLock
refuses to guess which chain is authoritative and names both paths. Likewise,
an existing legacy `.nock/events.db` remains visible after a rename.
`nocklock wrap` refuses to start if the resolved `logging.db` directory is the
project root: Landlock cannot protect the database's sidecars and chain anchor
while granting that root. Move the database, sidecars, and chain anchor
together under `.nock/` with
`[logging] db = ".nock/events.db"`, or use the NockLock state directory with
`[logging] db = "events.db"`.
`nocklock doctor` warns if an absolute path lands back inside
`filesystem.root`, where the agent can reach it.

Query it with `nocklock log`:

```text
$ nocklock log --blocked
Session a1b2c3d4  started 2026-04-09 14:23:01  ended 2026-04-09 14:47:33  (24m 32s)
  secret_blocked: AWS_SECRET_ACCESS_KEY
  file_blocked: /home/user/.ssh/id_rsa
  network_blocked: evil.example.com:443

Total: 3 event(s) across 1 session(s), 3 blocked, 0 passed
```

```text
$ nocklock log --stats
Total events: 847
Sessions:     12
Blocked:      23
Passed:       824
First event:  2026-04-07 09:00:01
Last event:   2026-04-09 14:47:33
```

## Optional Command integration

The CLI and its local audit log work without a hosted service. Operators with a Command deployment can opt into [forwarding recorded fence decisions](#forward-fence-decisions-to-command). Forwarding is off by default and uses a bounded, non-durable queue; the local audit log remains the source of record.

## Philosophy

NockLock is a fence, not guardrails.

Guardrails tell the agent what not to do. The agent can ignore them, work around them, or hallucinate past them. Guardrails are prompts.

`nocklock doctor` verdicts and exit codes (`--json` adds per-boundary `boundaries` posture of `enforced`, `advisory`, `disabled`, `unavailable` or `enabled`, and the proxy-mode `egress_level`):

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | PROTECTED | every reported boundary is enforced; the network is not `allow_all` and its proxy-mode egress level is CONFINED or SEATBELT. Linux CONFINED also requires the Unix-socket boundary to be available |
| 2 | GAPS FOUND | a boundary is configured but its backend is missing |
| 3 | PARTIAL | at least one boundary is enforced, but another is disabled, advisory or unavailable without requiring startup refusal; each is listed by name. Also when a [deputy](docs/how-it-works/deputies.md) the fence does not block is reachable, such as `docker.sock`, a writable agent config, or sudo that runs without a password prompt |
| 4 | UNPROTECTED | no boundary is enforced |

A missing or unparseable `.nock/config.toml` also exits 2.

**Since v0.9.0:** below Landlock ABI 9, doctor reports the Linux `CONFINED` Unix-socket boundary as unavailable and returns `PARTIAL` (exit 3). Default `wrap` warns and records the limitation in the signed session-start row. Set `network.require_unix_socket_isolation = true` to refuse launch when that boundary cannot be enforced; this setting requires Linux `CONFINED` mode. ABI 9 enforcement has not yet run on a real kernel. See [Linux CONFINED Unix-socket reachability](docs/design/unix-socket-reachability.md).

Boundary postures: `enforced` (the fence is active), `advisory` (logs or warns but does not block), `disabled` (turned off in config), `enabled` (configured but its backend is missing), and `unavailable` (the fence cannot enforce on this host or config; it never counts toward PROTECTED). `unavailable` is how doctor reports the `UNREACHABLE` egress level: syscall enforcement restricts proxy traffic to Unix sockets while the interposer bridge is disabled, so the allowlist cannot be reached.

A fence sits between the agent and the resource. How hard the boundary is depends on the fence. The secret fence is absolute: a blocked variable is gone from the environment before the agent starts. On Linux, the filesystem fence is kernel-enforced with Landlock by default and composes with LD_PRELOAD logging; where Landlock is engaged, static binaries and children that clear `LD_PRELOAD` are still denied by the kernel. Landlock is absent when `filesystem.linux_enforcement = "off"` and degraded or missing under `"preferred"` on a kernel without it (`"required"` refuses to start instead); in those cases an open that bypasses the interposer is not denied. On macOS, the filesystem fence is a kernel-enforced Seatbelt write confinement. Writes outside the configured root and its essential runtime exceptions are denied, and the built-in and configured sensitive paths are denied for reads and writes. It does not claim read confinement outside the root. The profile follows descendants even when they cross into protected system binaries. The network fence stops normal and prompt-injected attempts to reach unapproved domains; proxy denials are logged, but a bypass that never reaches the proxy is not (see [What the signed log proves](#what-the-signed-log-proves)). On Linux with syscall fencing enabled, proxy-mode runs restrict kernel socket creation to Unix-domain sockets; the interposer remaps intended TCP stream sockets and the configured loopback proxy connect to the proxy's Unix socket. Direct AF_INET/AF_INET6 socket syscalls fail closed. Below Landlock ABI 9, a child can also reach other path-based and abstract Unix sockets accessible to the same user; see [Linux CONFINED Unix-socket reachability](docs/design/unix-socket-reachability.md). With `--net-fence=netns` the child keeps IP sockets and the boundary is composed: the nftables default-drop floor and the network namespace prevent alternate transports and proxy bypass (direct DNS to other resolvers, non-DNS UDP, QUIC, SCTP and raw IP are dropped, and nothing but the transparent proxy and the in-namespace DNS stub is reachable), while the transparent HTTP(S) proxy and the DNS stub enforce the `network.allow` domain policy.

NockLock does not restrict how your agent works. It restricts what your agent can reach. Inside the fence, your agent still has full permissions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

---

Built by [Nock Technologies™](https://nocktechnologies.io).
