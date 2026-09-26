# NockLock™

**Fence, not guardrails.** Sandbox your AI agents without restricting how they work.

NockLock puts a fence around your AI coding agent — controlling what secrets it can see, what files it can access, and what domains it can reach. Your agent runs with full permissions inside the fence. When fences are active, nothing gets out beyond the access you allow.

## Why NockLock?

Your AI agent runs with full shell access — your environment, your filesystem, your network. NockLock doesn't change how your agent works — it controls what it can reach.

- **Secret Fence** — Filter environment variables. Your agent sees `PATH` and `HOME`. It never sees `AWS_SECRET_ACCESS_KEY`.
- **Filesystem Fence** — Your agent can't read outside the configured project root on Linux. Landlock provides kernel enforcement and LD_PRELOAD records blocked-access events. macOS `filesystem.root` is explicitly unsupported: `nocklock wrap` refuses to start the child because Seatbelt cannot enforce the same root-only allowlist.
- **Network Fence** — Local proxy with domain allowlist. Your agent can reach GitHub and `api.anthropic.com`. It can't phone home to anywhere else.

## Quick Start

```bash
brew install nocktechnologies/tap/nocklock
cd your-project
nocklock init
nocklock wrap -- claude
```

That's it. Four commands. Your agent is fenced.

For a runtime-specific first run, scaffold from a preset:

```bash
nocklock init --runtime codex
nocklock init --runtime aider
nocklock init --runtime gemini-cli
nocklock init --runtime opencode
nocklock init --runtime goose
```

## How It Works

`nocklock wrap` does three things before spawning your agent:

1. **Filters environment variables** based on pass/block lists with glob patterns — Linux, macOS
2. **Fences the filesystem** — Linux: Landlock applies a kernel allowlist and LD_PRELOAD records blocked-access events. On macOS, configuring `filesystem.root` fails closed before the child starts; it is not a root-isolation backend. In either case, a requested filesystem fence never silently degrades.
3. **Routes network traffic** through a local proxy that enforces a domain allowlist. On Linux, when the syscall fence is enabled and the network fence is active, IP socket creation is denied so native code cannot bypass the proxy; this is a fail-closed no-network posture. Disable `[syscall]` only if you accept the proxy as a userspace boundary. For HTTPS, only the hostname is inspected — no certificate injection, no payload decryption. If the proxy is not confirmed healthy, the agent does not start.

Every blocked access is logged to `.nock/events.db`. Blocked file opens and access-style checks return EACCES (permission denied); denied stat-family probes return ENOENT to avoid existence enumeration. Blocked domains return 403.

### Filesystem platform boundary

Root-only filesystem isolation is currently a Linux capability. On macOS, a
nonempty `filesystem.root` makes `nocklock wrap` print an explicit
unsupported-platform error and refuse to launch its child. The repository's
Seatbelt (`sandbox-exec`) component is a tested sensitive-path denylist proof,
but it deliberately uses `allow default`; it cannot satisfy the CLI's
root-only allowlist contract and is not enabled as a substitute. A future
macOS backend must prove that it refuses writes outside the configured root
before this limitation is removed.

## Tamper-Evident Audit Log (v1)

`nocklock verify --audit` walks the SHA-256 hash chain in `.nock/events.db` and reports its integrity. Each row carries a SHA-256 hash of its contents linked to the previous row's hash. A chain verification run looks like:

```
$ nocklock verify --audit
AUDIT: CONSISTENT — 247 events verified, hash chain intact (not externally anchored)
Head hash: fe48c7a11e02b9ebe9ba07eb7df01e1e3c5b18f3fcb31af8f0eb5d8b4f1e7a4c
```

This means the logged events have not been altered, deleted (except possibly the most recent), or reordered since they were recorded. An intentional compaction (`--prune`) re-anchors the chain and still verifies as consistent, but it is never silent: verify prints a `NOTE:` line reporting when the prune happened and how many events it removed. The chain is **not externally anchored** — a write-access attacker with access to the SQLite file can defeat this check by rewriting the chain and `chain_head` in the same transaction. A successful audit verification means the stored rows and their integrity metadata are internally consistent; it does not prove the history is authentic or that NockLock itself recorded the entries.

v1 is a tamper-*evident* log, not an unforgeable receipt. The hash chain alone cannot resist an active file writer.

## Signed Audit Log (v1.1: Ed25519)

v1.1 layers an Ed25519 signature over the same canonical bytes the hash chain already covers. Signing adds **authenticity** — it proves NockLock, holder of the private key, wrote each row — which the unkeyed hash chain provably cannot: because the chain algorithm is public and keyless, an active writer with access to `.nock/events.db` can recompute every hash and rewrite `chain_head` in lockstep, and v1 verification still passes. A signature the attacker cannot produce without the key defeats exactly that writer. The key is a NockLock-managed file at `~/.config/nocklock/signing-ed25519.key` (mode `0600`, generated on first use, and kept outside the database so a db-only attacker cannot sign). The key directory is resolved canonically and must end at a directory owned by the current user and not group/world-accessible: a benign user-owned symlink in the path is accepted (macOS temp dirs and a symlinked `~/.config` are normal, on every platform), while a symlink whose target is owned by another user or is group/world-accessible is rejected. The versioned `chain_head` signature binds the head, prune boundary, signing-adoption boundary, and the public-key fingerprint; an adopted log refuses writes unless its managed key matches that fingerprint and verifies the existing head. `nocklock verify --audit` reports states it never conflates: **AUTHENTIC** (signed and valid), **CONSISTENT** (hash chain intact but unsigned, or signed with no key supplied to check), **FORGED** (a signature does not verify, or signing artifacts remain without their adoption marker), and **SUSPECT** (a signed check was explicitly required via `--ed25519-pub` but the log carries no signatures and no adoption markers, whether or not any events remain — possibly a full strip of every signing artifact, or a deletion of every row with the head reset; reported non-zero, never a clean pass). Supplying `--ed25519-pub` is the external expectation that the log is signed: without it, a genuinely unsigned or pre-adoption log reads CONSISTENT, while with it a completely erased signing record reads SUSPECT. Cryptographically telling a never-signed log apart from a fully stripped one requires anchoring the signed head off-box (external head anchoring remains a follow-on). Signing is adopted going forward, so rows written before adoption verify as consistent-but-unsigned, not forged. Run `nocklock verify --export-pubkey` to publish the public key for out-of-band checking. Because the head is signed, freshly deleting the newest rows and rewriting `chain_head` in lockstep — the attack the unkeyed chain cannot resist — is now caught as FORGED, since the attacker cannot re-sign the shortened head. The residual gap is **rollback**: an attacker who restores an earlier, legitimately-signed snapshot of the whole database presents a shorter log that still verifies, because its head was validly signed at the time. Detecting that requires anchoring the signed head off-box, which is exactly what the external chain-head anchor below adds.

## External Chain-Head Anchor (v1.2)

An **anchor** is a small, signed record of the audit chain's head — `{version, agent_id, head_hash, row_count, created_at, sig}` — captured at a point in time and stored **outside** `events.db`. It closes the rollback/tail-truncation gap the signed head alone cannot: the signed `chain_head` proves a log is authentic *for the rows it currently holds*, but its signature was valid when it was written, so a shorter, earlier, legitimately-signed snapshot still verifies. An anchor pins the row count and head hash the log *should* have, so a later chain with **fewer** rows is caught.

The anchor is signed with the same NockLock-managed Ed25519 key the audit log signs rows and the head with; `agent_id` is that key's fingerprint (the same identity recorded in `chain_head`). Its signed bytes lead with a `0x05` domain-separation byte (rows use `0x01`, the head `0x03`), so a row or head signature can never be replayed as an anchor, and the exact layout is pinned by a byte-literal test.

```
$ nocklock anchor emit --out .nock/chain-anchor.json   # or to stdout without --out
$ nocklock verify --against-anchor .nock/chain-anchor.json
ANCHOR: OK — local chain reproduces the anchored head at 247 rows (anchor attests 247 rows, local has 247)
```

`verify --against-anchor` first authenticates the anchor itself (the supplied `--ed25519-pub`, else the local managed key; without a key it fails closed rather than falling back to a hash-only pass), then checks the local chain: **fewer rows than attested** is `ANCHOR: TRUNCATION` (tail truncation *or* rollback to an earlier snapshot — both present a shorter chain), a **head-hash mismatch at the attested count** is `ANCHOR: TAMPERED`, a bad or wrong-key anchor is `ANCHOR: FORGED`, and every non-OK verdict exits non-zero. A chain that has legitimately **grown** past the anchor still passes. A `nocklock wrap` session emits an anchor to `<db-dir>/chain-anchor.json` on teardown (best-effort but logged) and, when configured, pushes it off-box (see below).

Two honest limits. First, a legitimate `--prune` re-anchors the chain and invalidates any anchor emitted before it; verify surfaces a `NOTE` when the local `chain_head` records a prune after the anchor's timestamp, and a fresh anchor should be emitted after a prune (wrap re-emits on every teardown). Second, `chain-anchor.json` sits in the **same trust boundary** as `events.db` — a file-access attacker can delete it or swap an older valid anchor alongside a matching database rollback. Its real value is as the **off-box** push hook: once the head is pinned somewhere the agent cannot reach (e.g. NockCC), rollback and truncation become observable even against a full-file adversary.

### Off-box anchor push

Set two environment variables to pin anchors somewhere the agent cannot reach:

- `NOCKLOCK_ANCHOR_URL`: base URL of the anchor store. It must be `https://`; plain `http://` is accepted only for loopback hosts (`127.0.0.1`, `::1`, `localhost`) for local development and tests.
- `NOCKLOCK_ANCHOR_TOKEN`: optional bearer token, read from the environment only (never a config key or flag) and never printed in errors or logs.

`nocklock wrap` strips both variables from the fenced child's environment, whatever the secret-fence config says. With the URL set, wrap pushes the anchor it writes on teardown under a hard 5-second timeout. The push is **fail-open**: on any failure wrap prints `NockLock: warning: chain anchor NOT pushed off-box: <reason>` and exits with the wrapped command's own exit code. With the URL unset, teardown behaves exactly as before. `nocklock anchor push [--file <path>]` pushes an anchor by hand (default: `<db-dir>/chain-anchor.json`).

```
$ nocklock verify --against-remote-anchor
ANCHOR: TRUNCATION — truncation detected: anchor attests 247 rows, local has 190
```

`verify --against-remote-anchor` fetches the latest stored anchor for the local signing identity and runs the same checks as `--against-anchor` (the two flags are mutually exclusive). An unset URL, an unreachable store, or no stored anchor prints `ANCHOR: UNAVAILABLE (anchor_unavailable)` and exits non-zero: a missing off-box pin is reported, never read as a pass.

Server contract (the NockCC endpoint ships separately):

- `POST {base}/api/nocklock/anchors/` with `{"anchor": <anchor object>, "pubkey": "<base64 Ed25519 public key>"}` and `Authorization: Bearer <token>`. Any 2xx means stored.
- `GET {base}/api/nocklock/anchors/{agent_id}/latest/` returns the latest anchor, or 404 when none is stored.
- The server answers **409** when a pushed anchor's `row_count` is lower than the latest one it holds for that `agent_id`. This server-side monotonic check is what makes a local rollback observable: a rolled-back host can no longer re-pin a shorter chain, and `--against-remote-anchor` then reports the gap as `TRUNCATION`. Redirects are not followed and response bodies are capped at 64 KiB.

## Configuration

`nocklock init` creates `.nock/config.toml` with sensible defaults:

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
]
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
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
```

Defaults are deliberately safe. Customize per project.

Runtime presets are available for `claude-code`, `codex`, `aider`, `gemini-cli`, `opencode`, and `goose`. Each preset keeps network default-deny, blocks private ranges, keeps Linux filesystem and syscall enforcement required, and only passes the runtime's documented first-party provider key(s). `gemini-cli` targets the API-key path; OAuth and Vertex AI setups need explicit operator review before widening filesystem or egress. `opencode` targets OpenCode Zen/Go through `opencode.ai`; direct third-party providers should use a reviewed custom config. `goose` is a multi-provider preset covering Anthropic, OpenAI, Gemini, Groq, and OpenRouter; only the provider key the user has set is live, the rest are unset and harmless. MCP extensions that reach additional hosts need an operator overlay.

Candidate runtimes intentionally not preset here:

- `cursor-agent`: first-party egress endpoints are not documented clearly enough to pin without guessing.
- `continue`: provider endpoints are user-configurable and can include hosted or self-hosted providers, so there is no honest single default allowlist.

## Commands

| Command | Description |
|---------|-------------|
| `nocklock init` | Create `.nock/config.toml` with safe defaults |
| `nocklock init --runtime <name>` | Create `.nock/config.toml` from an embedded runtime preset |
| `nocklock wrap -- <cmd>` | Run a command inside the fence |
| `nocklock wrap --profile list` | List embedded runtime presets |
| `nocklock wrap --dry-run` | Validate config without starting fences or a command |
| `nocklock validate [config-path]` | Validate a config file and print the effective policy |
| `nocklock doctor` | Check whether each fence can be enforced on this host |
| `nocklock verify` | Run the adversarial fence self-test (proof-of-block) |
| `nocklock egress-probe` | Probe Linux network-egress enforcement feasibility on this host (structured `--json`) |
| `nocklock status` | Show fence state and event log summary |
| `nocklock log` | View fence event history |
| `nocklock log --blocked` | Show only blocked events |
| `nocklock log --stats` | Show aggregate statistics |
| `nocklock config` | Display current configuration |
| `nocklock version` | Show version |

## Installation

### Homebrew (recommended)

```bash
brew install nocktechnologies/tap/nocklock
```

### From Source

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
make build-all
```

Requires Go 1.26+. The binary is built to `./nocklock`. On Linux, `build-all` also compiles the filesystem fence interposer library (`libfence_fs.so`). On macOS, the library build is skipped automatically; filesystem-root isolation requires Linux Landlock.

### Verify Installation

```bash
nocklock version
```

### Linux network-egress helper (privileged)

On Linux, the network-egress fence (netns transparent-redirect) needs a small
root-owned helper plus a constrained NOPASSWD sudoers grant. `nocklock wrap`
runs unprivileged and hands the composed child to that helper over passwordless
sudo; the child's argv, env, and the credential to drop to travel on **stdin**,
never on argv, so the fixed two-vector (`check`, `setup`) sudoers policy is a
real privilege boundary rather than an argument-injection surface. Without the
helper the egress fence fails closed at runtime.

Install the binary, then the helper:

```bash
make install                                   # builds and installs the nocklock binary
sudo make install-egress-helper                # installs the root-owned helper + sudoers grant
# or, to name the unprivileged wrap user explicitly:
sudo NOCKLOCK_EGRESS_USER=<user> scripts/install-egress-helper.sh
```

The installer writes a root-owned shim to `/usr/libexec/nocklock-egress-helper`
and this constrained grant to `/etc/sudoers.d/nocklock-egress` (validated with
`visudo -cf` before it is moved into place, so a broken file is never left
behind). `<user>` is the unprivileged user that runs `nocklock wrap`:

```sudoers
Cmnd_Alias NOCKLOCK_EGRESS = /usr/libexec/nocklock-egress-helper check, \
                             /usr/libexec/nocklock-egress-helper setup
<user> ALL = (root) NOPASSWD: NOCKLOCK_EGRESS
```

Verify it as the wrap user:

```bash
sudo -n /usr/libexec/nocklock-egress-helper check   # prints nothing and exits 0
nocklock doctor                                     # egress-helper check reports ok
```

## Works With

NockLock is agent-agnostic. It wraps any CLI tool that respects standard environment variables.

```bash
nocklock wrap -- claude                          # Claude Code
nocklock wrap -- cursor                          # Cursor
nocklock wrap -- codex                           # Codex CLI
nocklock wrap -- aider                           # Aider
nocklock wrap -- your-custom-agent               # Anything
```

## Event Log

Every fence decision is recorded in `.nock/events.db`. Query it with `nocklock log`:

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

## NockLock Dashboard

The CLI is free and open source. For teams that want visibility across machines, [NockLock Dashboard](https://nocktechnologies.io) adds cloud monitoring, alerts, and team-wide fence event history.

## Philosophy

NockLock is a fence, not guardrails. The distinction matters.

**Guardrails** tell the agent what not to do. The agent can ignore them, work around them, or hallucinate past them. Guardrails are prompts.

**A fence** sits between the agent and the resource. How hard the boundary is depends on the fence. The **secret fence** is absolute — a blocked variable is gone from the environment before the agent starts. On **Linux the filesystem fence** is kernel-enforced with Landlock by default and composes with LD_PRELOAD logging; static binaries and children that clear `LD_PRELOAD` are still denied by the kernel. On **macOS `filesystem.root` is unsupported by the shipped CLI**: NockLock fails closed instead of treating Seatbelt's allow-default denylist component as root isolation. The **network fence** stops normal and prompt-injected attempts to reach unapproved domains and logs every try; on Linux with syscall fencing enabled, network-fenced runs allow only Unix-domain sockets, so the bypass-resistant posture is no IP sockets rather than proxy-based allowlisting.

NockLock doesn't restrict how your agent works. It restricts what your agent can reach. Your agent still has full permissions — inside the fence.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

---

Built by [Nock Technologies™](https://nocktechnologies.io).
