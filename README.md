# NockLock

**Fence, not guardrails.** Sandbox your AI agents without restricting how they work.

NockLock puts a fence around your AI coding agent — controlling what secrets it can see, what files it can access, and what domains it can reach. Your agent runs with full permissions inside the fence. When fences are active, nothing gets out beyond the access you allow.

## Why NockLock?

Your AI agent runs with full shell access — your environment, your filesystem, your network. NockLock doesn't change how your agent works — it controls what it can reach.

- **Secret Fence** — Filter environment variables. Your agent sees `PATH` and `HOME`. It never sees `AWS_SECRET_ACCESS_KEY`.
- **Filesystem Fence** — Your agent can't read outside the configured project root on Linux. Landlock provides kernel enforcement and LD_PRELOAD records blocked-access events. macOS `filesystem.root` is rejected because Seatbelt cannot enforce the same root-only allowlist.
- **Network Fence** — Local proxy with domain allowlist. Your agent can reach GitHub and `api.anthropic.com`. It can't phone home to anywhere else.

## Quick Start

```bash
brew install nocktechnologies/tap/nocklock
cd your-project
nocklock init
nocklock wrap -- claude
```

That's it. Four commands. Your agent is fenced.

## How It Works

`nocklock wrap` does three things before spawning your agent:

1. **Filters environment variables** based on pass/block lists with glob patterns — Linux, macOS
2. **Fences the filesystem** — Linux: Landlock applies a kernel allowlist and LD_PRELOAD records blocked-access events. Fails closed: if the required fence can't be enforced, the agent doesn't start.
3. **Routes network traffic** through a local proxy that enforces a domain allowlist. On Linux, when the syscall fence is enabled and the network fence is active, IP socket creation is denied so native code cannot bypass the proxy; this is a fail-closed no-network posture. Disable `[syscall]` only if you accept the proxy as a userspace boundary. For HTTPS, only the hostname is inspected — no certificate injection, no payload decryption. If the proxy is not confirmed healthy, the agent does not start.

Every blocked access is logged to `.nock/events.db`. Blocked file opens and access-style checks return EACCES (permission denied); denied stat-family probes return ENOENT to avoid existence enumeration. Blocked domains return 403.

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

## Commands

| Command | Description |
|---------|-------------|
| `nocklock init` | Create `.nock/config.toml` with safe defaults |
| `nocklock wrap -- <cmd>` | Run a command inside the fence |
| `nocklock wrap --dry-run` | Validate config without starting fences or a command |
| `nocklock validate [config-path]` | Validate a config file and print the effective policy |
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

**A fence** sits between the agent and the resource. How hard the boundary is depends on the fence. The **secret fence** is absolute — a blocked variable is gone from the environment before the agent starts. On **Linux the filesystem fence** is kernel-enforced with Landlock by default and composes with LD_PRELOAD logging; static binaries and children that clear `LD_PRELOAD` are still denied by the kernel. On **macOS filesystem-root isolation is not claimed**; NockLock fails closed instead of launching an allow-default denylist. The **network fence** stops normal and prompt-injected attempts to reach unapproved domains and logs every try; on Linux with syscall fencing enabled, network-fenced runs allow only Unix-domain sockets, so the bypass-resistant posture is no IP sockets rather than proxy-based allowlisting.

NockLock doesn't restrict how your agent works. It restricts what your agent can reach. Your agent still has full permissions — inside the fence.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

---

Built by [Nock Technologies](https://nocktechnologies.io).
