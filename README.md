# NockLock

**Fence, not guardrails.** Sandbox your AI agents without restricting how they work.

NockLock puts a fence around your AI coding agent — controlling what secrets it can see, what files it can access, and what domains it can reach. Your agent runs with full permissions inside the fence. Nothing gets out.

## Why NockLock?

Your AI agent runs with `--dangerously-skip-permissions`. It has access to your environment variables, your filesystem, your network. NockLock doesn't change how your agent works — it controls what it can reach.

- **Secret Fence** — Filter environment variables. Your agent sees `PATH` and `HOME`. It never sees `AWS_SECRET_ACCESS_KEY`.
- **Filesystem Fence** — LD_PRELOAD interception. Your agent can read the project directory. It can't read `~/.ssh/`.
- **Network Fence** — Local proxy with domain allowlist. Your agent can reach `github.com` and `api.anthropic.com`. It can't phone home to anywhere else.

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

1. **Filters environment variables** based on pass/block lists with glob patterns
2. **Intercepts filesystem calls** via LD_PRELOAD, blocking access outside allowed paths
3. **Routes network traffic** through a local proxy that enforces a domain allowlist

Every blocked access is logged to `.nock/events.db`. Your agent doesn't know the fence exists — blocked files return "not found", blocked domains return 403.

## Configuration

`nocklock init` creates `.nock/config.toml` with sensible defaults:

```toml
[secrets]
pass = ["HOME", "PATH", "SHELL", "USER", "LANG", "TERM"]
block = ["AWS_*", "STRIPE_*", "DATABASE_URL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "*_SECRET*", "*_PASSWORD*", "*_TOKEN*"]

[filesystem]
root = "."
mode = "read-write"
allow = ["~/.claude/", "/tmp/"]
deny = ["~/.ssh/", "~/.aws/", "~/.gnupg/", "~/.nock/"]

[network]
allow = ["github.com", "api.github.com", "api.anthropic.com", "registry.npmjs.org", "pypi.org", "rubygems.org", "crates.io"]
allow_all = false

[logging]
db = ".nock/events.db"
level = "info"
```

Defaults are deliberately safe. Customize per project.

## Commands

| Command | Description |
|---------|-------------|
| `nocklock init` | Create `.nock/config.toml` with safe defaults |
| `nocklock wrap -- <cmd>` | Run a command inside the fence |
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
make build
```

Requires Go 1.26+. The binary is built to `./nocklock`.

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

```
$ nocklock log --blocked
Session a1b2c3d4  started 2026-04-09 14:23:01  ended 2026-04-09 14:47:33  (24m 32s)
  secret_blocked: AWS_SECRET_ACCESS_KEY
  file_blocked: open /home/user/.ssh/id_rsa
  network_blocked: CONNECT evil.example.com:443

Total: 3 event(s) across 1 session(s), 3 blocked, 0 passed
```

```
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

## Platform Support

| Fence | Linux | macOS | Windows |
|-------|-------|-------|---------|
| Secret | Yes | Yes | Yes |
| Filesystem | Yes (LD_PRELOAD) | Coming soon | Not planned |
| Network | Yes | Yes | Yes |

## Philosophy

NockLock is a fence, not guardrails. The distinction matters.

**Guardrails** tell the agent what not to do. The agent can ignore them, work around them, or hallucinate past them. Guardrails are prompts.

**A fence** sits between the agent and the resource. The agent can't read `~/.ssh/id_rsa` because the syscall returns EACCES. The agent can't reach `evil.com` because the proxy returns 403. No amount of prompt injection changes this.

NockLock doesn't restrict how your agent works. It restricts what your agent can reach. Your agent still has full permissions — inside the fence.

## HTTPS Privacy

The network fence inspects the hostname from the HTTP CONNECT request to decide whether to allow a connection. It does not perform MITM, inject certificates, or decrypt traffic. The encrypted payload is never touched.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

---

Built by [Nock Technologies](https://nocktechnologies.io).
