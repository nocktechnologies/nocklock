# nocklock

AI agent security fence. Prevent your coding agents from escaping their sandbox.

## The Problem

AI coding agents (Claude Code, Cursor, Copilot, Windsurf) run with full access
to your filesystem, network, and environment variables. One prompt injection,
one hallucinated command, one bad dependency — and your agent can:

- Read your SSH keys and AWS credentials
- Exfiltrate code to external servers
- Delete files outside the project directory
- Access production databases
- Push to repos it shouldn't touch

## The Solution

NockLock wraps your agent in an invisible fence. Three boundaries:

- **Filesystem fence** — agent can only read/write inside the project directory
- **Network fence** — agent can only reach approved domains (GitHub, npm, PyPI)
- **Secret fence** — agent only sees environment variables you explicitly allow

Zero config defaults. The fence is invisible until something hits it.

> **Current status:** NockLock is in early development. The CLI skeleton and config
> system are working. Fence implementations are coming in upcoming PRs.

## Install (from source)

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
go build -o nocklock ./cmd/nocklock
```

## Usage

```bash
# Initialize fence config in your project
cd my-project
nocklock init

# View your config
nocklock config

# Wrap your agent (passthrough mode — fences coming soon)
nocklock wrap -- claude --dangerously-skip-permissions

# Check version
nocklock version
```

## What It Will Look Like (once fences are active)

```
$ nocklock log
2026-04-05 02:14:33 | filesystem | BLOCKED | open ~/.ssh/id_rsa
2026-04-05 02:14:35 | network    | BLOCKED | CONNECT evil.com:443
2026-04-05 02:15:01 | secret     | BLOCKED | env AWS_SECRET_ACCESS_KEY
2026-04-05 02:15:44 | filesystem | allowed | open src/main.py
```

Your agent never knew the fence was there. You sleep better at night.

## Roadmap

- [x] CLI skeleton + config system (PR #1)
- [ ] Secret fence — environment variable filtering (PR #3)
- [ ] Filesystem fence — LD_PRELOAD/DYLD_INSERT_LIBRARIES (PR #5)
- [ ] Network fence — local proxy with domain allowlist (PR #6)
- [ ] SQLite event logging (PR #4)
- [ ] Homebrew tap + CI (PR #8)

## Dashboard (Coming Soon)

Connect to [NockCC](https://nocktechnologies.io) for cloud monitoring:
- See fence events across all your machines
- Get Telegram/Slack alerts on blocked escape attempts
- Team visibility — know what every developer's agents are doing

## License

MIT
