# Architecture — NockLock

## Overview
NockLock is a Go CLI that wraps AI coding agents with three security fences: filesystem, network, and secret isolation. It reads a per-project TOML config, sets up fence engines, spawns the agent as a child process, logs fence events to SQLite, and optionally syncs events to the NockCC cloud dashboard.

## Package Structure

```
cmd/nocklock/           Entry point — calls cli.Execute()
internal/
  cli/                  Cobra command tree
    root.go             Root command + Execute() + exitCodeError
    wrap.go             Primary command — wraps child process with fences
    init_cmd.go         Creates .nock/config.toml with safe defaults
    config.go           Prints current config to stdout
    log.go              Views fence event log (stub, pending PR #4)
    status.go           Shows active fenced sessions (stub)
    version.go          Prints version string
  config/               Configuration
    config.go           Config structs (6 sections) + Load() with strict TOML parsing
    defaults.go         DefaultConfig() + DefaultTOML() — security-first defaults
    config_test.go      Parse, default, error, round-trip tests
  fence/                Fence implementations (planned)
    filesystem.go       LD_PRELOAD / DYLD_INSERT_LIBRARIES syscall interception
    network.go          Local HTTP/HTTPS proxy with domain allowlist
    secrets.go          Environment variable filtering (pass/block lists)
  logging/              Event logging (planned)
    sqlite.go           SQLite event store for fence_events table
  version/              Build info
    version.go          Version string, overridable via ldflags
```

## Data Flow

1. User runs `nocklock wrap -- claude --dangerously-skip-permissions`
2. CLI parses args, loads `.nock/config.toml` (or defaults)
3. Secret fence filters environment variables (pass/block lists)
4. Filesystem fence sets up LD_PRELOAD interception library
5. Network fence starts local proxy on random port
6. Child process spawned with filtered env, preload, and proxy vars
7. All fence decisions logged to `.nock/events.db` (SQLite)
8. Optional: events batched and synced to NockCC every 60s
9. NockLock exits with child's exit code

## Key Design Decisions
- See `.claude/decisions/` for Architecture Decision Records
- Go chosen for single-binary distribution and cross-platform support (ADR-001)
- MVP fences use userspace techniques — no root required (ADR-002)
- TOML config with strict parsing — unknown keys are errors (ADR-003)

## Diagrams
- `.claude/diagrams/architecture.mermaid` — package dependencies
- `.claude/diagrams/fence-flow.mermaid` — config → fences → child process
- `.claude/diagrams/event-flow.mermaid` — events → SQLite → cloud sync
