# Architecture — NockLock

## Overview
NockLock is a Go CLI that will wrap AI coding agents with three security fences: filesystem, network, and secret isolation.

**Current state:** The CLI skeleton is working — `wrap` passes through to the child process, `init` generates a config, and `config` prints it. Fences are not yet active.

**Target state:** NockLock reads a per-project TOML config, sets up fence engines (filesystem, network, secrets), spawns the agent as a child process with isolation applied, logs fence events to SQLite, and optionally syncs events to the NockCC cloud dashboard.

## Package Structure

```text
cmd/nocklock/           Entry point — calls cli.Execute()
internal/
  cli/                  Cobra command tree
    root.go             Root command + Execute() + exitCodeError
    wrap.go             Primary command — wraps child process (passthrough today, fences planned)
    init_cmd.go         Creates .nock/config.toml with safe defaults
    config.go           Prints current config to stdout
    log.go              Views fence event log (stub)
    status.go           Shows active fenced sessions (stub)
    version.go          Prints version string
  config/               Configuration
    config.go           Config structs (6 sections) + Load() with strict TOML parsing
    defaults.go         DefaultConfig() + DefaultTOML() — security-first defaults
    config_test.go      Parse, default, error, round-trip tests
  version/              Build info
    version.go          Version string, overridable via ldflags

  --- planned packages (not yet created) ---
  fence/                Fence implementations
    filesystem.go       LD_PRELOAD / DYLD_INSERT_LIBRARIES syscall interception
    network.go          Local HTTP/HTTPS proxy with domain allowlist
    secrets.go          Environment variable filtering (pass/block lists)
  logging/              Event logging
    sqlite.go           SQLite event store for fence_events table
```

## Data Flow

### Current (passthrough mode)
1. User runs `nocklock wrap -- claude --dangerously-skip-permissions`
2. CLI parses args, prints build info to stderr
3. Child process spawned with full env (no fences applied)
4. NockLock exits with child's exit code

### Target (once fences are implemented)
1. User runs `nocklock wrap -- claude --dangerously-skip-permissions`
2. CLI parses args, loads `.nock/config.toml` (or defaults)
3. Initialize fence engines — if any fence fails to init, abort (fail closed)
4. Secret fence filters environment variables (pass/block lists)
5. Filesystem fence sets up LD_PRELOAD / DYLD_INSERT_LIBRARIES interception library
6. Network fence starts local proxy on random port
7. Child process spawned with filtered env, preload, and proxy vars
8. All fence decisions logged to `.nock/events.db` (SQLite)
9. Optional: events batched and synced to NockCC every 60s
10. NockLock exits with child's exit code

## Key Design Decisions
- See `.claude/decisions/` for Architecture Decision Records
- Go chosen for single-binary distribution and cross-platform support (ADR-001)
- MVP fences use userspace techniques — no root required (ADR-002)
- TOML config with strict parsing — unknown keys are errors (ADR-003)

## Diagrams
- `.claude/diagrams/architecture.mermaid` — package dependencies
- `.claude/diagrams/fence-flow.mermaid` — config → fences → child process
- `.claude/diagrams/event-flow.mermaid` — events → SQLite → cloud sync
