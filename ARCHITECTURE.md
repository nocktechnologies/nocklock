# Architecture — NockLock

## Overview
NockLock is a Go CLI that wraps AI coding agents with three security fences: filesystem, network, and secret isolation.

**Current state:** Two fences are active — the secret fence filters environment variables, and the filesystem fence (Linux) intercepts libc calls via LD_PRELOAD. All fence events are logged to SQLite. The network fence is planned for the next PR.

**Target state:** All three fences active, with optional NockCC cloud dashboard sync.

## Package Structure

```text
cmd/nocklock/           Entry point — calls cli.Execute()
internal/
  cli/                  Cobra command tree
    root.go             Root command + Execute() + exitCodeError
    wrap.go             Primary command — wraps child process with secret + filesystem fences
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

  fence/                Fence implementations
    secrets/            Secret fence — environment variable filtering (pass/block lists)
    fs/                 Filesystem fence — config processing, Go wrapper, event listener
      interposer/       C shared library for LD_PRELOAD interception (Linux only)
    --- planned ---
    network/            Network fence — local proxy with domain allowlist
  logging/              Event logging
    logger.go           SQLite event store — Log, LogBatch, Query, Stats, Prune
```

## Data Flow

### Current
1. User runs `nocklock wrap -- claude --dangerously-skip-permissions`
2. CLI parses args, loads `.nock/config.toml` (walks up directory tree)
3. Initialize fence engines — if any fence fails to init, abort (fail closed)
4. Secret fence filters environment variables (pass/block lists)
5. Filesystem fence (Linux) sets up LD_PRELOAD with libfence_fs.so, opens Unix socket for events
6. Child process spawned with filtered env and preload vars
7. Filesystem fence events received over socket, logged to SQLite
8. All fence decisions logged to `.nock/events.db`
9. NockLock exits with child's exit code

### Target (once network fence is added)
- Network fence starts local proxy on random port, adds proxy env vars
- Optional: events batched and synced to NockCC cloud dashboard

## Key Design Decisions
- See `.claude/decisions/` for Architecture Decision Records
- Go chosen for single-binary distribution and cross-platform support (ADR-001)
- MVP fences use userspace techniques — no root required (ADR-002)
- TOML config with strict parsing — unknown keys are errors (ADR-003)

## Diagrams
- `.claude/diagrams/architecture.mermaid` — package dependencies
- `.claude/diagrams/fence-flow.mermaid` — config → fences → child process
- `.claude/diagrams/event-flow.mermaid` — events → SQLite → cloud sync
