# Architecture — NockLock

## Overview
NockLock is a Go CLI that wraps AI coding agents with three security fences: filesystem, network, and secret isolation.

**Current state:** The secret and network fences are active, and Linux has a
kernel-enforced root filesystem fence (Landlock plus LD_PRELOAD event logging).
All fence events are logged to SQLite. macOS supports secret and network
fencing, but the shipped CLI deliberately refuses a configured
`filesystem.root`: its Seatbelt component is an allow-default sensitive-path
denylist, not a root-only filesystem boundary.

**Target state:** Preserve all three active fence categories while adding a
macOS filesystem backend only when it can prove the same root-only boundary as
the Linux path; optional NockCC cloud dashboard sync remains separate.

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
    fs/                 Filesystem fence — config processing, Linux enforcement, Seatbelt profile component
      interposer/       C shared library for LD_PRELOAD interception (Linux only)
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
5. With `filesystem.root` configured on Linux, the filesystem fence applies
   Landlock and LD_PRELOAD with libfence_fs.so, then opens a Unix socket for events
6. With `filesystem.root` configured on macOS, NockLock refuses before child
   launch because Seatbelt cannot provide the requested root-only boundary
7. The network fence starts its domain-allowlist proxy when configured
8. Child process is spawned with the filtered environment and active fence wiring
9. Filesystem and network decisions are logged to `.nock/events.db`
10. NockLock exits with the child's exit code

### Future
- A macOS filesystem-root backend must prove out-of-root write refusal before
  `filesystem.root` can be enabled there.
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
