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

## Audit database: threat model and the validate-then-open window

`logging.NewLogger` (`internal/logging/logger.go`) validates the DB path
(`validatePath`) and then creates and opens it **by pathname**: `MkdirAll`,
`OpenFile(O_NOFOLLOW)` and `sql.Open("sqlite", dbPath)` each re-resolve the path
after validation. Validation and use are therefore not atomic (N10717).

**In scope (caught).** The static malicious-repo case: a checkout that commits
`.nock/events.db`, or any ancestor of it, as a symlink. Rejected: a symlink at the
final component (`lstat` plus `O_NOFOLLOW`, N8614), a swap of the final component
after create (inode re-check), and an ancestor that escapes the project root,
dangles, loops or cannot be canonicalized (`resolveDeepestExisting`, N10714).
`nocklock wrap` opens the DB before the fence is applied, so the repository
contents are the attacker-controlled input here.

**Out of scope (residual).** A concurrent writer running as the **same uid** that
swaps a validated ancestor, or the DB path, for a symlink between validation and
use. `TestResidual_AncestorSwapBetweenValidateAndOpen` demonstrates that such a
swap redirects the DB outside the project. We accept this because the racer must
already run as the user, and that process already owns everything the swap could
protect: it can read and write `.nock/events.db` directly, read the Ed25519
signing key at `~/.config/nocklock/signing-ed25519.key`, replace the config or
the binary, and ptrace NockLock. A different uid cannot swap a `0700` directory
it does not own. The fenced child is not the racer: it starts after `NewLogger`
returns, and for the default `.nock/events.db` location the filesystem fence denies
it the audit directory.

**Why not close it in code.** An `os.Root`/`openat` walk from the project root is
not enough on its own: SQLite reopens the database, and its `-wal`/`-shm`
siblings, by pathname. On Linux, keeping the validated directory descriptor open
for the Logger's lifetime and opening `/proc/self/fd/<dirfd>/events.db` does work
with WAL (verified with `modernc.org/sqlite`). macOS has no equivalent, and a
symlink swapped in at the final component would still be followed. That is a
Linux-only mitigation for a race we do not defend against, so it is not built. If
the threat model ever includes a same-uid racer, start from that Linux path;
macOS keeps a documented residual window.

## Diagrams
- `.claude/diagrams/architecture.mermaid` — package dependencies
- `.claude/diagrams/fence-flow.mermaid` — config → fences → child process
- `.claude/diagrams/event-flow.mermaid` — events → SQLite → cloud sync
