# Secret Fence Design — PR #3

**Date:** 2026-04-06
**Status:** Approved
**Branch:** `feature/secret-fence`

## Purpose

First real fence implementation for NockLock. When `nocklock wrap -- <command>` runs, the child process receives a filtered environment — sensitive variables (AWS keys, Stripe secrets, database credentials, API tokens) are stripped before the agent can see them.

## Architecture

### New Package: `internal/fence/secrets/`

**`secrets.go`** — The fence engine.

- `Fence` struct holds `PassPatterns` and `BlockPatterns` (both `[]string`)
- `NewFence(pass, block []string) (*Fence, error)` — constructor, validates patterns (fail closed)
- `Filter(environ []string) (filtered []string, blocked []string)` — takes `os.Environ()` format (`KEY=VALUE`), returns filtered env and list of blocked var names
- `Match(name string, patterns []string) bool` — checks if an env var name matches any pattern using `path.Match` with case-insensitive comparison (lowercase both sides)

### Filtering Rules (order matters)

1. If a var matches ANY block pattern → **BLOCKED** (block always wins)
2. If pass list is empty → all non-blocked vars pass through
3. If pass list is non-empty → var must match a pass pattern AND not match any block pattern
4. Block takes precedence over pass in all cases

### Glob Pattern Matching

Uses `path.Match` from stdlib (no third-party dependencies). Both the pattern and env var name are lowercased before matching for case-insensitive behavior.

Supported patterns:
- `AWS_*` — prefix match
- `*_SECRET` — suffix match
- `*_SECRET*` — contains match
- `DATABASE_URL` — exact match

### Integration Points

**`internal/cli/wrap.go`:**
1. Attempt to load config from `.nock/config.toml`
2. If config file not found → warn to stderr, run passthrough (no filtering)
2b. If config exists but is invalid → fail closed (return error)
3. If config exists → create `secrets.Fence` from `cfg.Secrets.Pass` and `cfg.Secrets.Block`
4. Filter `os.Environ()` through the fence
5. Print fence status to stderr: `"NockLock: secret fence active — blocked N environment variable(s)"`
6. If logging level is "debug", list blocked var NAMES (never values)
7. Set `cmd.Env = filteredEnv` on the child process

**`internal/cli/status.go`:**
- Load config and show fence state: `Secret fence: active (blocking N patterns)`
- If no config: `No config found. Run 'nocklock init' first.`

**`internal/cli/config.go`:**
- Annotate secrets section with pattern counts when printing config

## Security Constraints

- Variable VALUES are never logged, printed, or exposed
- Block always wins over pass — no accidental exposure
- Empty pass list = permissive mode (only block applies)
- Glob matching uses stdlib only (`path.Match`)
- Fence messages go to stderr, not stdout

## Testing Strategy

Comprehensive table-driven tests in `internal/fence/secrets/secrets_test.go`:
- Basic filtering (empty lists, pass-only, block-only, both)
- Block precedence (var matches both pass and block → blocked)
- Glob patterns (prefix, suffix, contains, exact)
- Case insensitivity (both directions)
- Edge cases (empty env, no-value vars, `=` in values, empty names, duplicate patterns)
- Default config patterns (verify HOME/PATH pass, AWS_*/STRIPE_*/tokens blocked)

## Out of Scope

- SQLite event logging (PR #4)
- Filesystem fence (PR #5)
- Network fence (PR #6)
- Cloud sync
- New CLI commands
- New go.mod dependencies
