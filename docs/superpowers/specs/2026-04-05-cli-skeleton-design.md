# NockLock PR #1: CLI Skeleton + Project Structure — Design Spec

**Status:** Approved  
**Date:** 2026-04-05  
**Branch:** `feature/cli-skeleton` from `main`

---

## Summary

First PR for NockLock — a Go CLI that wraps AI coding agents with filesystem, network, and secret isolation. This PR builds only the skeleton: project structure, CLI commands via cobra, TOML config parsing, and a passthrough `wrap` command. No fence implementations.

## Architecture

Single Go binary. Two dependencies: `spf13/cobra` (CLI), `BurntSushi/toml` (config).

```
nocklock/
├── cmd/nocklock/main.go           — Entry point
├── internal/
│   ├── cli/
│   │   ├── root.go                — Root command, global flags
│   │   ├── wrap.go                — wrap command (passthrough)
│   │   ├── init_cmd.go            — init command (generates config)
│   │   ├── log.go                 — log command (stub)
│   │   ├── config.go              — config command (prints config)
│   │   ├── status.go              — status command (stub)
│   │   └── version.go             — version command
│   ├── config/
│   │   ├── config.go              — Config struct, TOML parsing
│   │   ├── config_test.go         — Tests
│   │   └── defaults.go            — Default config values
│   └── version/
│       └── version.go             — Version string, build info
├── .nock/config.toml.example      — Example config
├── CLAUDE.md                      — Repo context
├── Makefile                       — Build targets
├── go.mod / go.sum
└── README.md                      — Updated with adapted pitch
```

## Commands

| Command | PR #1 Behavior |
|---|---|
| `nocklock version` | Prints `NockLock v0.1.0 (dev)` |
| `nocklock init` | Creates `.nock/config.toml` with safe defaults; idempotent |
| `nocklock wrap -- <cmd>` | Passthrough: prints banner, spawns child, forwards stdio, exits with child's code |
| `nocklock config` | Reads/prints `.nock/config.toml` or prompts user to run init |
| `nocklock log` | Stub: "No fence events recorded..." |
| `nocklock status` | Stub: "No active fenced sessions." |

## Config Structure

Six TOML sections: `project`, `filesystem`, `network`, `secrets`, `logging`, `cloud`. Security-first defaults — deny sensitive dirs (`~/.ssh/`, `~/.aws/`), block secret env vars (`AWS_*`, `*_TOKEN*`), allow only common dev domains. Full struct and defaults as specified in PROMPT_NOCKLOCK_PR1_CLI_SKELETON.md.

## Wrap Passthrough

Critical proof-of-concept. `nocklock wrap -- echo "hello"` spawns the child process, forwards stdin/stdout/stderr, and exits with the child's exit code. No fencing or filtering — validates the mechanism before fences are added in PR #3-6.

## Tests

`internal/config/config_test.go`:
- `TestParseConfig` — valid TOML parses correctly
- `TestDefaultConfig` — generated defaults match expected values
- `TestConfigNotFound` — missing file returns appropriate error

## README

Adapted from DESIGN_NOCK_CLI_ARCHITECTURE.md section 8: `nock` changed to `nocklock`, honest about current state (fences coming), keeps the compelling problem/solution pitch.

## Out of Scope

- Fence implementations (PR #3-6)
- SQLite logging (PR #4)
- Event types/models (PR #4)
- LD_PRELOAD or proxy code (PR #5-6)
- Homebrew tap (PR #8)
- GitHub Actions CI (PR #8)
