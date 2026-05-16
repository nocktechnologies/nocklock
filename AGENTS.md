# AGENTS.md — NockLock

## Project
NockLock is an AI agent security fence. Go CLI that wraps coding agents with filesystem, network, and secret isolation.

## Stack
- Go 1.22+
- cobra (CLI framework)
- BurntSushi/toml (config parser)
- SQLite (event logging — PR #4)

## Commands
- `go build ./cmd/nocklock` — build
- `go test ./... -v` — run all tests
- `go fmt ./...` — format
- `go vet ./...` — lint

## Pre-Push Checklist
1. `go test ./... -v` — all tests pass
2. `go vet ./...` — no warnings
3. `go fmt ./...` — code formatted
4. Self-review for: hardcoded secrets, path traversal, race conditions, subprocess injection

## Architecture
- cmd/nocklock/ — entry point
- internal/cli/ — cobra commands
- internal/config/ — TOML config parsing
- internal/fence/ — fence implementations (filesystem, network, secrets)
- internal/logging/ — SQLite event logging
- internal/version/ — version info

## Session Closeout

File a Session Report for every build/session before final response, even
docs-only work. Use `nockcc_session_report_create` or
`POST /api/sessions/reports/` with `session_id`, `agent_name`, `duration`,
task/PR/message/decision counts, `handoff_written`, standing-order pass/total
counts, concise notes, and 2-5 highlights. Include `nocklock` in the session
id or notes so NockCC can trace the report back to this repo.

## Code Standards
- All exported functions need doc comments
- Error messages must be actionable
- Fences fail closed (if fence can't initialize, block everything)
- No external dependencies without discussion
- Config changes must be backwards compatible
