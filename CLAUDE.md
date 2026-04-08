# CLAUDE.md — NockLock

## Project
NockLock is an AI agent security fence. Go CLI that wraps coding agents with filesystem, network, and secret isolation.

## Stack
- Go 1.26+ (single binary, cross-platform)
- cobra (CLI framework)
- BurntSushi/toml (config parser)
- SQLite (event logging — planned)

## Commands
- `go build ./cmd/nocklock` — build
- `make build` — build with version ldflags
- `go test ./... -v` — run all tests
- `go fmt ./...` — format
- `go vet ./...` — lint
- `make lint` — fmt + vet

## Structure
- `cmd/nocklock/` — entry point (main.go)
- `internal/cli/` — cobra command tree (wrap, init, config, log, status, version)
- `internal/config/` — TOML config parsing, defaults, validation
- `internal/version/` — build version info
- `internal/fence/` — fence implementations: filesystem, network, secrets *(planned, not yet created)*
- `internal/logging/` — SQLite event logging *(planned, not yet created)*

## Detailed Context
All detailed documentation lives in the .claude/ directory:
- `.claude/diagrams/` — Mermaid architecture diagrams
- `.claude/design/` — DESIGN.md with brand tokens and UI spec
- `.claude/lessons/` — Lessons learned, anti-patterns, incident notes
- `.claude/decisions/` — Architecture Decision Records (ADRs)
- `.claude/review/` — Review pipeline instructions, pre-push checklist

## Code Standards
- All exported functions need doc comments
- Error messages must be actionable
- Fences fail closed (if fence can't initialize, block everything)
- No external dependencies without discussion
- Config changes must be backwards compatible

## Pre-Push Checklist
1. `go test ./... -v` — all tests pass
2. `go vet ./...` — no warnings
3. `go fmt ./...` — code formatted
4. Self-review for: hardcoded secrets, path traversal, race conditions, subprocess injection
5. Review pipeline complete (see `.claude/review/PIPELINE.md`)
6. CHANGELOG.md updated
7. CLAUDE.md updated if structure changed
