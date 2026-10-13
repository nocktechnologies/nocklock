# CLAUDE.md: NockLock

NockLock is an AI agent security fence: a Go CLI that wraps coding agents with filesystem, network, and secret isolation. This file is a map. Detail lives in `docs/` (start at `docs/README.md`; every package is listed in `docs/REPO-MAP.md`).

## Commands
- `go build ./cmd/nocklock`: build; `make build`: build with version ldflags; `make build-all`: also builds the Linux interposer
- `go test ./... -v`: all tests (CI runs `go test ./... -count=1`)
- `go fmt ./...` / `go vet ./...`: format and lint; `make lint` runs both
- Stack: Go 1.26+, cobra, BurntSushi/toml, SQLite via modernc.org/sqlite. No new dependencies without discussion.

## Invariants (do not break)
- **Fences fail closed.** If a fence cannot initialize, the agent does not start. Never fall back to passthrough. Lesson: `.claude/lessons/fail-closed-principle.md`.
- **Config parsing is strict.** Unknown TOML keys are a hard error (`internal/config/config.go:480`). Config changes must be backwards compatible.
- **Tests carry negative controls.** A test that proves a block also proves the allowed case still passes.
- **Audit rows are loud and signed.** Fence decisions are written to the hash-chained, Ed25519-signed event log. Do not add a decision path that skips it. See `docs/how-it-works/audit-log.md`.
- **Say only what is enforced.** Docs, `doctor`, `wrap` banners and the README state the real boundary, including the limits (`docs/how-it-works/`). Egress levels are defined once, in `internal/cli/egress_level.go`.
- **Exit codes**: `doctor` uses 0/2/3/4 for PROTECTED/GAPS FOUND/PARTIAL/UNPROTECTED; `wrap` returns 2 when startup fails or the child's exit code (`docs/reference/cli.md`). Use `exec.ExitError.ExitCode()`, never `syscall.WaitStatus` (`.claude/lessons/cross-platform-exit-codes.md`).
- **Exported functions need doc comments; error messages must be actionable.**
- **Do not weaken `.claude/hooks/branch-lock.sh`.** It runs as a PreToolUse hook on every Bash call (5s timeout, `.claude/settings.json`) and blocks `git checkout` / `git switch` away from the branch first touched in the session, recorded in the gitignored `.branch-lock`; delete that file to unlock. `git merge` and `git rebase` are out of scope.

## Where things are
- `docs/REPO-MAP.md`: every directory and key package, with where its tests are
- `docs/setup.md`: install, first run, verify
- `docs/how-it-works/`: one page per fence or feature, with honest limits
- `docs/reference/cli.md`: commands, exit codes, config schema as they exist today
- `docs/runbooks/`: release, incident
- `docs/decisions/`: decision records (the first five stay in `.claude/decisions/`)
- `docs/ROADMAP.md`: the path to 1.0
- `docs/design/`, `docs/superpowers/specs/`: design notes and specs; `ARCHITECTURE.md`: deep package tree
- `.claude/diagrams/`, `.claude/design/`, `.claude/lessons/`, `.claude/review/PIPELINE.md`: diagrams, UI tokens, lessons, review pipeline

## Session Closeout
File a Session Report for every build/session before the final response, even docs-only work. Use `nockcc_session_report_create` or `POST /api/sessions/reports/` with `session_id`, `agent_name`, `duration`, task/PR/message/decision counts, `handoff_written`, standing-order pass/total counts, concise notes, and 2-5 highlights. Include `nocklock` in the session id or notes.

## Pre-Push Checklist
1. `go test ./... -v`, `go vet ./...`, `go fmt ./...` clean
2. Self-review for hardcoded secrets, path traversal, race conditions, subprocess injection
3. Review pipeline complete (`.claude/review/PIPELINE.md`)
4. `CHANGELOG.md` updated; this file and `docs/REPO-MAP.md` updated if structure changed
