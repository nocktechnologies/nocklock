# Invariants

These hold for every change. [AGENTS.md](../../AGENTS.md) summarizes them; this page is the full list.

- **Fences fail closed.** If a fence cannot initialize, the agent does not start. Never fall back to passthrough. Lesson: `.claude/lessons/fail-closed-principle.md`.
- **Config parsing is strict.** Unknown TOML keys are a hard error (`internal/config/config.go`). Config changes must be backwards compatible.
- **Tests carry negative controls.** A test that proves a block also proves the allowed case still passes.
- **Audit rows are loud and signed.** Fence decisions are written to the hash-chained, Ed25519-signed event log. Do not add a decision path that skips it. See `docs/how-it-works/audit-log.md`.
- **Say only what is enforced.** Docs, `doctor`, `wrap` banners and the README state the real boundary, including the limits (`docs/how-it-works/`). Egress levels are defined once, in `internal/cli/egress_level.go`.
- **Exit codes**: `doctor` uses 0/2/3/4 for PROTECTED/GAPS FOUND/PARTIAL/UNPROTECTED; `wrap` returns 2 when startup fails or the child's exit code (`docs/reference/cli.md`). Use `exec.ExitError.ExitCode()`, never `syscall.WaitStatus` (`.claude/lessons/cross-platform-exit-codes.md`).
- **Exported functions need doc comments; error messages must be actionable.**
- **No new dependencies without discussion.** The stack is Go 1.26+, cobra, BurntSushi/toml and SQLite via modernc.org/sqlite.
- **Do not weaken `.claude/hooks/branch-lock.sh`.** It runs as a PreToolUse hook on every Bash call (5s timeout, `.claude/settings.json`) and blocks `git checkout` / `git switch` away from the branch first touched in the session, recorded in the gitignored `.branch-lock`; delete that file to unlock. `git merge` and `git rebase` are out of scope.
