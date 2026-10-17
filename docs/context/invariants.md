# Invariants

These hold for every change. [AGENTS.md](../../AGENTS.md) summarizes them; this page is the full list.

- **Fences fail closed.** If a fence cannot initialize, the agent does not start. Never fall back to passthrough. Lesson: `.claude/lessons/fail-closed-principle.md`.
- **Config parsing is strict.** Unknown TOML keys are a hard error (`internal/config/config.go`). Config changes must be backwards compatible.
- **The config file must be trusted before it is read.** `loadInto` resolves the config path component by component and refuses it when the file, or any directory the resolution passes through (ancestors, directories holding a symlink, directories a symlink leads into), is world-writable (sticky is not an exemption), group-writable by a group other than the invoker's private group (primary gid, named for the invoker, no other members; any lookup failure counts as shared), or owned by a user other than root or the invoker, so a config another user could plant or rewrite is not picked up by the next run. The file checked is the file read (`readTrustedConfig`, `internal/config/config_trust_unix.go`). This is the cross-user defense; a same-user change to an invoker-owned config is surfaced by the signed `config.digest` row, not this check. `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG` is the operator-only escape hatch for a known-safe layout.
- **Tests carry negative controls.** A test that proves a block also proves the allowed case still passes.
- **Audit rows are loud and signed.** Fence decisions are written to the hash-chained, Ed25519-signed event log. Do not add a decision path that skips it. See `docs/how-it-works/audit-log.md`.
- **Say only what is enforced.** Docs, `doctor`, `wrap` banners and the README state the real boundary, including the limits (`docs/how-it-works/`). Egress levels are defined once, in `internal/cli/egress_level.go`.
- **Exit codes**: `doctor` uses 0/2/3/4 for PROTECTED/GAPS FOUND/PARTIAL/UNPROTECTED; `wrap` returns 2 when startup fails or a blocked-event or `session_end` audit write fails, otherwise the child's exit code (`docs/reference/cli.md`). Use `exec.ExitError.ExitCode()`, never `syscall.WaitStatus` (`.claude/lessons/cross-platform-exit-codes.md`).
- **Exported functions need doc comments; error messages must be actionable.**
- **No new dependencies without discussion.**
- **Pull requests target `next`, never `main`.** A maintainer promotes `next` to `main` in a release PR (`docs/runbooks/release.md`, `CONTRIBUTING.md`).
- **Do not weaken `.claude/hooks/branch-lock.sh`** (Claude Code only). It runs as a PreToolUse hook on every Bash call (5s timeout, `.claude/settings.json`) and blocks `git checkout` / `git switch` away from the branch first touched in the session, recorded in the gitignored `.branch-lock`; delete that file to unlock. `git merge` and `git rebase` are out of scope.
