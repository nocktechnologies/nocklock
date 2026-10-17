# Handoff: NockLock pod notes

Every run reads this first and adds to it at the end. Keep it short and true: what changed, what bit us, what is still open. The pod lead prunes it. When an entry is only history, move it to a dated file in docs/archive (create the directory with the first one) and drop it from here.

No internal host names, personal names or absolute home paths: `scripts/check-public-content.py` scans this file like any other.

## What changed

- 2026-10-17: `AGENTS.md` is now the full agent index (build, checks, rules, gotchas, locations). `CLAUDE.md` imports it and holds only Claude Code notes. This file added. `scripts/check-agents-paths.py` runs in the `test` job of `.github/workflows/test.yml` and fails when `AGENTS.md` names a path that does not exist.
- 2026-10-17: v0.12.0 released (config trust walk, `doctor` deputies, in-run anchor checkpoints, signed Linux install candidates in CI). `next` has since gained the GitSpawn `doctor` warning and its Linux CI proof; see `CHANGELOG.md` `[Unreleased]`.

## What bit us

- Platform proofs skip, not fail, on a host without Landlock, seccomp, gcc, `sandbox-exec` or root. Read `-v` output for `SKIP` before reporting a fence as proven.
- The public-content gate needs `git fetch origin next` locally, and rejects internal identifiers anywhere in tracked files, including this one and `CHANGELOG.md`.
- 2026-10-17, on a dev host: `go test ./...` failed in `internal/logging` under umask 002 (0775 temp dirs refused) and in `TestWrapComposedDefaultEgressAudit` because the egress helper ran a week-old installed binary. Both were the host, not the code: umask 022 fixes the first, `make install` the second.
- The config trust walk refuses projects under `/tmp`. Test packages that load a config need the `TestMain` setup described in `AGENTS.md`.

## Still open

- `docs/REPO-MAP.md` states the commit its paths were verified at; it predates v0.12.0. Re-verify and restamp it in the next change that touches it.
