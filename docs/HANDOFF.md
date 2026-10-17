# Handoff: NockLock pod notes

Every run reads this first and adds to it at the end. Keep it short and true: what changed, what bit us, what is still open. The pod lead prunes it. Lasting lessons move into the gotchas in `AGENTS.md`; when an entry is only history, move it to a dated file in docs/archive (create the directory with the first one) and drop it from here.

No internal host names, personal names or absolute home paths: `scripts/check-public-content.py` scans this file like any other.

## What changed

- 2026-10-17: integration fixtures corrected for release validation: explicit syscall-off in the shared unfenced config, supported generated config sections, current audit DB resolution and temporary audit state. The existing integration package passes on macOS with live networking (10 top-level passes, seven Linux-only skips); actual filesystem/Landlock proof configs are unchanged.
- 2026-10-17: `AGENTS.md` became the full agent index, this file was added, and CI checks that every path `AGENTS.md` names is tracked by git (`scripts/check-agents-paths.py`). `docs/REPO-MAP.md` was re-verified at next 13fa7a6. Release-level changes are in `CHANGELOG.md`.
- 2026-10-17: the path check also reads angle-bracketed and titled link targets, and no longer treats version strings as paths.
- 2026-10-17: docs-only PRs (only `*.md` or `docs/`) skip the test suites in CI. The required jobs run the detector as a step and skip their own steps, so they still report; a new step in a required job needs `if: steps.changes.outputs.code == 'true'`. A new optional test job needs `needs: changes` and the matching job `if:`.

## What bit us

- 2026-10-17, on a dev host: `go test ./...` failed in `internal/logging` under umask 002. The failure in `TestWrapComposedDefaultEgressAudit` was suspected to involve a week-old installed binary used by the egress helper; that host cause was not reverified. Both conditions are now `AGENTS.md` gotchas.

## Still open

- Nothing yet. `docs/REPO-MAP.md` states the commit its paths were verified at; restamp it whenever you touch it.
