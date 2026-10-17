# Handoff: NockLock pod notes

Every run reads this first and adds to it at the end. Keep it short and true: what changed, what bit us, what is still open. The pod lead prunes it. Lasting lessons move into the gotchas in `AGENTS.md`; when an entry is only history, move it to a dated file in docs/archive (create the directory with the first one) and drop it from here.

No internal host names, personal names or absolute home paths: `scripts/check-public-content.py` scans this file like any other.

## What changed

- 2026-10-17: release notes and roadmap prepared for v0.13.0 from next 7c4d6a9: GitSpawn doctor warnings and Linux netns proof, audit/config cleanup, and contributor/CI updates. Cleanup PR #252 already removed the batch's unused compatibility paths; the later GitSpawn and CI changes need no further cleanup.
- 2026-10-17: `AGENTS.md` became the full agent index, this file was added, and CI checks that every path `AGENTS.md` names is tracked by git (`scripts/check-agents-paths.py`). `docs/REPO-MAP.md` was re-verified at next 13fa7a6. Release-level changes are in `CHANGELOG.md`.
- 2026-10-17: the path check also reads angle-bracketed and titled link targets, and no longer treats version strings as paths.
- 2026-10-17: docs-only PRs (only `*.md` or `docs/`) skip the test suites in CI. The required jobs run the detector as a step and skip their own steps, so they still report; a new step in a required job needs `if: steps.changes.outputs.code == 'true'`. A new optional test job needs `needs: changes` and the matching job `if:`.

## What bit us

- 2026-10-17, on a dev host: `go test ./...` failed in `internal/logging` under umask 002. The failure in `TestWrapComposedDefaultEgressAudit` was suspected to involve a week-old installed binary used by the egress helper; that host cause was not reverified. Both conditions are now `AGENTS.md` gotchas.
- 2026-10-17, during v0.13.0 preparation on macOS: the integration package still expects init to emit `[cloud]` after #252 removed that inert section. Its shared fixture also disables the filesystem fence while leaving syscall enforcement at the required default, so wrap refuses to start; that fixture combination is unchanged from v0.12.0. Linux-only integration cases skipped as expected. These fixture failures need remediation before claiming integration validation.

## Still open

- v0.13.0 preparation still needs review and merge to next, then an exact-head next-to-main promotion with applicable platform CI. Tagging, main-to-next back-sync, Homebrew update and installation smoke follow the release runbook. `docs/REPO-MAP.md` states the commit its paths were verified at; restamp it whenever you touch it.
