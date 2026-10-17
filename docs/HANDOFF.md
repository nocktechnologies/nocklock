# Handoff: NockLock pod notes

Every run reads this first and adds to it at the end. Keep it short and true: what changed, what bit us, what is still open. The pod lead prunes it. Lasting lessons move into the gotchas in `AGENTS.md`; when an entry is only history, move it to a dated file in docs/archive (create the directory with the first one) and drop it from here.

No internal host names, personal names or absolute home paths: `scripts/check-public-content.py` scans this file like any other.

## What changed

- 2026-10-17: `AGENTS.md` became the full agent index, this file was added, and CI checks the paths `AGENTS.md` names (`scripts/check-agents-paths.py`). Release-level changes are in `CHANGELOG.md`.

## What bit us

- 2026-10-17, on a dev host: `go test ./...` failed in `internal/logging` under umask 002 and in `TestWrapComposedDefaultEgressAudit` because the egress helper ran a week-old installed binary. Both were the host, not the code; both are now `AGENTS.md` gotchas.

## Still open

- `docs/REPO-MAP.md` states the commit its paths were verified at; it predates v0.12.0. Re-verify and restamp it in the next change that touches it.
