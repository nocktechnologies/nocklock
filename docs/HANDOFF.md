# Handoff: NockLock contributor notes

Every run reads this first and adds to it at the end. Keep it short and true: what changed, what bit us, what is still open. Maintainers prune it. Lasting lessons move into the gotchas in `AGENTS.md`; when an entry is only history, move it to a dated file in docs/archive (create the directory with the first one) and drop it from here.

No internal host names, personal names or absolute home paths: `scripts/check-public-content.py` scans this file like any other.

## What changed

- 2026-10-22: doctor checks dotenv files only at the project root and one directory level below, skipping dependency/build directories. Incomplete inspection is informational; actual matches retain PARTIAL. The CI credential proof now cleans its isolated process session on every exit path, with mocked lifecycle regression tests that do not execute enforcement locally.

- 2026-10-22: mandatory credential denies now share one policy resolver across Linux and macOS; broad grants refuse. macOS home filename prefixes protect agent and dotenv stores, and presets persist their own login exception. Doctor inspects project dotenv metadata without adding denies. CI-only fake-home canaries and policy-removal mutations cover both backends; pre-made project hardlinks remain a documented limitation.

- 2026-10-18: contributor guidance now states that this public repository's agent index and handoff stay product-only. Existing coordination wording in those files was replaced with neutral terms.
- 2026-10-17: release notes and roadmap prepared for v0.13.0 from next 7ee2a6e: GitSpawn doctor warnings and Linux netns proof, audit/config cleanup, and contributor/CI updates. Cleanup PR #252 already removed the batch's unused compatibility paths; the later GitSpawn and CI changes need no further cleanup.
- 2026-10-17: integration fixtures corrected for release validation: explicit syscall-off in the shared unfenced config, supported generated config sections, current audit DB resolution and temporary audit state. The existing integration package passes on macOS with live networking (10 top-level passes, seven Linux-only skips); actual filesystem/Landlock proof configs are unchanged.
- 2026-10-17: `AGENTS.md` became the full agent index, this file was added, and CI checks that every path `AGENTS.md` names is tracked by git (`scripts/check-agents-paths.py`). `docs/REPO-MAP.md` was re-verified at next 13fa7a6. Release-level changes are in `CHANGELOG.md`.
- 2026-10-17: the path check also reads angle-bracketed and titled link targets, and no longer treats version strings as paths.
- 2026-10-17: docs-only PRs (only `*.md` or `docs/`) skip the test suites in CI. The required jobs run the detector as a step and skip their own steps, so they still report; a new step in a required job needs `if: steps.changes.outputs.code == 'true'`. A new optional test job needs `needs: changes` and the matching job `if:`.

- 2026-10-19: `.github/workflows/landlock-abi9-receipt.yml` runs `bench/redteam/kernel_cases.py --require-abi 9` in a throwaway Ubuntu 26.10 KVM guest (kernel 7.3) on a GitHub-hosted runner and signs the receipt (ROADMAP bar 1: receipt produced in CI, not yet released). Landlock ABI 9 first shipped in Linux 7.1 (7.0 reports 8), so the hosted runner kernel cannot prove it itself. `packaging/linux/sign-manifest.sh` is now shared with the candidate workflow. The guest image is pinned by URL and digest; when Ubuntu prunes that release directory, bump both together.

## What bit us

- 2026-10-22: mandatory credential denies make a fake home beneath /tmp incompatible with the default /tmp allow, and root=/ is now refused even in network-only fixtures. CLI fixtures keep fake homes beside the package and network proofs grant their temporary project plus runtime paths.

- 2026-10-17, on a dev host: `go test ./...` failed in `internal/logging` under umask 002. The failure in `TestWrapComposedDefaultEgressAudit` was suspected to involve a week-old installed binary used by the egress helper; that host cause was not reverified. Both conditions are now `AGENTS.md` gotchas.

## Still open

- The existing opencode and goose presets grant paths beneath the mandatory home .config deny and now refuse startup. They need a separately reviewed runtime configuration that relocates required files without broadening credential access.
- `docs/REPO-MAP.md` states the commit its paths were verified at; restamp it whenever you touch it.
