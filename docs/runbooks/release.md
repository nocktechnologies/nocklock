# Runbook: release

Reconstructed from repo history at `origin/main` 89c02fa. This repo has no release workflow and no release script (`.github/workflows/` holds `test.yml`, `network-egress.yml`, `gitleaks.yml`, `claude.yml`, `claude-code-review.yml`). Steps marked **confirm** are not recorded in this repo; get them from the release owner before relying on them, and then edit this page.

## What past releases did
Each release is a lightweight git tag `vX.Y.Z` on the merge commit of a PR titled `CHANGELOG: vX.Y.Z release section`: v0.6.1 on the merge of #153, v0.7.0 on a793375 (#164), and v0.8.0 on db1a273 (#176). In each, `CHANGELOG.md` moves `[Unreleased]` entries under a new `## [X.Y.Z] - YYYY-MM-DD` heading with a short summary paragraph (`CHANGELOG.md` for 0.8.0). `make build` stamps the version from `git describe --tags --always --dirty` through ldflags (`Makefile`), so the tag is the version.

## Steps
1. **Freeze.** All intended PRs merged to `main`, each with its `CHANGELOG.md` entry under `[Unreleased]`. Anything user-visible that changes a documented boundary also updates `README.md` and the matching `docs/how-it-works/` page.
2. **Gate.** On `main`: `go build ./...`, `go vet ./...`, `gofmt -l .` empty, `go test ./... -count=1`, and CI green on `test.yml` (build, vet, fmt, test, Landlock proofs, fuzz smoke, macOS SBPL proof) and `network-egress.yml`. Run `go test -tags=integration ./...` (`CONTRIBUTING.md`).
3. **Changelog PR.** Branch, rename `[Unreleased]` to `[X.Y.Z] - date`, add a leading summary paragraph, add a fresh empty `[Unreleased]`. Call out every breaking change under `### Breaking` and every security-relevant behavior change under `### Security`, with upgrade steps (see `CHANGELOG.md` for the pattern). Review as usual (`.claude/review/PIPELINE.md`); a human merges.
4. **Tag** the merge commit: `git tag vX.Y.Z <sha> && git push origin vX.Y.Z`. **Confirm** who may push tags and whether tag protection applies.
5. **Distribution.** `README.md` installs with `brew install nocktechnologies/tap/nocklock`. **Confirm** how the tap formula and any release binaries are updated; nothing in this repo does it.
6. **Smoke.** On a clean Linux and a clean macOS host: install the new build, `nocklock version`, `nocklock init`, `nocklock doctor`, `nocklock verify`, `nocklock wrap -- true` (`docs/setup.md`). On Linux, first install `libfence_fs.so`, which `make install` does not provide: run `make build-all`, then `sudo install -D -m 0644 internal/fence/fs/interposer/libfence_fs.so /usr/local/lib/nocklock/libfence_fs.so` (or place it next to the `nocklock` binary or in `/usr/lib/nocklock/`; `findTrustedLibFenceFS` in `internal/cli/wrap.go`). Until packaging lands (N11643), `wrap -- true` fails without it. Then also run `scripts/test-init-default-linux.sh` (what CI runs).
7. **Record.** File the session report (`CLAUDE.md` Session Closeout).

## Rolling back
Tags are not moved. Ship a patch release (`X.Y.Z+1`) that reverts or fixes, with a `### Security` or `### Fixed` entry saying what was wrong. For a defective tap formula, **confirm** the formula owner.
