# AGENTS.md: NockLock

NockLock is an AI agent security fence: a Go CLI (`nocklock wrap -- <agent>`) that runs a coding agent behind filesystem, network, secret and syscall fences and writes every fence decision to a signed, hash-chained audit log. Linux uses Landlock, an `LD_PRELOAD` interposer, seccomp and an optional network namespace; macOS uses Seatbelt.

This is the canonical agent and contributor file; `CLAUDE.md` imports it. If this file and the code disagree, the code wins; fix the file. CI fails when this file names a path git does not track (`scripts/check-agents-paths.py`): every link target (bare, angle-bracketed or titled), and every backticked span without spaces that contains a slash or ends in a file extension with a letter in it (so version strings pass), must be a tracked file or directory inside the repo. Spans with an angle-bracket placeholder or a glob are skipped; write host paths and git refs without backticks.

Follows Engineering Standards v4.

This is a public repository. Keep `AGENTS.md` and `docs/HANDOFF.md` product-only: exclude agent and person names, card numbers, internal coordination systems and hosts, and review or merge-gate procedures.

## Start here

1. Read `docs/HANDOFF.md`: what changed lately, what bit the last run, what is still open.
2. Read the section of this file for the area you are changing.
3. At the end of your run, add to `docs/HANDOFF.md` (see the rules at its top).

## Build and test

- `go build ./cmd/nocklock`: build; `make build`: build with version ldflags; `make build-all`: also builds the Linux interposer (`internal/fence/fs/interposer/`, needs a C compiler)
- `go test ./... -count=1`: the full suite. CI runs it once on every code PR as the gate; do not run it locally before you push. A PR that changes only `*.md` files or `docs/` runs no tests in CI (`scripts/ci-code-changed.sh`); the required checks still report green.
- `go test -tags=integration ./...`: end-to-end tests against the built binary
- `GOOS=darwin GOARCH=arm64 go vet ./...`: compiles the darwin code and test files from Linux; CI runs it on every push
- `go fmt ./...` / `go vet ./...`: format and lint; `make lint` runs both. CI fails if `gofmt -l .` prints anything.
- Stack: Go 1.27.3+, cobra, BurntSushi/toml, SQLite via modernc.org/sqlite. Python 3 for scripts and the red-team bench.

## Required checks

Before you push:

1. The tests for the packages you touched pass, plus lint: `go test -count=1 $(git diff --name-only origin/next... -- '*.go' | xargs -r -n1 dirname | sort -u | while read -r d; do [ -d "$d" ] && echo "./$d"; done)` (skip it when no Go file changed), then `go vet ./...` and `gofmt -l .` (prints nothing). Not the full suite; CI runs it.
2. `python3 scripts/check-public-content.py` and `python3 scripts/check-agents-paths.py` pass.
3. Self-review for hardcoded secrets, path traversal, race conditions and subprocess injection.
4. The PR follows `CONTRIBUTING.md` and targets `next`.
5. `CHANGELOG.md` has an `[Unreleased]` entry; this file and `docs/REPO-MAP.md` are updated if structure changed.

CI: `.github/workflows/test.yml` runs build, darwin cross-vet, vet, gofmt, the content gates, the unit suite, race regressions, fuzz smoke tests, Landlock and macOS Seatbelt enforcement proofs. `.github/workflows/network-egress.yml` runs the root netns, egress and red-team jobs. `.github/workflows/gitleaks.yml` scans for secrets against `.gitleaks-baseline.json`. `.github/workflows/linux-candidate.yml` builds the Linux install candidate. `.github/workflows/landlock-abi9-receipt.yml` runs the Unix-socket and io_uring kernel cases in a KVM guest with Landlock ABI 9+ and signs the receipt.

## Rules that bite

The full list is `docs/context/invariants.md`. The ones that break builds or reviews:

- Fences fail closed. If a fence cannot initialize, the agent does not start; never fall back to passthrough.
- Unknown TOML keys are a hard error, and config changes stay backwards compatible.
- A test that proves a block also proves the allowed case still passes.
- Every fence decision is written to the signed, hash-chained event log. No decision path skips it.
- Docs, `doctor`, `wrap` banners and the README say only what is enforced, with the limits next to the claim.
- `doctor` exits 0/2/3/4; `wrap` exits 2 on startup failure or a failed blocked-event or `session_end` audit write, otherwise with the child's code. Use `exec.ExitError.ExitCode()`, never `syscall.WaitStatus`.
- Egress levels are defined once, in `internal/cli/egress_level.go`. Do not restate them elsewhere in code.
- Exported functions have doc comments; error messages are actionable.
- No new dependencies without discussion.
- Pull requests target `next`, never `main`. A maintainer promotes `next` to `main` in a release PR (`docs/runbooks/release.md`).

## Gotchas

Credential canary and mutation scripts in `scripts/` are CI-only. Their fake home, project, and audit state are separate siblings outside default grants; moving the fake home under the project or a granted temp directory correctly makes startup refuse. `internal/fence/fs/builtins.go` is the shared mandatory policy resolver.

Things you cannot guess from the code layout:

- **A skipped proof is not a pass.** Platform tests skip, not fail, when Landlock, seccomp, gcc, `sandbox-exec` or root is missing. A green local run on the wrong host may have proved nothing. Read the `-v` output for `SKIP` before you claim a fence works.
- **macOS proofs run only on ready PRs.** The Seatbelt enforcement job in `.github/workflows/test.yml` runs on non-draft pull requests only, not on pushes to `next` or `main`. Mark the PR ready to get it.
- **The public-content gate rejects internal identifiers** in every tracked file: internal host and service names, personal names and absolute home-directory paths. Write `<host>`, `<user>` or `<home>` instead. It diffs `CHANGELOG.md` against the copy on origin's next branch, so run `git fetch origin next` first or it errors locally. Its own controls are in `scripts/test_public_checks.py`.
- **Audit state lives outside the project**, under the nocklock directory in the XDG state home (default: the user's local state directory), named by a hash of the project's real path. This is a security requirement: Landlock grants a whole subtree, so state inside the fenced project would be writable by the agent. See `internal/config/state.go` and `docs/decisions/010-audit-state-outside-project.md`.
- **The config file must be trusted before it is read.** A project's .nock/config.toml in a world-writable or foreign-group-writable directory, or owned by another user, is refused. That includes every project under /tmp, so `t.TempDir()` projects are refused too: `internal/cli/audit_state_test.go` sets `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG` in `TestMain`, and `internal/config/main_test.go` installs a permissive trust seam. A new test package that loads a config needs the same. The variable is an operator-only escape hatch and is never read from config.
- **Tests must not write real audit state.** Packages that run `wrap` point `XDG_STATE_HOME` at a scratch directory in `TestMain` (`internal/cli/audit_state_test.go`); copy that, or tests leave chains in the developer's state directory.
- **Linux `wrap` needs the interposer** at its trusted path, not just a built binary (`docs/setup.md`). The privileged egress helper for `--net-fence=netns` installs separately with `sudo make install-egress-helper`.
- **The claude-code preset tests create preset-* directories in `internal/cli/`.** They are gitignored and normally cleaned up; delete leftovers from a crashed run, do not commit them.
- **Run the suite with umask 022.** Under umask 002 the temp directories come out 0775, and the audit state trust check in `internal/logging/` refuses them, so prune and receipt tests fail with "group- or world-writable". CI runners use 022.
- **Root netns tests are CI-only and run the installed binary.** They self-skip unless the egress helper is reachable through passwordless sudo, so a plain `go test ./...` on a host with the helper installed runs them. Do not run them on a shared host. The helper execs the root-owned nocklock in /usr/local/bin, not your build, so a stale install fails tests that the code under test passes; `make install` first.
- **Race-sensitive code has its own CI steps** (`go test -race -count=20` on the proxy and netns packages). Run them locally when you touch proxy shutdown.
- **Decision records live in two places:** 001 to 005 in `.claude/decisions/`, 006 onward in `docs/decisions/`. New records go in `docs/decisions/`.

## Where things are

| To change | Go to |
|---|---|
| A CLI command, flag or exit path | `internal/cli/` (`internal/cli/wrap.go` is the main command, `internal/cli/root.go` holds `Execute()`), then `docs/reference/cli.md` |
| Config keys, defaults, validation, profiles | `internal/config/`; runtime presets in `internal/config/presets/` |
| The secret fence or preflight scan | `internal/fence/secrets/`, `docs/how-it-works/secret-fence.md`, `docs/how-it-works/secret-preflight.md` |
| The filesystem fence | `internal/fence/fs/` (macOS Seatbelt), `internal/fence/fs/landlock/` (Linux), `internal/fence/fs/interposer/` (Linux C library), `docs/how-it-works/filesystem-fence.md` |
| The network fence | `internal/fence/network/` (proxy, allowlist, look-back rules), `internal/fence/network/netns/` (Linux netns mode), `docs/how-it-works/network-fence.md` |
| The syscall fence | `internal/fence/syscallfence/`, `docs/how-it-works/syscall-fence.md` |
| The audit log, signing, anchors, verification | `internal/logging/`, `internal/anchorclient/`, `pkg/receipt/` (public verifier), `docs/how-it-works/audit-log.md` |
| `doctor` and `verify` verdicts | `internal/cli/doctor.go`, `internal/cli/verify.go`, `docs/how-it-works/doctor-and-verify.md` |
| End-to-end tests | `integration/` |
| The red-team bench | `bench/redteam/` |
| Linux packaging candidate | `packaging/linux/` |
| CI | `.github/workflows/` |
| A release | `docs/runbooks/release.md` |
| User-facing docs | `README.md`, `docs/setup.md`, `docs/how-it-works/` |

## Other files

- Changelog: `CHANGELOG.md` (add to `[Unreleased]` in every PR).
- Roadmap: `docs/ROADMAP.md` (the path to 1.0).
- Architecture: `ARCHITECTURE.md` (deep package tree); `docs/REPO-MAP.md` (every package and where its tests are).
- Contributor notes: `docs/HANDOFF.md`.
- Docs index: `docs/README.md`. Designs and specs: `docs/design/`, `docs/superpowers/specs/`. Lessons: `.claude/lessons/`.
