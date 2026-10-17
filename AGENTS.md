# AGENTS.md: NockLock

NockLock is an AI agent security fence: a Go CLI that wraps coding agents with filesystem, network, and secret isolation. This is the canonical agent and contributor file; `CLAUDE.md` imports it. It is a map: detail lives in `docs/` (start at `docs/README.md`). If this file and the code disagree, the code wins; fix the file.

Follows Engineering Standards v4.

## Where things are

| To change | Go to |
|---|---|
| A CLI command, flag or exit path | `internal/cli/` (`wrap.go` is the main command; `root.go` holds `Execute()`), then `docs/reference/cli.md` |
| Egress levels | `internal/cli/egress_level.go` (the only definition) |
| Config keys, defaults, validation, profiles | `internal/config/`; runtime presets in `internal/config/presets/` |
| The secret fence or preflight scan | `internal/fence/secrets/`, `docs/how-it-works/secret-fence.md`, `secret-preflight.md` |
| The filesystem fence | `internal/fence/fs/` (macOS Seatbelt), `internal/fence/fs/landlock/` (Linux), `internal/fence/fs/interposer/` (Linux C library), `docs/how-it-works/filesystem-fence.md` |
| The network fence | `internal/fence/network/` (proxy, allowlist, look-back rules), `internal/fence/network/netns/` (Linux netns mode), `docs/how-it-works/network-fence.md` |
| The syscall fence | `internal/fence/syscallfence/`, `docs/how-it-works/syscall-fence.md` |
| The audit log, signing, anchors, verification | `internal/logging/`, `internal/anchorclient/`, `pkg/receipt/` (public verifier), `docs/how-it-works/audit-log.md` |
| `doctor` and `verify` verdicts | `internal/cli/doctor.go`, `internal/cli/verify.go`, `docs/how-it-works/doctor-and-verify.md` |
| End-to-end tests | `integration/` |
| The red-team bench | `bench/redteam/` |
| CI | `.github/workflows/` |
| A release | `docs/runbooks/release.md`, `CHANGELOG.md` |
| User-facing docs | `README.md`, `docs/setup.md`, `docs/how-it-works/` |

More: `docs/REPO-MAP.md` (every package and where its tests are), `ARCHITECTURE.md` (deep package tree), `docs/ROADMAP.md` (the path to 1.0), `docs/decisions/` and `.claude/decisions/` (decision records), `docs/design/` and `docs/superpowers/specs/` (designs and specs), `.claude/lessons/` (lessons).

## Build and test

- `go build ./cmd/nocklock`: build; `make build`: build with version ldflags; `make build-all`: also builds the Linux interposer
- `go test ./... -v`: all tests (CI runs `go test ./... -count=1`)
- `go test -tags=integration ./...`: end-to-end tests against the built binary
- `go fmt ./...` / `go vet ./...`: format and lint; `make lint` runs both
- Stack: Go 1.26+, cobra, BurntSushi/toml, SQLite via modernc.org/sqlite.

## Required checks

Before you push:

1. `go test ./... -v`, `go vet ./...` and `go fmt ./...` are clean.
2. `python3 scripts/check-public-content.py` passes (CI runs it; it rejects internal identifiers in tracked files).
3. Self-review for hardcoded secrets, path traversal, race conditions and subprocess injection.
4. The PR follows `CONTRIBUTING.md`.
5. `CHANGELOG.md` is updated; this file and `docs/REPO-MAP.md` are updated if structure changed.

CI (`.github/workflows/test.yml`) also runs the darwin cross-vet, race regressions, fuzz smoke tests, Landlock and macOS Seatbelt enforcement proofs; `network-egress.yml` runs the egress and red-team jobs; `gitleaks.yml` scans for secrets.

## Rules that bite

Full list: [docs/context/invariants.md](docs/context/invariants.md).

- Fences fail closed. If a fence cannot initialize, the agent does not start; never fall back to passthrough.
- Unknown TOML keys are a hard error, and config changes stay backwards compatible.
- A test that proves a block also proves the allowed case still passes.
- Every fence decision is written to the signed, hash-chained event log. No decision path skips it.
- Docs, `doctor`, `wrap` banners and the README say only what is enforced, with the limits next to the claim.
- `doctor` exits 0/2/3/4; `wrap` exits 2 on startup failure or a failed blocked-event or `session_end` audit write, otherwise with the child's code. Use `exec.ExitError.ExitCode()`, never `syscall.WaitStatus`.
- Exported functions have doc comments; error messages are actionable.
- No new dependencies without discussion.
- Pull requests target `next`, never `main`. A maintainer promotes `next` to `main` in a release PR (`docs/runbooks/release.md`).
