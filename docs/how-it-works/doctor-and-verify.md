# doctor and verify

Citations are `file:line` at `origin/main` 8a65777.

## `nocklock doctor`: can this host enforce each fence?
Static check of the configuration plus host capabilities (`internal/cli/doctor.go:85-102`). Checks are grouped, each `ok`, `warning`, `critical` or `info`, with a fix hint (`doctor.go:25-48`). The verdict has two values today: `PROTECTED` and `GAPS FOUND` (`doctor.go:36-39`); `--json` emits the structured report, and `GAPS FOUND` exits 1. Doctor reads the same rules `wrap` enforces, so a config that passes `doctor` is the config `wrap` accepts (`CHANGELOG.md:76-78`).

Limit: `doctor` describes what *can* be enforced here, not that a given session was. Shipping honest doctor verdicts is a 1.0 bar item, tracked in PR #168 and not on `main` at this commit (`docs/ROADMAP.md`).

## `nocklock verify`: does the fence block?
Runs an adversarial self-test: child processes inside the fence attempt forbidden reads, writes, connections and syscalls, and the result must be BLOCKED (`internal/cli/verify.go:392`, hidden `__probe` re-exec at `internal/cli/probe.go:35`). Design: `.claude/design/003-verify-fence-selftest.md`. Exit 1 if any probe is not blocked (`verify.go:106-107`).

`verify --audit`, `--against-anchor`, `--against-remote-anchor`, `--export-pubkey` verify the audit log instead (`audit-log.md`).

## `nocklock egress-probe`
Linux-only structured feasibility probe for the netns egress fence (`internal/cli/egress_probe.go:172`).

## Tests
`internal/cli/doctor_test.go`, `verify_test.go`, `probe_test.go`, `egress_probe_test.go`.
