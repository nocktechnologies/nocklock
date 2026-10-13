# doctor and verify

Citations are `file:line` at `origin/main` 89c02fa.

## `nocklock doctor`: can this host enforce each fence?
Static check of the configuration plus host capabilities (`internal/cli/doctor.go`). Each boundary has a posture: `enforced`, `advisory`, `disabled`, `enabled` (configured but backend missing), or `unavailable`. `--json` includes these postures and the effective proxy-mode egress level (`doctor.go:55-96`). The verdicts and exits are `PROTECTED` (0), `GAPS FOUND` (2), `PARTIAL` (3), and `UNPROTECTED` (4), as mapped in `doctor.go:36-59`. A missing required backend is a gap; a deliberately disabled or advisory boundary does not count as protected. The honest verdicts landed in v0.8.0 (#168, `CHANGELOG.md`).

Limit: `doctor` reports configuration and host capability, not proof that a particular session ran with every fence. Use `verify` for an active self-test and inspect that session's signed fence-state rows for evidence.

## `nocklock verify`: does the fence block?
Runs an adversarial self-test: child processes inside the fence attempt forbidden reads, writes, connections and syscalls, and the result must be BLOCKED (`internal/cli/verify.go:392`, hidden `__probe` re-exec at `internal/cli/probe.go:35`). Design: `.claude/design/003-verify-fence-selftest.md`. Exit 1 if any probe is not blocked (`verify.go:106-107`).

`verify --audit`, `--against-anchor`, `--against-remote-anchor`, `--export-pubkey` verify the audit log instead (`audit-log.md`).

## `nocklock egress-probe`
Linux-only structured feasibility probe for the netns egress fence (`internal/cli/egress_probe.go:172`).

## Tests
`internal/cli/doctor_test.go`, `verify_test.go`, `probe_test.go`, `egress_probe_test.go`.
