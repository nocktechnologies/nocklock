# doctor and verify

Citations are `file:line` at `origin/main` 89c02fa.

## `nocklock doctor`: can this host enforce each fence?
Static check of the configuration plus host capabilities (`internal/cli/doctor.go`). Each boundary has a posture: `enforced`, `advisory`, `disabled`, `enabled` (configured but backend missing), or `unavailable`. `--json` includes these postures and the effective proxy-mode egress level (`doctor.go`). The verdicts and exits are `PROTECTED` (0), `GAPS FOUND` (2), `PARTIAL` (3), and `UNPROTECTED` (4), as mapped in `doctor.go`. A missing required backend is a gap; a deliberately disabled or advisory boundary does not count as protected. The honest verdicts landed in v0.8.0 (#168, `CHANGELOG.md`).

Limit: until #174 lands, `doctor` reports PROTECTED for a Linux `CONFINED` config although `CONFINED` does not stop Unix-socket connects (Known issues in 0.8.0). Read it as "enforced as designed", not "no escape".

Limit: `doctor` reports configuration and host capability, not proof that a particular session ran with every fence. Use `verify` for an active self-test and inspect that session's signed fence-state rows for evidence.

## `nocklock verify`: does the fence block?
Runs an adversarial self-test: child processes inside the fence attempt forbidden reads, writes, connections and syscalls, and the result must be BLOCKED (`internal/cli/verify.go`, hidden `__probe` re-exec at `internal/cli/probe.go`). Design: `.claude/design/003-verify-fence-selftest.md`. Exit 1 if any probe is not blocked (`verify.go`).

`verify --audit`, `--against-anchor`, `--against-remote-anchor`, `--export-pubkey` verify the audit log instead (`audit-log.md`).

## `nocklock egress-probe`
Linux-only structured feasibility probe for the netns egress fence (`internal/cli/egress_probe.go`).

## Tests
`internal/cli/doctor_test.go`, `verify_test.go`, `probe_test.go`, `egress_probe_test.go`.
