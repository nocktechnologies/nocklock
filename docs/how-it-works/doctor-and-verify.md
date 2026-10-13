# doctor and verify

Citations name source files at `v0.9.0` (`f2b0d04`) (no line numbers, so they do not go stale).

## `nocklock doctor`: can this host enforce each fence?
Static check of the configuration plus host capabilities (`internal/cli/doctor.go`). Each boundary has a posture: `enforced`, `advisory`, `disabled`, `enabled` (configured but backend missing), or `unavailable`. `--json` includes these postures and the effective proxy-mode egress level (`doctor.go`). The verdicts and exits are `PROTECTED` (0), `GAPS FOUND` (2), `PARTIAL` (3), and `UNPROTECTED` (4), as mapped in `doctor.go`. A missing required backend is a gap; a deliberately disabled or advisory boundary does not count as protected. The honest verdicts landed in v0.8.0 (#168, `CHANGELOG.md`).

Since v0.9.0, `doctor` reports `PARTIAL` (exit 3) for Linux `CONFINED` below Landlock ABI 9 because the Unix-socket boundary is unavailable. Default `wrap` warns and records that limitation; `network.require_unix_socket_isolation = true` refuses launch instead. The ABI 9 enforcement branch has not yet run on a real kernel. See [the network boundary](network-fence.md).

Limit: `doctor` reports configuration and host capability, not proof that a particular session ran with every fence. Use `verify` for an active self-test and inspect that session's signed fence-state rows for evidence.

## `nocklock verify`: does the fence block?
Runs an adversarial self-test through fenced child processes (`internal/cli/verify.go`, hidden `__probe` re-exec at `internal/cli/probe.go`). The report lists a result and reason for each filesystem, network, secret and syscall probe. `PASS` proves the tested operation was blocked; `SKIP` is not proof. Any failed probe, or a run with no passing probe, exits 1. A passing run with skipped probes covers only the tests that passed; read the per-probe results. Design: `.claude/design/003-verify-fence-selftest.md`.

`verify --audit`, `--against-anchor` and `--against-remote-anchor` check the audit log instead. `--export-pubkey` prints the managed public key without running a fence probe. See [audit verification](audit-log.md).

## `nocklock egress-probe`
Linux-only structured feasibility probe for the netns egress fence (`internal/cli/egress_probe.go`).

## Tests
`internal/cli/doctor_test.go`, `verify_test.go`, `probe_test.go`, `egress_probe_test.go`.
