# Design 003: `nocklock verify` — adversarial fence self-test (proof-of-block)

**Status:** Accepted (scoped, ready to build)
**Date:** 2026-07-23
**Author:** Mira (owner)

## Problem
`doctor` answers *"can the fences be enforced on this host?"* (capability: Landlock ABI present,
seccomp-BPF available, macOS Seatbelt, config valid). It does NOT answer the question that
actually matters for a security tool: *"do the configured fences actually BLOCK an escape?"*
A fence that only holds when the agent cooperates is theater. `verify` closes that gap: it runs a
benign probe **under the live fences** that attempts to escape each one and asserts it is blocked.

## Decision: a new `nocklock verify` command (distinct from `doctor`)
- `doctor` = passive, read-only capability check (safe to run anywhere).
- `verify` = ACTIVELY constructs the same fenced child environment as `wrap` (reuse the fence
  wiring in `internal/cli/wrap.go`: secrets.Filter, fsfence, network proxy, syscallfence) and,
  instead of the user's agent command, runs a built-in probe that tries to escape each fence.

## Design questions — ANSWERED

1. **How does the probe run without a second binary?**
   A hidden self-exec subcommand `nocklock __probe <fence>` (unlisted, `Hidden: true`). `verify`
   re-execs the current binary as the fenced child with `__probe`, so it stays a single static
   binary. The probe writes a structured result to stdout as JSON `{fence, attempted, blocked, detail}`
   and sets exit code (0=blocked-as-expected, 1=ESCAPED). `verify` reads that back per fence.

2. **Per-fence probe (all benign — no exfiltration, no damage):**
   - **filesystem:** `verify` creates a canary file in a temp dir GUARANTEED outside the config's
     allowed roots, writes a random token, and first runs the probe unfenced as a positive control
     proving the canary exists and is readable. If no outside temp location can be proven (for
     example because the configured root is `/`), verification reports FAIL/SKIP with detail rather
     than PASS. The fenced probe attempts `os.ReadFile` on the known-existing canary: EACCES/EPERM,
     or backend ENOENT hiding for that known-existing path, is PASS; readable with the expected
     token is FAIL; missing/unavailable without the positive-control marker is inconclusive.
   - **network:** probe attempts an HTTP GET to a fixed NON-allowlisted canary host
     selected from candidates that are verified against the active allowlist before launch. The
     network self-test isolates the network proxy from syscall socket denial so a PASS proves the
     proxy allowlist path specifically: only proxy-generated HTTP 403 with the NockLock marker is
     PASS. DNS failures, connection refusal, proxy outage, or generic transport errors are
     inconclusive/SKIP rather than proof of a block. Any non-fence response from the off-allowlist
     target is FAIL.
   - **secret:** `verify` injects a canary env var `NOCKLOCK_VERIFY_SECRET=<random>` and adds its
     NAME to the effective block list before building the child env. It also injects a separate
     non-secret control env var and first runs the probe unfenced to prove the intended child env
     carries both values. Under the secret fence, the control var must still be present and the
     secret canary must be absent; missing control is inconclusive, secret present is FAIL, and
     control-present/secret-absent is PASS.
   - **syscall:** probe attempts ONE benign syscall present in the active denylist/seccomp policy
     (`unshare(CLONE_NEWUSER)` when namespace creation is denied). `verify` first runs the same
     syscall probe unfenced; if the host already denies it, the syscall check is inconclusive rather
     than a PASS. After that positive control proves the syscall is attemptable, SIGSYS/EPERM under
     the fence is PASS and success is FAIL. If the active policy has no safely attemptable denied
     call, SKIP with reason.

3. **Cross-platform:** reuse `doctor`'s backend detection (filesystem/syscall/network doctor checks).
   Where a fence is configured but NOT enforceable on this platform/host, `verify` reports **SKIP**
   (not FAIL) with the same reason `doctor` gives. Linux → Landlock/seccomp; macOS → Seatbelt/SBPL.
   A fence that is OFF by config → SKIP ("not configured").

4. **Output + exit codes:** per-fence line `[PASS]/[FAIL]/[SKIP] <fence>: <detail>` + a summary,
   plus `--json` (mirror `doctor`'s `--json` shape: `{checks:[{fence,result,detail}], summary}`).
   **Exit 0 iff at least one configured+enforceable fence returned PASS and no checks returned
   FAIL.** Any FAIL (an escape succeeded or a required positive control failed) exits non-zero.
   An all-SKIP/no-proof run also exits non-zero, so `nocklock init` onboarding and CI cannot
   mistake "nothing was verified" for "the fence actually holds."

5. **Safety contract (documented in `Long` help):** probes never exfiltrate, never write outside a
   temp dir, never touch real secrets — they read a self-created non-secret canary, dial an invalid/
   example host, check env absence, and attempt one side-effect-free denied syscall. `verify` is safe
   to run in CI and onboarding. Each child probe has an overall timeout, and network requests have
   their own request timeout.

## Files
- `internal/cli/verify.go` (+ `verify_test.go`) — the command + result aggregation.
- `internal/cli/probe.go` — the hidden `__probe` self-exec + per-fence attempt functions
  (build-tagged where a fence is platform-specific, mirroring the existing fence packages).
- Wire into `internal/cli/root.go`; reuse `wrap.go`'s fence construction (refactor the shared
  child-env/fence build into a helper if needed — keep `wrap` behavior identical).
- Tests: table-driven per fence — a config that WOULD block (expect PASS) and a deliberately-open
  config (expect the probe to detect an escape = FAIL), plus SKIP paths. Mirror the build-tagged
  test style already in `internal/fence/*`.
- `CHANGELOG.md` [Unreleased]: `### Added — nocklock verify: adversarial fence self-test`.

## Acceptance
`nocklock verify` on a correctly-fenced config prints all PASS and exits 0; on an intentionally-open
config it prints the escaped fence as FAIL and exits non-zero; unsupported/off fences are SKIP.
`go test ./...` green on Linux and macOS build tags. No change to `wrap`/`doctor` behavior.
