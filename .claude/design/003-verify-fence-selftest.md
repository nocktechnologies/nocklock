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
     allowed roots, passes its path to the probe via env; probe attempts `os.ReadFile` on it →
     expect ENOENT/EACCES = PASS. Readable = FAIL. (Also attempt a fixed out-of-scope read like
     `/etc/hostname` on Linux / a non-allowed path on macOS as a secondary.)
   - **network:** probe attempts an HTTP GET to a fixed NON-allowlisted canary host
     (`http://verify.nocklock.invalid` + a real off-allowlist domain e.g. `example.com`) through
     the injected HTTP(S)_PROXY → expect proxy 403 / dial refused = PASS. 200 = FAIL.
   - **secret:** `verify` injects a canary env var `NOCKLOCK_VERIFY_SECRET=<random>` and adds its
     NAME to the effective block list before building the child env; probe checks the var is ABSENT
     in `os.Environ()` → absent = PASS, present = FAIL. (Proves the block-list filter holds.)
   - **syscall:** probe attempts ONE benign syscall present in the active denylist/seccomp policy
     (choose a safe, side-effect-free denied call; e.g. a denied `ptrace`/`unshare`/config-driven
     entry) → expect SIGSYS/EPERM = PASS. Succeeds = FAIL. Reuse `syscallfence.Policy` to pick a
     denied-but-safe call; if none safely attemptable, SKIP with reason.

3. **Cross-platform:** reuse `doctor`'s backend detection (filesystem/syscall/network doctor checks).
   Where a fence is configured but NOT enforceable on this platform/host, `verify` reports **SKIP**
   (not FAIL) with the same reason `doctor` gives. Linux → Landlock/seccomp; macOS → Seatbelt/SBPL.
   A fence that is OFF by config → SKIP ("not configured").

4. **Output + exit codes:** per-fence line `[PASS]/[FAIL]/[SKIP] <fence>: <detail>` + a summary,
   plus `--json` (mirror `doctor`'s `--json` shape: `{checks:[{fence,result,detail}], summary}`).
   **Exit 0 iff every configured+enforceable fence returned PASS.** Any FAIL (an escape succeeded)
   → exit non-zero, so `nocklock init` onboarding and CI can gate on "the fence actually holds."

5. **Safety contract (documented in `Long` help):** probes never exfiltrate, never write outside a
   temp dir, never touch real secrets — they read a self-created non-secret canary, dial an invalid/
   example host, check env absence, and attempt one side-effect-free denied syscall. `verify` is safe
   to run in CI and onboarding.

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
