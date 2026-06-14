# Linux Landlock Filesystem Fence — Design

**Date:** 2026-06-11
**Status:** Approved (Mira, product lead) — Phase 1 scoped for build
**Author:** Mira Ashworth
**Tracks:** Linux kernel-enforced fence backend (the Landlock half of the
filesystem fence). Mirrors the macOS Seatbelt decision: a userspace interposer
fails open against a determined process; the kernel-enforced backend is the
fail-closed floor.

## Purpose

Today the Linux filesystem fence is **LD_PRELOAD interposition only**
(`internal/fence/fs/interposer/libfence_fs.c`). That is a userspace mechanism
with a structural ceiling: it is bypassed by a statically-linked binary, a
process that unsets `LD_PRELOAD` before its own `exec`, or a direct syscall that
skips libc. For an *observability* layer that is fine — but NockLock's whole
posture is fail-closed enforcement. This spec adds **Landlock** (Linux kernel
LSM, fail-closed, deny-by-default) as the enforcement floor, with the existing
interposer retained for its rich event stream.

## The design questions, answered

**Q1. Does Landlock replace the LD_PRELOAD interposer, or compose with it?**
**Compose — defense in depth, distinct jobs.** Landlock is the *enforcement*
floor: the kernel denies disallowed access even to a static binary, and the
denial is unforgeable. But Landlock denies *silently* (EACCES at the syscall);
it emits no audit record. The interposer is kept as the *observability* layer —
it is what produces the `FenceEvent` JSON stream over the Unix socket that feeds
the events.db audit trail. So: **Landlock enforces, the interposer reports.** A
process that escapes the interposer (static binary) is still kernel-blocked but
produces no fine-grained event — that is the correct trade (enforcement >
observability when they conflict), and the gap is logged at fence-start
("interposer-blind enforcement active").

**Q2. Which kernels, and how do we detect capability?**
Landlock shipped in **5.13 (ABI v1)**; v2=5.19, v3=6.2 (truncate), v4=6.7 (TCP),
v5=6.10 (ioctl-dev). Detect at runtime via
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` which returns
the supported ABI integer (or ENOSYS/EOPNOTSUPP). **We request the file-access
rights subset and clamp to the kernel's ABI** (omit rights the running kernel
doesn't know — passing an unknown right is rejected, so we mask
`handled_access_fs` down to the detected ABI's known bits). v1 (5.13) is the
floor we target; truncate-protection (v3) is added when present.

**Q3. Fail-open or fail-closed when Landlock is unavailable?**
**Fail-closed by default, policy-overridable.** Three modes on a new
`linux_enforcement` config key:
- `required` (DEFAULT on Linux): Landlock unavailable (pre-5.13, or disabled via
  `lsm=` boot param) → **refuse to launch** with a clear error. This is the
  Seatbelt-parity posture — no silent downgrade to a bypassable fence.
- `preferred`: Landlock unavailable → fall back to interposer-only with a **loud
  stderr + events.db warning** ("kernel fence unavailable, userspace-only").
- `off`: interposer-only, no Landlock attempt (escape hatch / old kernels).
The default is `required` precisely because "the fence is on" must not silently
mean "the bypassable half is on."

**Q4. NockLock's path-allowlist model vs Landlock's fd-rule model.**
Clean fit — both are deny-by-default allowlists. Landlock rules are added per
file descriptor: open each ALLOW path `O_PATH|O_CLOEXEC`, call
`landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, {allowed_access, fd})`.
Everything not covered by an allow rule is denied by the ruleset's
`handled_access_fs` mask — so NockLock's **deny list needs no rules** (it is the
implicit complement of the allow list), and the existing `FenceConfig`
allow-path resolution (`config.go`, already symlink-resolved post-#32) is the
exact input. Read-only allow paths get the read-family rights; read-write get
read+write+create+remove families.

**Q5. Where is the ruleset applied? (the Go/fork-exec problem)**
Landlock self-restriction must run **in the child, after fork, before execve**,
under `PR_SET_NO_NEW_PRIVS` — and Go's `os/exec` has no portable pure-Go
pre-exec hook. **Decision: a re-exec shim, no cgo.** NockLock re-execs itself as
a hidden subcommand `nocklock __landlock-exec` that (1) reads the serialized
ruleset from an env var / pipe fd, (2) sets `no_new_privs`, (3) builds the
ruleset and `landlock_restrict_self`, (4) `execve`s the real target. Syscalls go
through `golang.org/x/sys/unix` (Landlock wrappers exist) — **zero cgo**, keeping
the build matching the project's dependency discipline. The shim is a few dozen
lines and is directly unit-testable by invoking it against a temp dir.

**Q6. events.db must stay writable (cross-fence interaction).**
The audit trail is fail-closed (#30) — if Landlock denies its write, the session
dies. So the events.db path (and its parent dir, for WAL/journal files) is added
to the **always-allow set** with read-write rights, the same carve-out the
interposer already honors. This is asserted by an e2e test (fence on, events.db
write succeeds, a sibling path write is denied).

**Q7. Network?** Out of scope. Landlock v4 (6.7) can restrict TCP bind/connect,
but the network fence is a separate, existing component. Noting only that a
future unification is possible; this spec is filesystem-only.

## Architecture

### New: `internal/fence/fs/landlock/` (Linux build-tagged)
- `landlock_linux.go` (`//go:build linux`): ABI detection (`DetectABI() int`),
  ruleset construction from `*fs.FenceConfig`, the `Apply()` self-restrict call.
  Pure `x/sys/unix`.
- `landlock_stub.go` (`//go:build !linux`): `DetectABI() int { return 0 }`,
  `Supported() bool { return false }` — keeps cross-compile + macOS builds green.
- `landlock_test.go`: ABI-clamp unit tests; ruleset-from-config mapping tests.

### New hidden subcommand: `nocklock __landlock-exec`
- Hidden from `--help`. Reads ruleset spec from `NOCKLOCK_LANDLOCK_RULES`
  (serialized allow-paths + rights + abi), applies, `execve`s `os.Args` tail.
- Fail-closed: any error building/applying the ruleset → exit non-zero **before**
  exec (never exec the target with the fence half-applied).

### Integration: `fence.go` `WrapEnv`/spawn path
- When `linux_enforcement != off` and `landlock.Supported()`: the spawn command
  becomes `nocklock __landlock-exec -- <original argv>`, with the interposer
  `LD_PRELOAD` + `NOCKLOCK_FS_ALLOWED` still set (both layers active).
- `linux_enforcement=required` + `!Supported()` → `CheckSupported()`-style error,
  refuse to spawn.

## Phase 1 build scope (this dispatch)
1. `internal/fence/fs/landlock/` package: ABI detect + config→ruleset + Apply
   (Linux), stub (non-Linux), unit tests.
2. `__landlock-exec` hidden subcommand, fail-closed.
3. `fence.go` wiring behind `linux_enforcement` config (default `required`) with
   the `preferred`/`off` modes.
4. events.db always-allow carve-out.
5. e2e on a 6.x kernel (nock-fleet-02, glibc 2.43, kernel supports Landlock):
   (a) disallowed write is kernel-denied even when `LD_PRELOAD` is cleared by the
   child — the bypass the interposer alone misses; (b) events.db write succeeds;
   (c) `required` on a simulated no-Landlock path refuses to launch.
6. README/docs note: Linux fence is now kernel-enforced (Landlock) + userspace
   (interposer); Seatbelt is the macOS parallel.

**Out of scope (later phases):** macOS Endpoint Security; Landlock network (v4);
per-rule ioctl (v5). 

## Test posture
TDD: the bypass e2e (static/PRELOAD-cleared child still blocked) is the headline
red→green — it is the entire reason the kernel backend exists. Unit tests must
not require a Landlock kernel (ABI detection is mocked/guarded); the enforcement
e2e is build-tagged + skips with a clear message off a Landlock kernel.

## Security review
Kernel-enforcement code — **Warden review required post-build, pre-merge.**
Specific review asks: the ABI-clamp masking (an unmasked unknown right rejects
the whole ruleset → accidental fail-*open* if mishandled), the fail-closed
ordering in `__landlock-exec` (never exec on partial apply), and the events.db
carve-out not being broader than the single path + journal siblings.
