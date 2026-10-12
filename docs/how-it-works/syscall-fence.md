# Syscall fence

Citations are `file:line` at `origin/main` 8a65777.

## Linux: seccomp filter
- Config: `[syscall] enforcement = "required" | "preferred" | "off"` (default `required`), `allow_namespaces` (default false), `socket_families` (default `unix`, `inet`, `inet6`).
- A default-allow seccomp filter denies a curated baseline with `EPERM` (`internal/fence/syscallfence/denylist.go:25`): kernel-module loading, the mount family, `open_by_handle_at` / `name_to_handle_at` (a path-fencing bypass), the kernel keyring, `bpf`, `perf_event_open`, `userfaultfd`, and more. `unshare`, `setns` and `clone` with `CLONE_NEW*` are denied unless `allow_namespaces` is true. `socket()` for families outside `socket_families` is denied (`internal/fence/syscallfence/policy.go:30-60`). The filter is built in `seccomp_linux.go` and installed by the `__landlock-exec` shim after Landlock (`internal/cli/landlock_exec.go:21`).
- Default-allow is a deliberate choice: an allowlist would break on the next libc or runtime (comment at `denylist.go:12-17`). It also means any syscall not on the denylist is allowed. `io_uring` is not on it today (no reference in `internal/`); closing that is roadmap work (N11655, `docs/ROADMAP.md`).
- With the filesystem interposer enabled in proxy mode, the child's IP sockets are denied so only the proxy's Unix socket is reachable: egress level `CONFINED` (`network-fence.md`).

## macOS
There is no seccomp. With `syscall.enforcement` `required` or `preferred`, `wrap` adds hardened Seatbelt rules to the profile: deny `mach-priv-host-port`, `iokit-open`, `system-socket`, and limit `/dev` writes to common pseudo-devices (`CHANGELOG.md:45-60`, v0.6.1). `required` with an empty `filesystem.root` has no profile to carry the rules, so `wrap` refuses to start (`internal/cli/wrap.go:343`).

## Limits
- Denial returns `EPERM`; it does not hide that a fence exists.
- Enforcement `off` disables the filter; `doctor` reports a configured-but-unavailable backend as a gap.
- The denylist is Linux ABI specific; names with no number on the target arch are skipped.

## Tests
`internal/fence/syscallfence/program_test.go`, `denylist_test.go`, `seccomp_enforce_linux_test.go`; `internal/cli/syscall_wire_test.go`.
