# 014: Syscall fence is a default-allow filter with a curated denylist

**Status:** Accepted. Source: `internal/fence/syscallfence/denylist.go:12-17`.

**Context.** A from-scratch syscall allowlist would have to enumerate the thousands of benign syscalls modern runtimes make, and would break on the next libc.

**Decision.** Deny a curated set of dangerous subsystems with `EPERM` (module loading, mount family, handle-based opens, keyring, `bpf`, `perf_event_open`, `userfaultfd`, namespace creation unless allowed, socket families outside the allowlist) and allow the rest.

**Consequences.** Maintainable and forward-compatible, but any syscall not listed is reachable. Known gap: `io_uring` (N11655, `docs/ROADMAP.md`).
