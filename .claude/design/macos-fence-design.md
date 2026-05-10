# macOS Filesystem Fence Design

**Status:** Proposed
**Date:** 2026-05-09
**Nock:** #484
**Audience:** Kevin, Warden, NockLock implementers

## Summary

NockLock should add macOS filesystem fence support, but it must ship as a
clearly bounded dynamic-interposition fence, not as a blanket OS sandbox.
The early customer and demo audience is likely Mac-heavy, and a working
macOS fence materially improves the product story. The security claim must
stay precise: the fence covers dynamically linked, non-SIP-protected child
processes that honor `DYLD_INSERT_LIBRARIES`.

The implementation should use Apple's dyld interpose mechanism on Darwin
instead of trying to treat macOS as `LD_PRELOAD` with different environment
variable names. Linux and Darwin should share the config parser, path policy,
and event reporting code, while platform-specific wrapper entrypoints live in
separate C files.

## Product Decision

Proceed with macOS support.

Required product wording:

- macOS support is valuable for solo developers, operator machines, and demos.
- macOS support is not equivalent to Linux namespace isolation.
- NockLock must fail closed or explicitly refuse commands when the primary
  command or critical child execution path is SIP-protected and therefore
  cannot receive dyld environment variables.
- Public copy should say "filesystem fence for supported dynamic processes on
  Linux and macOS", not "complete macOS filesystem sandbox".

## Current State

`internal/fence/fs/fence.go` currently reports support only on Linux and sets
`LD_PRELOAD` in `Fence.EnvVars()`. `Makefile` skips `make build-fence-fs` on
Darwin. The C interposer is named `libfence_fs.c` and is Linux-oriented:

- It uses `RTLD_NEXT` plus direct wrapper symbols.
- It uses `/proc/self/fd/<n>` for `openat` and fd path resolution.
- It builds `libfence_fs.so`, not a Darwin `.dylib`.
- It already contains the post-Nock #129 stat-family Linux hardening.

ADR-002 said the filesystem fence would use `LD_PRELOAD` /
`DYLD_INSERT_LIBRARIES`, but the implementation has intentionally remained
Linux-only until this design.

## Local macOS Findings

Verified on this machine during Nock #484:

- Host: macOS 26.3.1, Darwin 25.3.0, arm64.
- An arm64 probe linked against bare symbols: `_stat`, `_lstat`, `_fstat`,
  `_fstatat`.
- An x86_64 probe cross-compiled with the same SDK linked against
  `$INODE64` symbols: `_stat$INODE64`, `_lstat$INODE64`, `_fstat$INODE64`,
  `_fstatat$INODE64`.
- The local `stat(2)` man page says `$INODE64` suffixes are automatically
  appended by the compiler toolchain for some compatibility modes, while
  64-bit-only targets do not use the suffix.

Implication: the Darwin implementation must not assume one universal symbol
name. It needs architecture and target-mode aware interpose entries.

## Interposition Mechanism

Use `DYLD_INSERT_LIBRARIES` to load `libfence_fs.dylib` before normal program
dependencies.

Inside the dylib, use dyld interpose sections for Darwin wrapper entrypoints.
The current dyld header defines `DYLD_INTERPOSE(replacement, replacee)` by
emitting a static replacement/replacee pair in `__DATA,__interpose,interposing`.
Apple's Dynamic Library Programming Topics also documents interposition and
`dlsym(RTLD_NEXT, ...)` for calling the real function.

Recommended pattern shape:

```c
#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose,interposing"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    }
#endif
```

The implementation should vendor or adapt Apple's current macro rather than
copying this minimal sketch verbatim, because modern dyld headers include
pointer-authentication annotations on supported targets.

For `$INODE64` replacees, prefer C aliases with asm labels so the macro still
gets a normal C identifier:

```c
extern int darwin_stat_inode64(const char *, struct stat *)
    __asm("_stat$INODE64");

static int nocklock_stat(const char *path, struct stat *buf);

#if defined(__x86_64__)
DYLD_INTERPOSE(nocklock_stat, darwin_stat_inode64)
#else
DYLD_INTERPOSE(nocklock_stat, stat)
#endif
```

Direct `$` identifiers compiled in a local Clang syntax probe, but asm labels
make the design less dependent on that extension and avoid awkward token
pasting in macro names.

## File Layout

Split platform entrypoints instead of growing one `#ifdef`-heavy file:

```text
internal/fence/fs/interposer/
  Makefile
  libfence_fs_common.h
  libfence_fs_common.c
  libfence_fs_linux.c
  libfence_fs_darwin.c
```

`libfence_fs_common.*` owns:

- `NOCKLOCK_FS_ALLOWED` parsing.
- Path prefix checks.
- Policy checks.
- JSON escaping.
- Blocked-event reporting over the Unix domain socket.
- Shared `open`/`fopen` write-mode helpers when portable.

`libfence_fs_linux.c` owns:

- Existing Linux wrappers and `RTLD_NEXT` symbol lookup.
- `/proc/self/fd/<n>` path resolution.
- Linux-only `stat64`, `lstat64`, `fstat64`, `statx`, `renameat2`, and
  `O_TMPFILE` handling.

`libfence_fs_darwin.c` owns:

- dyld interpose mappings.
- Darwin symbol matrix for bare and `$INODE64` stat-family symbols.
- fd path resolution through `fcntl(fd, F_GETPATH, buf)`.
- Darwin-specific build and compatibility conditionals.

This split keeps Linux regressions reviewable and prevents Darwin symbol
compatibility logic from leaking into the Linux hot path.

## Darwin Coverage

Darwin should target parity for the filesystem operations NockLock already
claims at the interposer boundary:

- Read/open probes: `open`, `openat`, `fopen`, `access`, `readlink`,
  `realpath`, `stat`, `lstat`, `fstat`, `fstatat`.
- Mutations: `unlink`, `rename`, `mkdir`, `rmdir`.
- Follow-up candidates, not required for first implementation: `chmod`,
  `chown`, `truncate`, `link`, `symlink`, `*at` variants beyond `openat` and
  `fstatat`, and Apple-specific metadata APIs such as `getattrlist`.

Blocked stat-family calls must continue to return `-1` with `errno = ENOENT`
so restricted files appear absent. Blocked mutating/open calls should keep the
existing `EACCES` behavior unless the operation is stat-family.

Do not implement `stat64`, `lstat64`, or `fstat64` on arm64 unless the SDK
exposes those declarations. The local man page marks the transitional 64
suffix routines as deprecated, and Apple Silicon headers may omit them.

## Path Resolution

Linux keeps `/proc/self/fd/<n>`. Darwin must not use that path.

Darwin fd resolution should use `fcntl(fd, F_GETPATH, buf)`, where `buf` is at
least `MAXPATHLEN`. Apple's `fcntl(2)` man page documents `F_GETPATH` as the
command to get a descriptor path.

Rules:

- `openat(dirfd, absolute_path, ...)` uses normal path resolution.
- `openat(AT_FDCWD, relative_path, ...)` resolves relative to cwd.
- `openat(dirfd, relative_path, ...)` resolves `dirfd` through `F_GETPATH`,
  joins the relative path, then applies the same normalization and policy.
- `fstat(fd, ...)` checks the descriptor path when `F_GETPATH` succeeds.
- Non-path descriptors such as sockets and pipes should delegate to the real
  function, matching the Linux non-path fd bypass added after Nock #129.
- Filesystem descriptors that cannot be resolved to a path should fail closed
  unless the implementation can prove they are non-path descriptors.

## SIP and Hardened Runtime Gate

This is the main product risk.

Apple documents that dyld environment variables are ignored for binaries
protected by System Integrity Protection. The dyld man page says
`DYLD_INSERT_LIBRARIES` loads additional dynamic libraries before the normal
ones, but also notes SIP-protected binaries ignore dyld environment variables.
Apple's SIP runtime protections say protected child process launches purge
dyld environment variables.

Security implication:

- `nocklock wrap -- /opt/homebrew/bin/node ...` is a realistic supported path.
- `nocklock wrap -- /bin/ls ...` is not safely covered by dyld injection.
- A supported agent can potentially spawn `/bin/ls`, `/usr/bin/stat`, or other
  protected Apple tools that drop `DYLD_INSERT_LIBRARIES`.

Implementation gate before public macOS support:

1. Detect and refuse a SIP-protected primary executable when filesystem fence
   is enabled.
2. Add an exec-family control or documented hard limitation for protected
   child process escape. The safer first implementation is to interpose
   `execve`, `posix_spawn`, and `posix_spawnp` on Darwin and fail closed when
   the target executable is in known SIP-protected system locations.
3. Add integration tests proving NockLock does not silently report the macOS
   filesystem fence as active for a command that ignores dyld variables.

Known protected-path heuristic for the first gate:

- `/bin/*`
- `/sbin/*`
- `/usr/bin/*`
- `/usr/sbin/*`
- `/System/*`
- `/System/Applications/*`

Do not include `/usr/local/*`, `/opt/homebrew/*`, or project-local toolchains
in that deny heuristic.

## Go Integration

`fs.IsSupported()` should return true for Linux and Darwin only after the
Darwin implementation and SIP gate land.

`Fence.EnvVars()` should become platform-aware:

- Linux: `LD_PRELOAD=<libfence_fs.so>`.
- Darwin: `DYLD_INSERT_LIBRARIES=<libfence_fs.dylib>`.
- Both: `NOCKLOCK_FS_ALLOWED=<serialized policy>`.

The CLI merge logic currently special-cases `LD_PRELOAD`. It should merge both
platform variables by prepending NockLock's library to any existing value and
using the platform's list separator. Darwin dyld documents
`DYLD_INSERT_LIBRARIES` as colon-separated.

`findLibFenceFS()` should look for the platform extension:

- Linux: `libfence_fs.so`.
- Darwin: `libfence_fs.dylib`.

## Build Design

Top-level `make build-fence-fs` should build on Linux and Darwin.

Interposer Makefile targets:

- Linux: `libfence_fs.so`, `-shared -fPIC`, link with `-ldl -lpthread`.
- Darwin: `libfence_fs.dylib`, `-dynamiclib -fPIC`, no Linux-only `-ldl`,
  keep pthread flags only if required by the SDK.

The Darwin target should support native arm64 and x86_64 CI. Universal dylib
support can be a follow-up unless distribution requires one artifact for both
architectures.

## Verification Plan

Baseline:

- `go test ./...`
- `go vet ./...`
- `make build-fence-fs` on Linux.
- `make build-fence-fs` on macOS arm64.

Darwin symbol verification:

- Build a C probe that calls `stat`, `lstat`, `fstat`, and `fstatat`.
- `nm -u` must show the expected bare symbols on arm64.
- Cross-compile `-arch x86_64`; `nm -u` must show `$INODE64` symbols.
- `otool -l libfence_fs.dylib` must show the interpose section.

Darwin runtime verification:

- Run the C probe with `DYLD_INSERT_LIBRARIES=<libfence_fs.dylib>` and a
  `NOCKLOCK_FS_ALLOWED` policy that denies a temp path.
- Assert denied `stat`, `lstat`, `fstat`, and `fstatat` return `ENOENT`.
- Assert allowed paths still return success.
- Assert socket and pipe `fstat` calls are not blocked as filesystem path
  attempts.
- Assert protected primary commands are refused or otherwise fail closed.

Integration tests:

- Extend `integration/integration_test.go` to build the Darwin dylib when
  `runtime.GOOS == "darwin"`.
- Extend the stat probe to compile and run on Darwin.
- Add a macOS-only test for the protected executable gate.
- Keep Linux integration tests unchanged except for any file layout move.

## Alternatives Considered

### Keep Linux-only

Safest security story, but weak product fit for the likely early audience.
Rejected unless Kevin decides macOS support would create unacceptable claim
risk.

### Single `libfence_fs.c` with `#ifdef __APPLE__`

Smallest initial diff. Rejected for implementation clarity: Darwin needs a
different loader contract, fd resolution mechanism, stat symbol matrix, and
SIP gate. Mixing those into the Linux file makes later review harder.

### macOS sandbox profiles

Could provide stronger OS-level restrictions for process trees, but
`sandbox-exec` is poorly positioned for a public developer CLI and does not
match the existing no-root dynamic interposer architecture. Keep as a future
hardening path, not the first macOS fence.

### Endpoint Security framework

Stronger visibility and enforcement, but it requires entitlements and a much
heavier product/install story. Out of scope for the solo developer tier.

## Review Gates

Before implementation:

- Kevin accepts the bounded macOS support claim.
- Warden reviews the SIP/protected-binary escape analysis.

Before merge of the implementation PR:

- Darwin and Linux tests pass.
- A reviewer verifies that Linux behavior did not regress during file split.
- A reviewer verifies that macOS cannot silently claim filesystem fence
  coverage for SIP-protected commands.

## References

- Apple Dynamic Library Programming Topics, "Interposing Functions in
  Dependent Libraries":
  https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/UsingDynamicLibraries.html
- Apple dyld man page source:
  https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/doc/man/man1/dyld.1
- Apple dyld interposing header:
  https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/dyld-interposing.h
- Apple `stat(2)` man page:
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fstat64.2.html
- Apple `fcntl(2)` man page:
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html
- Apple System Integrity Protection runtime protections:
  https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/RuntimeProtections/RuntimeProtections.html
