# Filesystem fence

Citations name source files at `origin/main` 89c02fa (no line numbers, so they do not go stale). Wording of limits follows `README.md` ("Filesystem platform boundary").

## Linux: Landlock root allowlist
- `wrap` re-execs the child through the hidden `__landlock-exec` shim (`internal/cli/wrap.go`), which builds a Landlock ruleset (`internal/fence/fs/landlock/landlock_linux.go`) and `execve`s the child in place. Every descendant inherits it.
- `filesystem.allow` grants read-only, `filesystem.allow_rw` read-write, `filesystem.root` is the working root, `filesystem.deny` lists excluded paths. Missing optional paths grant nothing and do not block a wrap. Defaults: `README.md` "Configuration".
- An `LD_PRELOAD` interposer (`internal/fence/fs/interposer/libfence_fs.c`) reports denied opens to the Go side, which logs `file_blocked` (`internal/fence/fs/fence.go`). It also carries the proxy bridge (`network-fence.md`).
- New interposer report details separate child claims from the collector's connection-peer snapshot (`SO_PEERCRED` captured once after accept). The signed detail identifies the connector, not each action's writer or proof of the action; the executable path is a later, best-effort procfs observation. Credential/executable lookup failures are explicit and do not discard the report. See [audit provenance and limits](audit-log.md#linux-interposer-connection-provenance).
- `filesystem.linux_enforcement` is `required`, `preferred` or `off` (`internal/config/validate.go`).

**Limits**: Landlock is inode-bound. Where Landlock is engaged, the kernel denies static binaries and children that clear `LD_PRELOAD`. Landlock is off with `linux_enforcement = "off"` and can be degraded or missing with `"preferred"` on a kernel without it, and then those opens are not denied. They bypass the interposer, so they produce no `file_blocked` event and cannot trip a look-back rule. A path under a granted directory cannot be excluded, which is why the audit log lives outside the project (`audit-log.md`). Grandchildren do not get their own `/proc/self` reads: `.claude/decisions/005-grandchild-procfs-self-limitation.md`.

### Linux interposer installation trust

Before loading `libfence_fs.so`, `wrap` checks the candidate file and every ancestor: each must be owned by root or the invoking real UID and must have no group/world write bits. A sticky writable directory such as `/tmp` is not an exception. The library must be a regular file. Symlinks remain supported for safe source and Homebrew layouts; their owners, original ancestors, targets and target ancestors are checked. Symlink permission bits themselves do not control replacement on Unix.

An unsafe existing candidate causes refusal instead of silently trying another location. Install the library beside the executable or in the documented system library directory with those permissions; do not use a shared writable prefix. A group-writable `/usr/local`, `/usr/local/lib` or `/usr/local/lib/nocklock` (common with some package managers, for example mode 0775 with group `staff`) is refused for this reason; the refusal names the path. Remove the bit with `chmod g-w <path>` (as root or the owner), or install beside the executable under a private directory. `doctor` uses the same resolver and reports a missing or unsafe backend as `GAPS FOUND` (exit 2) when the filesystem fence is configured.

The resolver returns the canonical path and rechecks inode, device, owner, mode and symlink target observations before returning. This detects observed path changes during validation. It does not pin an open library descriptor for the child's lifetime or prevent root/the invoking user from changing a trusted file afterward. The invoking UID is a trust principal; this check does not separate hostile processes already running as that UID.

## macOS: Seatbelt write boundary
- The SBPL profile (`internal/fence/fs/sbpl.go`) keeps `(allow default)`, applies `(deny file-write*)`, then allows writes to the canonical `filesystem.root`, `.nock`, `/private/tmp`, the user's temp and cache paths and required `/dev` pseudo-devices. `filesystem.mode = "read-only"` drops the root write allow (`sbpl.go`).
- Built-in sensitive paths (`internal/fence/fs/seatbelt.go`: `~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/Library/Keychains`) and `filesystem.deny` are denied for reads and writes.
- The profile is validated before launch (`seatbelt.go`) and the child is wrapped with `sandbox-exec` (`seatbelt.go`). A rejected profile or an unresolvable path means `REFUSED-TO-START`; every macOS wrap records exactly one fence state: `ENGAGED`, `REFUSED-TO-START` or `DEGRADED` (`internal/cli/wrap.go`).
- Per-file deny events are best-effort: a background `log stream` tailer (`internal/fence/fs/denylog.go`) records kernel denials as `file_blocked`, at most 500 per session.

**Limits**: reads outside `filesystem.root` are not confined. `filesystem.allow` and `allow_rw` are not enforced on macOS. Apple deprecates `sandbox-exec`. The unified log can drop lines, so a missing row is not proof that no denial happened. The `macos_allow_unfenced` escape hatch was removed in v0.6.0 (`docs/decisions/009-remove-macos-unfenced-escape.md`).

## Windows
No fence. Feasibility notes: `docs/design/windows-feasibility.md`, probes in `docs/probes/`.

## Tests
`internal/fence/fs/*_test.go` (`sbpl_test.go`, `seatbelt_darwin_test.go`, `fuzz_test.go`), `internal/fence/fs/landlock/*_test.go`, interposer tests `internal/fence/fs/interposer_*_test.go`. CI proofs: `.github/workflows/test.yml` (Landlock, macOS SBPL, fuzz smoke).
