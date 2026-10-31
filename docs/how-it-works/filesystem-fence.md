# Filesystem fence

Citations name source files at `origin/main` 89c02fa (no line numbers, so they do not go stale). Wording of limits follows `README.md` ("Filesystem platform boundary").

Both platforms merge the mandatory credential deny set with user denies through
`internal/fence/fs/builtins.go`. Grants overlapping a built-in path refuse startup.
macOS adds home `.env*` and `.claude*` prefix rules and `.codex`, with only the
selected agent preset exempting its own login store. `--profile` selects it, or
`project.runtime` when the wrapped command runs that agent: the project config
is writable by the fenced child, so it cannot pick the exemption on its own
(`config.LoginStoreRuntime` in `internal/config/config.go`). Each signed
`config.digest` row records the exempt runtime outside the hashed policy, and a
change from the previous wrap writes a signed `config.runtime_changed` row
(`internal/cli/config_digest.go`). Project `.env*` files stay readable; see the
README for the complete path list and preset migration.

Pre-made hard links into an allowed project tree can remain readable, including
on macOS: Seatbelt path rules do not find every name for an inode. The CI proof
asserts this limitation instead of claiming hard-link isolation.

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
- Every profile also denies Mach lookups of `com.apple.SecurityServer`. Service-by-service tests identified this as the route used by both queries against the synthetic private file keychain, including when its database is outside the sensitive-path denylist. The other inspected service names (`com.apple.securityd`, `com.apple.security.keychaind`, `com.apple.secd`, `com.apple.security.agent`) are not denied without a demonstrated need; data-protection and other Keychain backends are not claimed isolated. It applies without hardened mode or a network proxy. Tools that retrieve credentials through SecurityServer inside the fence will fail; supply only the credentials the agent needs through an explicitly allowed environment variable or another supported credential source. An agent login-store file exception does not exempt SecurityServer.
- The profile is validated before launch (`seatbelt.go`) and the child is wrapped with `sandbox-exec` (`seatbelt.go`). A rejected profile, an unresolvable path or `HOME`, or a `filesystem.root`, `allow` or `allow_rw` grant overlapping a built-in credential deny means `REFUSED-TO-START`; every macOS wrap records exactly one fence state: `ENGAGED`, `REFUSED-TO-START` or `DEGRADED` (`internal/cli/wrap.go`).
- Deny events are best-effort: a background `log stream` tailer (`internal/fence/fs/denylog.go`) records attributed kernel file denials as `file_blocked` and SecurityServer denials as `secret_blocked`, sharing a 500-event session cap. A missing unified-log record is not proof of successful access.

**Limits**: reads outside `filesystem.root` are not confined. `filesystem.allow` and `allow_rw` are not enforced on macOS. Apple deprecates `sandbox-exec`. The unified log can drop lines, so a missing row is not proof that no denial happened. The `macos_allow_unfenced` escape hatch was removed in v0.6.0 (`docs/decisions/009-remove-macos-unfenced-escape.md`).

## Decoy files

A decoy is a fake credentials file nobody should ever open. Deny it, and any read of it by a fenced agent fails and leaves a signed `file_blocked` row, with no cooperation from the agent.

1. Create a file with obviously fake values, outside any real credential path:

   ```sh
   mkdir -p ~/decoys
   printf '[default]\naws_access_key_id = FAKE-DECOY-DO-NOT-USE\n' > ~/decoys/aws-credentials
   ```

2. Add it to `.nock/config.toml`. Keep the default entries when you extend the list:

   ```toml
   [filesystem]
   deny = ["~/.ssh/", "~/.aws/", "~/.gnupg/", "~/.nock/", "~/decoys/aws-credentials"]
   ```

3. Run the agent with `nocklock wrap -- <agent>`. Afterwards, list the denials and check the chain:

   ```sh
   nocklock log --blocked
   nocklock verify --audit
   ```

   A read of the decoy appears as a `file_blocked` row whose detail names its path. macOS shows `file-read-data <path>`; Linux shows `op=... path=<path> reason=...`, or a JSON detail carrying the same path.

Proven by `TestWrapMacOSDecoyFileReadIsLogged` (`internal/cli/wrap_darwin_test.go`) and `TestWrapDecoyFileReadIsLogged` (`internal/cli/wrap_decoy_linux_test.go`): the read fails, the decoy's contents do not reach the child, an undenied sibling stays readable, exactly one row names the decoy and the chain verifies.

What it does not catch:
- Agents NockLock did not launch.
- Linux: a static binary, or a child that clears `LD_PRELOAD`, bypasses the interposer. It is denied only by Landlock, only where the decoy is outside every granted root, and it writes no row. A decoy inside a granted directory (such as the project root) is not denied at all in that case.
- Linux with `linux_enforcement = "off"`, or `"preferred"` on a kernel without Landlock, adds no kernel backstop.
- macOS rows come from the unified log, which can drop lines: a missing row is not proof that no read happened.

## Windows
No fence. Feasibility notes: `docs/design/windows-feasibility.md`, probes in `docs/probes/`.

## Tests
`internal/fence/fs/*_test.go` (`sbpl_test.go`, `seatbelt_darwin_test.go`, `fuzz_test.go`), `internal/fence/fs/landlock/*_test.go`, interposer tests `internal/fence/fs/interposer_*_test.go`. CI proofs: `.github/workflows/test.yml` (Landlock, macOS SBPL, fuzz smoke).

`internal/fence/fs/seatbelt_keychain_darwin_test.go` compiles the Security.framework helper in `internal/fence/fs/testdata/keychain_probe.c`. It creates a disposable private keychain, disables interactive prompts, scopes both query APIs to that keychain, deletes it afterward and checks that the user's default and search list are unchanged. The generated profiles deny the synthetic credential read while allowing an ordinary file read; removing only the Keychain service rule restores credential access. This proves isolation of the tested SecurityServer route independently of path denies. It does not establish that the old profile bypassed a denied Keychain file: that separate local probe was already blocked. The macOS CI enforcement job runs this test and requires its compiler and sandbox prerequisites.

Certificate-trust services `trustd` and `ocspd` stay outside the denylist. `internal/cli/wrap_keychain_https_darwin_test.go` exercises system curl, a Go system-root HTTPS client and `git ls-remote` against public GitHub through the enforced proxy under the Claude Code preset. The macOS CI job enables this live control with `NOCKLOCK_KEYCHAIN_HTTPS_REQUIRE=1`; ordinary offline runs skip it. An optional `NOCKLOCK_KEYCHAIN_CLAUDE_BINARY` absolute path also checks an installed Claude Code's `--version` inside that preset, without credentials or a model request. The CI preset control launches ordinary tools and does not require Claude Code to be installed.

On Linux, the interposer permits stat-family metadata queries on canonical ancestors of the project root so tools such as Git can resolve its path. This grants neither directory listing nor file reads outside the configured roots. Explicit denies still take precedence.
