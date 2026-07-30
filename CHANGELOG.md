# Changelog

All notable changes to NockLock will be documented in this file.

## [Unreleased]

### Added

- `nocklock verify`: adversarial fence self-test that runs benign proof-of-block
  probes under the live wrap fence path.
- `nocklock doctor` now warns when a curated network allowlist is inert. On Linux,
  when the network fence is active (`allow_all = false`) and the syscall fence is
  on, the child is restricted to unix-domain sockets, so the TCP proxy that
  enforces `network.allow` is unreachable and the posture collapses to no IP
  network — the allowlist reaches *none* of the configured domains, not a subset.
  This is the intended hardened no-network posture, but it silently defeats a user
  who curated `network.allow` expecting selective access, so doctor surfaces it
  with the fix (set `[syscall] enforcement = "off"` for a working, userspace
  boundary, or accept no-network by design).

### Changed

- CI now runs `go build`, `go vet`, a `gofmt` cleanliness check, and the full
  `go test ./...` suite on every push and pull request (`.github/workflows/test.yml`,
  GitHub-hosted `ubuntu-latest`). Until now no workflow ran the Go test suite, so
  the unit tests that guard the fence layers had never gated a merge.

### Fixed

- Documented the previously-undocumented `nocklock doctor` and `nocklock verify`
  commands in the README command table.

### Testing

- **Fuzz coverage over the fence decision surface** — the project's first fuzz
  targets, seeded from the v0.4.0 known-bypass regressions, hunt the next bypass
  class continuously in CI (bounded `-fuzztime`, one target per package). The
  seed corpus also runs as normal regression cases under `go test` (no `-fuzz`):
  - `FuzzConfigLoad` (`internal/config`) fuzzes `Load` and `LoadOverlay` with
    arbitrary bytes. Asserts untrusted-config parsing never panics, a rejected
    config is returned nil (never a partially-populated, possibly permissive
    one), and — differentially against a restrictive profile base — that an
    overlay can only tighten the fence, never widen it (no boolean widener flips
    on, no allowlist grows, no inverted allowlist collapses to its permissive
    empty sentinel, the audit-log path stays immutable).
  - `FuzzFsFencePathDecision` (`internal/fence/fs`) fuzzes `resolvePath`,
    `canonicalizeForProfile`, `GenerateProfile`, and `ProcessConfig`. Generalises
    the fail-open symlink regression (`sbpl_test.go`): every emitted rule path,
    made differential against `filepath.EvalSymlinks`, must be symlink-free, so a
    rule can never carry an unresolved symlink that silently never matches.
  - `FuzzRulesFromConfigContainment` (`internal/fence/fs/landlock`) fuzzes
    `RulesFromConfig` with adversarial root-child names. Asserts every emitted
    grant stays inside the resolved root (N8537) and no configured deny overlaps
    a granted tree (N8441) — the allow-only grant/deny decision fails closed.

## [0.4.0] - 2026-07-09

Users on v0.3.0 should upgrade: this release closes ten bypass paths across
the Landlock, seccomp, LD_PRELOAD interposer, and audit-logging layers. The
two feature additions (runtime profile presets and `nocklock init --runtime`)
are also included.

### Security

- **N8614** — Audit-log symlink attack closed (#57): the log-path resolver
  previously validated only the parent directory, so a symlink at `.nock/events.db`
  pointed outside the project was followed, chmod'd, and written before fences engaged.
  Now: `lstat`-reject a symlink at the final path, open with `O_NOFOLLOW`, post-open
  re-validate via `f.Stat` + `os.SameFile`, and `chmod` by fd rather than path.
- **N8537** — Landlock root symlink escape closed (#56): root children are now
  resolved to canonical paths before Landlock rule emission; any child whose canonical
  target falls outside the configured root is rejected, preventing a project symlink
  from granting access to host paths outside the fence.
- **N8441** — Landlock deny/allow overlap fails closed (#53): a `deny` path that
  overlaps a Landlock-granted tree (root child or `allow` path) is rejected at startup
  with a clear error. Previously the deny rule was silently ignored — Landlock is
  allow-only at the kernel level and the LD_PRELOAD interposer cannot be relied upon
  for static binaries or children that clear `LD_PRELOAD`.
- **N8431** — Reachable Go stdlib CVEs closed (#52): bumped `go` directive
  1.26.1 → 1.26.4. Affected paths include the live network proxy and TLS stacks
  (GO-2026-5039 `net/textproto`, GO-2026-4976 `net/http/httputil`,
  GO-2026-4918 `net/http` ReverseProxy, GO-2026-4866/4870 `crypto/x509` + `crypto/tls`).
- **N8332** — seccomp x32 ABI bypass closed (#48): the BPF filter compared syscall
  numbers against the amd64 denylist and defaulted to `ALLOW`. Linux multiplexes the
  x32 ABI onto `AUDIT_ARCH_X86_64` by OR-ing `__X32_SYSCALL_BIT` (0x40000000) into
  the syscall number, so any denied call could be re-issued with the bit set and
  bypass the filter. The filter now denies any nr carrying `__X32_SYSCALL_BIT` on
  amd64 via `BPF_JSET` before any number comparison. Arm64 is unaffected.
- **N8291** — Metadata mutator fence bypass closed: `libfence_fs.c` mutator hooks
  did not guard null pathnames before `pathname[0]` dereferences and did not preserve
  `EBADF` for invalid-fd path resolution failures. A crafted `AT_EMPTY_PATH` call with
  a valid fd could slip through unrecorded. Now: null pathname guard, `EBADF` preserved,
  `AT_EMPTY_PATH` events reported with fd identifier, original arguments passed through
  after fence checks.
- **N8186** — Medium hardening (#46): seccomp enforcement mode now defaults to
  `required` when absent from config (was `preferred`); Linux `filesystem` `preferred`
  mode is treated as fail-closed at runtime; `filesystem.root` on macOS is rejected at
  startup (Seatbelt cannot enforce root-only isolation — a denylist is not a root
  sandbox); network-fenced runs with syscall enforcement active restrict `socket()` to
  `AF_UNIX` only so IP sockets cannot bypass the network proxy.
- **N8185** — Inherited `NOCKLOCK_FS_ALLOWED` stripped before fence append (#44):
  the LD_PRELOAD interposer reads its policy from the first `NOCKLOCK_FS_ALLOWED`
  entry in the child's environment. An attacker-controlled variable in the parent
  environment survived `secrets.Filter` and sat earlier than the fence's own appended
  value, winning `getenv` first-match and forging an allow-all policy. Now stripped
  from `childEnv` before the fence's value is appended, matching the existing
  `landlockRulesEnv` and `syscallPolicyEnv` strip paths.
- Landlock `allow` paths kept read-only (#45): `cfg.AllowPaths` entries were
  previously granted `rootAccess` (read+write); now forced to `AccessReadOnly`.
- Trusted fence interposer path required (#43): `libfence_fs.so` is located via a
  hardened resolver and its path verified before injection into `LD_PRELOAD`. An
  untrusted or unexpected library at the resolved path is rejected.
- Config security defaults preserved on partial load (#50): a partial TOML file that
  omits security-relevant keys no longer resets them to permissive Go zero values.

### Added

- Runtime profile presets (#51): embedded TOML presets for `claude-code`, `codex`,
  `aider`, `gemini-cli`, and `opencode`. Presets enforce default-deny network with
  runtime-specific egress grants and cache paths. Overlay semantics for inverted fields
  (`secrets.pass`, `syscall.socket_families`) tighten rather than loosen: a disjoint
  user overlay keeps the restrictive base. Each preset passes the runtime's own
  provider API key variable while blocking unrelated credentials.
- `nocklock init --runtime <name>` (#55): scaffolds `.nock/config.toml` from an
  embedded preset. `aider`, `gemini-cli`, and `opencode` are supported. `cursor-agent`
  and `continue` are intentionally absent — their default egress cannot be pinned
  from first-party docs.

### Dependencies

- `golang.org/x/sys` 0.44.0 → 0.46.0 (#54)
- `modernc.org/sqlite` 1.52.0 → 1.53.0 (#49)

---

## [0.3.0] - 2026-06-18

### Security

- Syscall fence hardening follow-ups (#39): absent `[syscall]` tables fail closed on
  kernels without seccomp; network-fenced sessions that activate the syscall fence deny
  all non-Unix socket families via the BPF program so IP sockets cannot bypass the
  network proxy.

### Added

- Syscall-surface fence (#38, N8122): seccomp-BPF on Linux (kernel-enforced, pure Go,
  no cgo) and hardened SBPL syscall-surface extensions on macOS. Baseline denylist =
  Kubernetes RuntimeDefault inverted (default `ALLOW`, explicit `EPERM` per dangerous
  subsystem): covers `bpf`, `perf_event_open`, `ptrace`, `keyctl`, raw socket creation,
  and `CLONE_NEW*` namespace creation. Applied via re-exec shim so Landlock and the
  syscall filter are both in place before `execve`. Config: `[syscall]
  enforcement = required|preferred|off`.
- `nocklock doctor` health check (#42): reports fence support status (Landlock, seccomp,
  Seatbelt), config validity, and audit-log health.
- Extended macOS default denylist (#37): `.netrc`, `.docker/`, and `.git-credentials`
  added to the Seatbelt credential-store deny list alongside the existing `.ssh/` and
  `.kube/`.

### Fixed

- Tagged release builds no longer append `(dev)` to the version string (#40, N8112).
- Anvil AI review job skipped on public repos, clearing false-red CI on every PR
  (#41, N8114).

### Dependencies

- `modernc.org/sqlite` 1.50.1 → 1.52.0 (#33)

---

## [0.2.0] - 2026-06-14

Users on v0.1.0 should upgrade: this release closes multiple bypass paths in the
filesystem, network, and audit-logging layers.

### Security

- **CRITICAL** — Network proxy fails closed on start or runtime failure (#9, #15):
  proxy bind and health check gate child startup; a watchdog goroutine monitors proxy
  health throughout the session and kills the child process group on unexpected proxy
  death. `--allow-unfenced` is rejected; NockLock fails closed when the network fence
  is unavailable.
- **CRITICAL** — Process group isolation (#9): wrapped child placed in its own process
  group (`Setpgid: true`); context cancellation sends `SIGKILL` to the entire group;
  Linux additionally sets `Pdeathsig: SIGKILL` so descendants cannot escape the fence
  by forking before the wrapper process exits.
- **CRITICAL** — stat-family TOCTOU closed (#9, #17, `43e558d`): all
  stat/lstat/fstatat/faccessat/readlinkat/`__xstat`/`__lxstat`/`__fxstatat`/statx hooks
  now pass the resolved canonical path to the real syscall, closing the symlink-swap
  race between `check_path` and the actual operation. Non-path fds (`AT_EMPTY_PATH`,
  procfs magic fds) bypass path resolution safely.
- **CRITICAL** — open/write-family TOCTOU closed (#32): all mutating/open hooks
  (open/openat, unlink, mkdir, rename, link, chmod, chown, truncate, symlink/symlinkat)
  pass the resolved canonical path to the real syscall. The symlink-swap window between
  the fence check and the kernel call is closed for the entire mutating surface.
- **HIGH** — DNS rebinding prevention (#9): `DNSCache` pins the first resolved IP set
  for each hostname; subsequent lookups return the cached result. Rebinding attempts are
  blocked and logged.
- **HIGH** — DNS cache key normalization (#9): hostnames are lowercased and trailing
  dots stripped before lookup and store so mixed-case variants share one pinned cache
  entry and cannot produce divergent IP sets.
- **HIGH** — Link-local / cloud-metadata blocked unconditionally (#28): `169.254.169.254`
  and all link-local unicast addresses remain blocked even when `--allow-private-ranges`
  is set. RFC-1918, loopback, and CGNAT ranges remain permittable for local development.
- Audit log fenced from fenced child (#31): the `.nock/` audit directory is injected
  into the filesystem fence deny list before fence activation, preventing a fenced agent
  from tampering with or deleting `events.db`. Applies to both the Linux LD_PRELOAD
  interposer and the macOS Seatbelt SBPL deny list.
- Fail closed when event log cannot open (#30): a session that cannot write the audit
  log does not start. Matches the network fence posture — unrecorded operation is treated
  as unfenced operation; no opt-out.
- Linux Landlock kernel-enforced fence (#36, N8027/N8067): Landlock LSM composites with
  the LD_PRELOAD interposer (Landlock enforces at the kernel level; interposer reports
  and covers userspace gaps). Applied via re-exec shim (no cgo). ABI auto-detected and
  clamped; fail-closed by default.
- Strict config validation (#9): `config.Load()` validates `filesystem.mode`,
  `logging.level`, `cloud.api_key` (when enabled), and path-traversal in allow/deny
  lists. Invalid configs exit non-zero with a specific error rather than silently
  applying defaults.
- Warden launch-blocker findings (#14): additional fail-closed hardening for proxy
  availability, DNS rebinding detection, and dry-run validate path coverage.

### Added

- macOS filesystem fence via Seatbelt, Phase 1 (#27, N7938): SBPL denylist profile
  enforced via `sandbox-exec`. Path canonicalization via `EvalSymlinks` is mandatory —
  a non-canonical (subpath) rule silently fails open (`/tmp` vs `/private/tmp`), so
  unresolvable paths fail closed. Interim denylist posture; strict root-only allowlist
  enforcement gated on the Endpoint Security framework.
- `nocklock validate [config-path]` and `nocklock wrap --dry-run` (#9): validate config
  and print the effective policy summary without starting fences or a child process.
- `--allow-private-ranges` flag (#9): permits RFC-1918/loopback connections for local
  development; link-local and cloud-metadata ranges remain blocked unconditionally.
- Anvil CI: Codex PR security review on every non-draft PR (#11).
- gitleaks pre-commit hook + CI scan (N7714).
- Dependabot security updates enabled (N7715).
- Branch-lock `PreToolUse` hook (#10, task 144): prevents mid-session branch switching
  in Claude Code sessions. Scoped to `git checkout` and `git switch`; merge and rebase
  are unrestricted.

### Fixed / CI

- Anvil action versions pinned to commit SHAs to harden against tag-move supply-chain
  attacks (#13).
- Anvil sandbox downgraded to workspace-read-access (#12).
- Anvil Codex auth home isolated to prevent cross-session credential bleed (#16).
- Skip AI reviews for Dependabot PRs to reduce noise (#35).

### Dependencies

- `modernc.org/sqlite` 1.48.1 → 1.50.1 (#24)

---

## [0.1.0] — 2026-04-06

### Added
- CLI skeleton: `wrap`, `init`, `config`, `log`, `status`, `version` commands (PR #1, #2)
- TOML config parsing with strict validation (reject unknown keys)
- `nocklock init` creates `.nock/config.toml` with security-first defaults
- `nocklock wrap` passes through to child process (fences coming in PR #3-6)
- Cross-platform exit code handling (no Unix-only syscall dependencies)
- Makefile with build, test, lint targets
- Default config: deny `~/.ssh/`, `~/.aws/`, `~/.gnupg/`; block `AWS_*`, `*_SECRET*`, `*_TOKEN*`
