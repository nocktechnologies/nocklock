# Changelog

All notable changes to NockLock will be documented in this file.

## [Unreleased]

### Added
- Branch-lock PreToolUse hook (`.claude/hooks/branch-lock.sh`, task 144) — prevents agent sessions from switching branches mid-session by inspecting `git checkout` / `git switch` commands. Scope limited to branch switches; `git merge` and `git rebase` remain unrestricted. Lock file `.branch-lock` at repo root is gitignored; remove to reset.

### Security (hotfix/security-139-142)
- **CRITICAL** — Network proxy now fails closed (task 139): if the proxy cannot bind, fails readiness, or crashes, NockLock exits non-zero and the child never runs. A health/readiness probe gates child startup, and a proxy watchdog monitors health during the session.
- **CRITICAL** — Process group isolation (Codex gate): wrapped child is placed in its own process group (`Setpgid: true`). On context cancellation the entire process group is killed via `SIGKILL` — descendants cannot escape the fence by forking before the parent dies. On Linux, `Pdeathsig: SIGKILL` additionally kills the child if the nocklock wrapper exits unexpectedly.
- **CRITICAL** — LD_PRELOAD hook now intercepts `stat`, `lstat`, `fstatat`, `faccessat`, `readlinkat`, `__xstat`, `__lxstat`, `__fxstatat`, and `statx` (kernel ≥4.11, Linux only — task 140). Denied stat-family calls return ENOENT; denied access/readlinkat calls return EACCES. `lstat` path resolution preserves symlink-no-follow semantics.
- **CRITICAL** — TOCTOU race in stat-family hooks closed (Codex gate): all stat/lstat/fstatat/statx hooks now pass the resolved canonical path to the real syscall. A symlink swap between `check_path` and the real call can no longer redirect the stat outside the fence.
- **MAJOR** — DNS rebinding prevention (task 141): proxy pins the first resolved IP set for each hostname and verifies later DNS answers against it. Rebinding attempts are blocked and logged. Use `--allow-private-ranges` to permit RFC1918/loopback connections (local dev).
- **MAJOR** — DNS cache hostname canonicalization (Codex gate): `DNSCache.LookupOrResolve` normalizes hostnames (lowercase + strip trailing dot) before lookup and store. Mixed-case variants cannot produce divergent cache entries.
- **MAJOR** — Strict config validation (task 142): `config.Load()` now runs semantic validation (`filesystem.mode`, `logging.level`, `cloud.api_key` when enabled, path traversal in allow/deny lists). Invalid configs exit non-zero with a specific error rather than silently applying defaults.

### Added
- `nocklock validate [config-path]` and `nocklock wrap --dry-run` — validate config and print the effective policy summary without starting fences or a child process (task 142).
- `--allow-unfenced` is rejected; NockLock fails closed when the network fence is unavailable.
- `--allow-private-ranges` flag on `nocklock wrap` — permits RFC1918/loopback network connections (task 141).
- `config.NetworkConfig.AllowPrivateRanges` field (`toml:"allow_private_ranges"`) (task 141).

### Added
- README.md: complete rewrite for public launch — accurate defaults, Quick Start, full command reference, platform notes
- Integration tests: 10 end-to-end tests covering all three fences (`integration/integration_test.go`, `//go:build integration`)
- Homebrew tap formula: `brew install nocktechnologies/tap/nocklock` via `nocktechnologies/homebrew-tap`
- Network fence (PR #7) — local HTTP/HTTPS proxy on 127.0.0.1:<random> enforces domain allowlist
  - HTTP CONNECT tunnel for HTTPS (no MITM — hostname inspection only, payload never decrypted)
  - Domain matching: exact hostname + all subdomains, `*.example.com` wildcard, case-insensitive
  - Raw IP addresses blocked (fail closed)
  - `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` injected into child env
  - `NO_PROXY`/`no_proxy` cleared from child env to prevent bypass
  - Fail closed: agent does not start if proxy fails to start
  - `allow_all = true` disables the fence entirely
  - `nocklock status` shows network fence domain count
  - 27 new tests in `internal/fence/network/`
- Filesystem fence via LD_PRELOAD — intercepts file system calls on Linux, blocks access outside allowed directory tree (PR #6)
- C shared library (`libfence_fs.so`) intercepts 27 libc functions with symlink-safe path resolution
- Filesystem config: `root`, `mode` (read-write/read-only), `allow`, `deny` with tilde expansion
- Deny list takes priority over allow list; allow list is read-only
- Fence events reported over Unix domain socket and logged to SQLite
- Linux-only guard with clear macOS error message
- `build-fence-fs` and `build-all` Makefile targets
- Standardized repo with `.claude/` directory, Mermaid architecture diagrams, DESIGN.md, review pipeline
- ARCHITECTURE.md documenting package structure and data flow
- Architecture Decision Records (ADRs) in `.claude/decisions/`
- Lessons learned docs in `.claude/lessons/`
- Review pipeline (`.claude/review/PIPELINE.md`) — 7-phase process

## [0.1.0] — 2026-04-06

### Added
- CLI skeleton: `wrap`, `init`, `config`, `log`, `status`, `version` commands (PR #1, #2)
- TOML config parsing with strict validation (reject unknown keys)
- `nocklock init` creates `.nock/config.toml` with security-first defaults
- `nocklock wrap` passes through to child process (fences coming in PR #3-6)
- Cross-platform exit code handling (no Unix-only syscall dependencies)
- Makefile with build, test, lint targets
- Default config: deny `~/.ssh/`, `~/.aws/`, `~/.gnupg/`; block `AWS_*`, `*_SECRET*`, `*_TOKEN*`
