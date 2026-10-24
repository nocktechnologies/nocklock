# Changelog

All notable changes to NockLock will be documented in this file.

## [Unreleased]

### Added

- `nocklock verify --export ocsf [--out <file>]` writes the signed audit log as OCSF 1.9.0 events, one JSON line per row, for security tools that ingest OCSF. Each event carries its source row verbatim, and a closing trailer carries the chain head, the head signature and the public key, so every entry hash, row signature and the head signature can be checked from the export alone. The export verifies the chain first and refuses, exiting `1` and writing nothing, when verification fails, the log gains rows between those checks and the read, or `--out` names the audit database, its SQLite sidecars, its chain anchor, the signing key or a trusted chain identity file. The `--out` directory is opened once and the export is renamed into it, so a symlink swapped mid-export cannot redirect it. `--export` refuses `--json` and `--audit`. CI validates the golden export against the pinned OCSF class schemas. See `docs/how-it-works/audit-log.md`.

### Security

- macOS: `project.runtime` alone no longer exempts an agent login store from the built-in `.claude*` and `.codex` denies. The project config is writable by the fenced child, so the exemption now comes from `--profile`, or from `project.runtime` only when the wrapped command runs that agent (`claude` for `claude-code`, `codex` for `codex`). Any other command keeps every agent login store denied, and a config that grants the store then refuses to start. This corrects the v0.14.0 note that the runtime is recorded in the signed config digest: the declared `project.runtime` and the resolved deny rules are in the hashed policy, so the digest changes when the exempt agent changes (for example `wrap -- claude` then `wrap -- make`), and the `runtime` field of each signed `config.digest` row names the agent. When it differs from the previous wrap of the same project, `wrap` prints a warning and writes a signed `config.runtime_changed` row. Other platforms have no login-store exemption and record no runtime. `doctor` and `wrap --dry-run` without a command have no wrapped command and judge the run `wrap -- <agent>` for the agent `project.runtime` names. A refused login-store grant now names `--profile` and the agent command as the fix, for example when a wrapper such as `npx` launches the agent.

## [0.14.0] - 2026-10-23

v0.14.0 makes the credential-file denies mandatory on Linux and macOS (#269). A config can add paths to the deny list but can no longer remove the built-in ones, and a config that grants one of the protected folders now refuses to start. Read the upgrade note under Breaking before you upgrade.

### Breaking

- The credential-file denies are mandatory on Linux and macOS: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, `~/.kube`, `~/.docker`, `~/.netrc` and `~/.git-credentials`, plus `~/.nock` and `~/Library/Keychains`. `filesystem.deny` adds to this list but cannot remove from it. A `filesystem.root`, `filesystem.allow` or `filesystem.allow_rw` grant that overlaps one of these paths, including a grant of the whole home directory, now refuses to start. To upgrade: run `nocklock doctor` in each project, or start a `wrap`; the refusal names the grant and the built-in deny it overlaps. If the agent needs a file that lives in one of those folders, move or copy that file to a location outside them and grant that location instead; otherwise drop the grant. Narrowing a grant to a subfolder of a protected folder does not help: any overlap is refused.
- Existing OpenCode and Goose presets now refuse startup because they grant paths beneath the mandatory `~/.config` deny. They need separately reviewed runtime configurations that relocate required files outside protected credential directories.

### Security

- The credential-file denies are now mandatory on Linux and macOS (#269): a config can no longer remove the built-in ones. See Breaking for the list and for grants that now refuse to start. macOS also denies home `.env*`, `.claude*`, and `.codex`, except the login store of the agent named by `project.runtime` (or the `--profile` preset), so that agent can sign in; the runtime is recorded in the signed config digest. Generic defaults no longer grant `~/.claude/`. Package manager config denies stay opt-in.
- Keep project `.env` and `.env.*` readable and make `doctor` report `PARTIAL` for actual secret-shaped values, without disclosing values. The check covers the project root plus one level, skips dependency/build directories, and reports incomplete inspection as informational `not checked`. Document pre-made hard links into a granted project as a remaining read exposure on both platforms.
- Add CI-only credential canaries, allowed controls, and per-case policy-removal mutation checks on Linux and macOS, including symlinks, hardlink names, case aliases, grandchildren, and Linux `/proc/self/root`.
- On macOS the signed config digest records the home `.env*` and `.claude*` prefix rules, not the home entries they match, so a matching file appearing or going away leaves the digest unchanged. Existing matches, including symlink targets, are still denied.
- The `doctor` `.env` check inspects the inline default of a `${VAR:-default}`, `${VAR:=default}` or `${VAR:+value}` reference on a secret-named key; a plain `$VAR` or `${VAR}` reference is not reported.
- The `doctor` `.env` check ignores an unquoted inline comment (whitespace then `#`), so `API_KEY= # your key here` is not reported, and reads a single-quoted value as literal text, so `API_KEY='$abc'` is reported; double-quoted and unquoted values keep reference parsing.

### Fixed

- On macOS a built-in credential deny refusal (a filesystem grant overlapping a built-in deny, or no resolvable `HOME`) is recorded as one `REFUSED-TO-START` filesystem fence state before the run refuses, instead of exiting as an unrecorded config error. `--dry-run` still reports it.
- When the filesystem config is refused, such as by a grant over a built-in credential deny, `doctor` reports the `signing-key` row as `will-refuse` with the filesystem refusal as its cause and fix, instead of `unresolved` with a signing key path fix.

## [0.13.1] - 2026-10-21

v0.13.1 raises the minimum Go version to 1.27.3 to fix reachable standard-library vulnerabilities.

### Security

- Requires Go 1.27.3 or later to build. GO-2026-6809 in `crypto/x509`, reached through the proxy's `http.Server.Serve`, affects Go before 1.26.10 and Go 1.27.0 to 1.27.2. go.mod now requires Go 1.27.3, so any older toolchain, including the patched 1.26.10, either downloads Go 1.27.3 automatically or refuses to build. On macOS, run `brew update && brew upgrade nocklock`. On Linux, rebuild from source as described in docs/setup.md, including the interposer library.

### Added

- CI job `landlock-abi9-receipt` (`.github/workflows/landlock-abi9-receipt.yml`). On a GitHub-hosted runner it boots a throwaway KVM guest from a digest-pinned Ubuntu 26.10 cloud image, fails unless the guest kernel reports Landlock ABI 9 or later, and runs the kernel cases. The receipt records the kernel, ABI, commit and, for each case, expected and actual results. Under a full `CONFINED` wrap, an unrelated pathname socket outside `filesystem.root` and an abstract socket are denied and the policy-allowed proxy and event sockets connect. The io_uring case probes the seccomp filter directly, not a full wrap: `io_uring_setup` is denied after an unfenced control reaches a live listener. A passing receipt is signed with the workflow's Sigstore identity. `doctor` and `wrap` claims are unchanged until a release carries this receipt.
- `bench/redteam/kernel_cases.py --require-abi N` fails before any case on a kernel below Landlock ABI N; with `--out`, every case must pass and each enforcement claim must match. Reports now record the Landlock ABI.

### Changed

- The Linux candidate workflow signs its manifest through `packaging/linux/sign-manifest.sh`, shared with the receipt job. The signature, verification and both refusal controls are unchanged. The shared script also checks the manifest with `sha256sum --check --strict` before signing.
- The tamper-evident audit log spec now says it shipped (#89, #90, #93).

## [0.13.0] - 2026-10-17

v0.13.0 adds repo git-config execution warnings to `doctor` and a Linux netns proof for GitSpawn. It also simplifies audit appends, retires unused internal v1 HTTP routes, and removes inert cloud settings from newly generated configs. Existing config files and audit formats remain compatible. GitSpawn warnings leave doctor verdicts and exit codes unchanged; the new enforcement proof covers Linux netns mode only.

### Fixed

- Integration fixtures now explicitly disable syscall enforcement when the shared fixture disables filesystem fencing, check the generated syscall section, and resolve the audit DB through the current config API. The runner keeps audit state in its temporary directory. Product enforcement and existing fence proofs are unchanged.

### Added

- `doctor` warns about repo git config that runs code ("GitSpawn"). Run inside a git repository, it lists each local config key whose value is a program git runs, such as `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, diff `textconv`, filter and merge drivers, credential helpers and `!` aliases. It reads `.git/config`, `config.worktree` and the files they include (not your system or global config) for the repository doctor runs in, and names the key, its value and the file it came from. A repository config doctor cannot read (an include that stalls the read past the timeout, such as a FIFO, or git older than 2.26) is reported as an incomplete warning, not skipped; a config git cannot parse or open gets no doctor warning, because every git command then fails with git's own error and runs nothing. The warning leaves the verdict and exit code unchanged, and doctor runs no hook and removes nothing.
- A Linux CI proof for GitSpawn (`gitspawn-proof`). A planted `core.fsmonitor` program fires on `git status` and, unwrapped, reaches a host outside the allowlist, reads a file under `~/.ssh/` and writes outside the project. Under `wrap --profile claude-code --net-fence=netns` it still fires, all three are blocked, each block is a signed audit row, and `verify --audit` reports `AUTHENTIC`. Proxy-mode networking and macOS are not covered. See `docs/how-it-works/doctor-and-verify.md`.

### Changed

- `LogImmediate` uses the same immediate SQLite transaction as ordinary event writes, preserving write-lock waiting, committed-event callbacks, and signed run-close accounting without an unused predecessor lookup.
- Removed the unused internal HTTP client for ordinary v1 anchor pushes and fetches. Remote v2 enrollment, migration, and conditional updates, plus local v1 anchor-file verification, are unchanged.
- Newly generated configs, runtime presets, and examples omit the inert `[cloud]` section. Existing cloud settings still decode and validate as before; optional delivery uses `[audit.forward]`.
- Release runbook: one whole-repo cleanup pass before the release notes.
- CI skips the test suites on a pull request that changes only `*.md` files or `docs/` (`scripts/ci-code-changed.sh`). The required checks still run and report green; the public content, `AGENTS.md` path and gitleaks checks still run. Pushes to `main` and `next` always run everything. `AGENTS.md` now asks contributors to run the tests for the packages they touched, plus lint; the full suite runs once, in CI.
- `AGENTS.md` is the full agent index, with build, checks, rules, gotchas and locations; `CLAUDE.md` only imports it and adds Claude Code notes. New `docs/HANDOFF.md` carries pod notes between runs. CI now fails when `AGENTS.md` names a path git does not track, or one outside the repo (`scripts/check-agents-paths.py`).

## [0.12.0] - 2026-10-17

v0.12.0 refuses a `.nock/config.toml` that another user could rewrite, and `nocklock doctor` now lists deputies: more-privileged helpers the wrapped agent can reach and ask to act for it. `wrap` now fails the run when it cannot record one of its own blocks, including a blocked network request, and can push the committed audit head off-box during a run instead of only at teardown. CI now builds signed Linux install candidates; no release assets ship with this release. Read the upgrade notes under Breaking before you upgrade: a config in a directory other users can write is refused, and some `doctor` verdicts move from `PROTECTED` to `PARTIAL`.

### Breaking

- Every command that reads `.nock/config.toml` (`wrap`, `doctor`, `validate`, `status`, `log`, `config`, `verify`) now refuses the config when the file, or any directory its path passes through (including through symlinks), is world-writable, is group-writable by a group other than your own private group, or is owned by a user other than root or you. A config that loaded before can be refused after upgrading, including every project under `/tmp` or `/var/tmp`. To upgrade, run `nocklock validate` in each project. If it refuses the config, the message names the offending path and its fix (`chmod go-w <path>`, or `chown` for a foreign owner). You can also move the project under your home directory. Group write by your private group is accepted, so on hosts with local accounts a fresh project on Debian or Ubuntu with the default umask of `002` loads without changes. The private-group check reads only `/etc/group` and `/etc/passwd`, so on a host whose accounts come from a directory service (LDAP, SSSD or NIS) a 0775 project can still be refused; there, run `chmod g-w` on the named path or, for a layout you know is safe, set `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG=1` in the operator environment (NockLock never reads it from the config file).
- `doctor` keeps the verdict at `PARTIAL` (exit 3) when it finds a deputy the fence does not block. A project with writable agent config inside `filesystem.root`, or a macOS host where sudo runs without a password prompt, now reports `PARTIAL` where it reported `PROTECTED`. To upgrade: if a script accepts only exit 0 from `doctor`, read the new Deputies section, then lock the deputy down or accept the `PARTIAL`.

### Security

- Before reading `.nock/config.toml`, NockLock resolves its path one component at a time, the way the kernel does, and checks the ownership and permissions of the file and of every directory the resolution passes through: each ancestor, each directory holding a symlink, and each directory a symlink leads into. It refuses a config any other user could rewrite: world-writable (the sticky bit is not an exemption), group-writable by a shared group, or owned by someone other than root or the invoking user. Your private group is your primary group when it has your login name and no other members, as far as the local account files show; a group whose members cannot be read counts as shared. A trusted system symlink such as macOS's `/var -> /private/var` loads; a symlink planted in `/tmp`, or one leading into a writable directory, is refused. The file it checks is the file it reads: it opens the resolved file, checks the open handle, and reads from it, and `..` after a symlink is resolved against the link's target, not lexically. This stops the next run from picking up a config planted in a world-writable directory, or one in a directory chain another user owns. `nocklock verify` sets `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG` only for the probe it runs in its own freshly created scratch directory.
- Linux: when the CLI runs from a versioned release directory (`/usr/local/lib/nocklock/releases/<version>/`), `wrap` loads only the interposer library installed next to it. If that library is missing, `wrap` refuses to start instead of falling back to the fixed `/usr/local/lib/nocklock` or `/usr/lib/nocklock` library, which could be an older build that does not match the CLI. Installs outside that directory search as before.
- `allow_private_ranges` no longer permits Alibaba Cloud's instance-metadata address (100.100.100.200). It stays blocked unconditionally, like AWS's metadata endpoints. The rest of the CGNAT range it sits in stays reachable under the option.

### Added

- Deputies in `doctor`. The new Deputies section lists the helpers the wrapped agent can reach: container sockets (Docker, containerd, Podman, Docker Desktop on macOS), the systemd user bus and user unit directory on Linux, `~/Library/LaunchAgents` on macOS, writable shell startup files, writable Claude Code, Codex, Cursor and Gemini CLI config and hook files (user and project), and sudo that runs without a password prompt from a NOPASSWD rule. The sudo check runs only `/usr/bin/sudo -k -n true` with a short timeout, so it never prompts, ignores a cached sudo login without refreshing it, and never runs a `sudo` found on `PATH`. A config file or directory also counts as reachable when its folder is writable, because the agent can replace it. Each row, and each `--json` check with `"group": "Deputies"`, says what the deputy is, whether the fence blocks it, and why it matters. Doctor changes nothing on the machine. `GAPS FOUND`, `UNPROTECTED` and `network.require_unix_socket_isolation = true` behave as before. See `docs/how-it-works/deputies.md`.
- In-run anchor checkpoints. `wrap` can upload the committed audit head to the anchor store while the run is in progress, not only at teardown. Set `NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL` (and optionally `NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE`) in the operator environment; checkpoints are off by default, and a malformed value refuses the run before the child starts. One upload runs at a time, through the existing v2 push and its conditional update, and each is bounded by the deadline. A failed upload is recorded and retried and never fails the run. At teardown, `wrap` runs the usual final push and prints the last confirmed checkpoint, the lag and the last failure. If `wrap` is killed, the remote pin stays at the last confirmed checkpoint. A checkpoint is not an independent signed timestamp and does not protect rows written after the last confirmed pin.
- An offline rotation endorsement format, with public accept and reject vectors and a library verifier. An endorsement binds an independently trusted first-key fingerprint, both chain IDs, the exact tail and row count of the retiring chain, and the successor key, and the successor can sign its acceptance. No command uses it yet: NockLock does not switch keys or migrate remote anchors with it. An endorsement does not restore trust in a compromised retiring key and does not replace the remote v2 pin. See `docs/design/rotation-endorsement.md`.
- Signed Linux CI candidates. CI builds an Ubuntu 24.04 amd64 archive that pairs the CLI with the matching filesystem interposer, signs its checksum manifest with Cosign keyless signing, and checks a fresh install on a disposable VM: filesystem allow and deny controls, the `doctor` boundary, and authentic audit logs that report `CONFINED` and `KERNEL`. These are candidates, not releases: no release assets are attached yet, and there is no public installer, upgrade or rollback path. Keep using the source install in `docs/setup.md`. See `packaging/linux/INSTALL.md` and `docs/design/linux-packaging.md`.

### Fixed

- `wrap` now exits 2 with a fatal message naming the error when it cannot write one of its own blocked-event rows to the audit log: filesystem denials, macOS denial rows, network fence errors, blocked environment variable rows, `session_end`, and each blocked network request (allowlist and look-back denials, DNS rebinding blocks, and the row written when the network fence degrades). A blocked-row write failure while the child runs stops the child. A denied network request is still refused. Previously these write errors were ignored and the run could exit 0. Rows for allowed network requests stay best-effort.
- Every audit append (`Log`, `LogImmediate` and `LogBatch`, so all rows including the blocked environment variable rows, the secret preflight rows and blocked network request rows) now takes the write lock up front, so a second concurrent `wrap` or an in-run checkpoint verify waits for the lock (up to 5 seconds) instead of failing at once with `SQLITE_BUSY`. Under heavy lock contention a denied network request can wait for the lock before it is refused.
- `verify`: the syscall check's positive control now runs an operation that succeeds without the fence. An unfenced `EINVAL` is reported as inconclusive, which fails verify.

### Changed

- Docs: `AGENTS.md` is the contributor and agent map and `CLAUDE.md` imports it. The full invariant list is in `docs/context/invariants.md`. `docs/ROADMAP.md` is one dated now / next / later page; release history stays in this file.
- New design note: `docs/design/public-timestamp-v2-digest.md` describes an optional public timestamp over the v2 anchor snapshot digest. It is design only; NockLock does not request or check public timestamps.
- Red-team bench: a proof path or match containing a `..` component no longer counts as a match.

## [0.11.0] - 2026-10-15

v0.11.0 makes each run's audit trail provably complete or provably cut short. `wrap` now ends every run with a signed close row, and `nocklock verify --audit` reports whether each run closed cleanly, was cut short, was pruned, or fails its close check. Repeat verification is much faster on large trails: a signed receipt lets the verifier skip re-checking signatures it already checked, and a new `--walk-timeout` flag bounds long walks. The signed `session_start` row now records the SHA-256 of the command that ran. On Linux, `wrap` refuses an interposer library that is unsafe to load. Older audit databases verify as before.

### Breaking

- Linux: `wrap` now refuses an interposer library with unsafe ownership or permissions, or one reached through a path inside the project. An install that worked before can be refused after upgrading. Run `nocklock doctor` to see which check fails.
- A project overlay that loosened a `--profile` fence through unusual key or table-name spelling no longer takes effect; the stricter profile value applies.

### Security

- Linux: before launch, `wrap` checks the ownership, permissions and symlink path of the interposer library and refuses one the project could control. Any path the trust check visits that lies inside the project (the library path, a parent directory, a symlink or a symlink target) rejects that library, so a file in the project cannot point `wrap` at a library of its choosing. The check follows at most 40 symlinks and has the same time-of-check window as the rest of the path walk. `nocklock doctor` reports an unsafe installation.

### Added

- Signed run close. At teardown, `wrap` writes a signed `session_close` row that binds the run's first and last row, its row count and a rolling hash over its rows. `nocklock verify --audit` reports each run as `closed`, `unclosed`, `pruned`, `close_mismatch`, `rows_after_close` or `legacy`. A mismatched close, or rows written after the close, always fail verification. An `unclosed` run fails only with the new `--require-closed` flag; otherwise the `COVERAGE: LIMITED` notice names it. A missing close cannot tell a crash from a deliberate cut, so it is never reported as tampering. Audit trails written before this release verify as `legacy`. The design is in `docs/design/run-lifecycle-contract.md`.
- Signed verification receipt. After a full verification, a key holder stores a signed receipt for the verified prefix of the chain. Later runs re-check that prefix byte for byte and verify signatures only for newer rows, which removes about 97% of the per-row cost on an unchanged prefix. Any change to the prefix, its signatures or the key discards the receipt and runs the full check with the same diagnostics. Output labels those prefix signatures as attested by the receipt, not verified in this run. A verifier with only the public key reads receipts but never writes them, and `prune` drops the receipt.
- `--walk-timeout` on `anchor emit`, `anchor push`, `verify --against-anchor`, `verify --audit` and `verify --against-remote-anchor`. It bounds only the local verification walk, separately from the 30-second lock and network budget. The default is `0` (no limit). An interrupted walk reports that the chain was not judged; it never reports the chain authentic or tampered, and it writes no anchor.
- Command fingerprint. The signed `session_start` row records the resolved path and SHA-256 of the command `wrap` runs, with a status (`hashed`, `unresolved`, `unreadable`, `not_regular` or `oversized`). Only regular files up to 256 MiB are hashed. The hash covers the command file only, not its interpreter, libraries or modules. The command is quoted in the signed row so its text cannot plant a fake hash field, and the hashed path is the path `wrap` runs. See `docs/how-it-works/audit-log.md`.

### Fixed

- Off-box anchor push no longer loses its time budget to its own preflight checks. Each step (identity read, preflight walks, fetch and push) gets its own budget, so a slow walk can no longer drop off-box delivery without notice.
- `anchor enroll` and `anchor migrate` no longer skip the local anchor write when the follow-up verification runs out of time. The follow-up fetch gets its own budget and the walk runs unbounded.
- `wrap` stops the network proxy before it writes `session_end`, so the close row is the run's last row. If the proxy takes longer than 5 seconds to drain, the run is left `unclosed` rather than risk a false `rows_after_close`. A failed `session_end` write now prints a warning that names the run. The child's exit code is unchanged.
- `verify --audit` applies `--walk-timeout` to the whole run check, uses less memory on large trails, and reads in one snapshot so a concurrent `prune` cannot make an honest run show `close_mismatch`. A run integrity failure prints an `AUDIT: RUN INTEGRITY FAILURE` line. The list of unclosed runs in the coverage notice is capped and sanitized.
- The network proxy watchdog no longer reports a failure after teardown has cancelled it.
- A project overlay can no longer loosen a `--profile` fence through unusual key or table-name spelling.
- Red-team bench: a `path=` rule matches the whole path or a path-component suffix, so a bare filename works and `xcanary.txt` no longer matches `canary.txt`. The kernel companion prints cleanup failures after an interrupt.

### Changed

- The repository no longer carries internal drafts, review instructions or personal identifiers in its probe records and design notes; probe verdicts remain with host, account and home paths redacted. CI now checks published content and fails closed on malformed input.
- New design notes: `docs/design/run-lifecycle-contract.md` and `docs/design/anchor-verification-profile.md`, with an env-gated profiling test.

## [0.10.0] - 2026-10-14

v0.10.0 gives each project its own remote audit chain: anchor v2 requires explicit `nocklock anchor enroll` or `anchor migrate` before remote push and verify, and prune and `anchor emit` now refuse unsafe states. It fixes two security issues: cloud metadata addresses in Linux netns bridge allocation, and current-directory lookup in `nocklock wrap`. Text output of audit and anchor verification now ends with a `COVERAGE: LIMITED` notice that states what recorded history does and does not prove.

### Breaking

- Remote anchor push/verify now require explicit v2 enrollment or migration and an upgraded store. They never fall back to key-only v1 routes. Legacy files remain explicitly verifiable; legacy local teardown emission remains v1 until enrollment.

- `anchor emit` requires existing signing adoption and the original key. It refuses unsigned or stripped databases instead of adopting/re-signing them. Normal wrap signing adoption is unchanged.

### Added

- Add per-chain remote v2 anchors with explicit `anchor enroll` / `anchor migrate`, durable exact-request retry, expected-pair verification, signed-prefix checks, conditional remote updates and actual NCC handler/CLI acceptance coverage (N11742–N11745). Independent projects may share one signing key. Trusted external identity and SQLite metadata must agree; pending/enrolled chains refuse prune and moved state requires explicit relocation and remote verification.

- Add trusted external chain identities and monotonic local registration state for v2 enrollment (N11744). Registration and prune share a process-safe lock; pending/enrolled or incomplete identity state refuses prune. The existing wrap path protects that directory independently of the configured DB and refuses unenforced filesystem access. Legacy chains still prune normally. The offline move procedure is documented and tested.

- Add opt-in v2 anchor record encoding, signature and expected-pair verification, snapshot digests, and public interoperability vectors (N11742). V2 signs an independent `chain_id` and legacy migration witness. This supplies the record-format foundation for the v2 lifecycle and remote commands described above.

- Sign a versioned Linux interposer report detail containing separate child report and collector-observed connection peer sections. Linux `SO_PEERCRED` identifies the connector; executable paths are best-effort procfs observations with explicit unavailable statuses. Capture runs before parsing in each connection's goroutine so it cannot stall the shared accept loop. The red-team bench matches legacy and version 1 report fields while preserving signed detail bytes. This does not identify each action's writer or prove an action occurred; existing audit signatures and enforcement/ACK behavior are unchanged (N11762).

### Security

- Exclude `169.254.169.0/24` and `169.254.170.0/24` from private Linux netns bridge allocation so common instance/container metadata endpoints cannot become bridge addresses. Exhaustive pure mapping tests cover all original slots; reservation and fail-closed proxy readiness remain unchanged (N11776).

- Resolve the requested command against the caller's PATH before adding Linux/macOS fence helpers, preserving arguments and refusing implicit current-directory lookup even with `GODEBUG=execerrdot=0`. Hosted bare-command and CWD-decoy controls cover Landlock/seccomp and composed netns launch (N11777).

### Changed

- Append `COVERAGE: LIMITED` to audit and local/remote anchor verification, including errors. The notice distinguishes verified recorded history from complete activity logging or past enforcement; verdicts, exit codes, protocol behavior and live-probe/JSON output remain unchanged (N11761).

- `nocklock wrap -- <cmd>` now resolves `<cmd>` on the caller's PATH and no longer runs an executable from the current directory. A command that relied on being found in the current directory must be given as an explicit path such as `./<cmd>` (N11777).

- Document the card-to-`next` and batched `next`-to-`main` review/release workflow, verified ruleset checks and the maintainers' exact-head review gate; run test and network-egress CI on pushes to `next` as well as `main`. Refresh the roadmap to v0.9.3 while retaining the unimplemented packaging and anchor-protocol limits (N11740).

### Documentation

- Fix signing-key recovery verification for absolute and project-local audit-log paths. Verify an isolated copy with the archived public key, preserving the live config, original archive and project provenance (N11739).

### Fixed

- Preserve original registration replay after interrupted writes: any retained request blocks prune, including state `none`. Strict anchor opens validate existing adoption, key fingerprint and signed head before database mutation and observe live WAL state. V2 file verification distinguishes a missing key from a forged signature; emit handles nil contexts and confirms written v2 files. The real NCC acceptance gate adds a same-head `already_stored` CLI case and scopes/redacts its receipts (N11745).

- Anchor v2 identity-lock waits now honor command cancellation and share the existing HTTP deadline. Wrap teardown starts its five-second budget before reading identity; interactive anchor commands and verification use 30 seconds. Durable filesystem writes remain synchronous rather than being abandoned on timeout (N11745).

- Harden trusted identity retries and pruning (N11744): every pending retry redoes file/directory durability barriers before registration; post-rename sync errors explicitly report a committed replacement with uncertain durability. Only trusted identity writes preflight the full state-root lineage before mutation; ordinary state resolution, reads and prune retain their no-fsync behavior. Post-rename barriers stop at the canonical state root, with a defensive filesystem-root stop. State directory and boundary come from one resolution. Prune requires project context after a database rollback and times out on the identity lock after five seconds. Filesystem-enabled wraps deny the future identity directory before enrollment, including custom DB locations and broad grant overlaps. Explicitly unfenced legacy behavior remains degraded; existing identities require enforcement.

- Concurrent first-time chain identity initialization now creates its persistent lock exclusively, then opens the winning inode. This avoids a macOS `os.Root.OpenFile` creation race while retaining anchored path, ownership and symlink checks.

### Testing

- Linux CI coverage for post-exec child credentials under scheduler stress, full installed netns wrap credentials, and test-only cross-thread exec/proxy-group mutation controls (N11747). The red-team companion records real Unix-socket and io_uring controls separately; older Landlock ABIs and unavailable io_uring remain explicit coverage gaps, with no change to the main bench score or runtime behavior.

- N11747 acceptance harnesses fail on every timeout, including earlier passing output; installed-wrap probes kill isolated process groups and bound output draining/reaping. Hanging-stub controls cover both harnesses. Hosted-only credential jobs check actual runner metadata, and a failed kernel companion stops the main bench and fails the job while preserving receipts.

- Tests: pin three disposable Landlock probes to their OS threads so Go cannot move their checks away from the restricted thread. Production already pinned its launch thread; runtime behavior is unchanged. CI repeats the probes under scheduler variation and deterministically proves that a separate existing thread remains unrestricted. Natural unpinned reproduction is an optional manual soak (N11773).

- CI: fail the scoped-sudoers artifact check when a blanket `NOPASSWD:ALL` grant is present or grep cannot read the file. Only grep's no-match exit code passes; the previous standalone negation could continue under Bash errexit (N11749).

### Upgrading from 0.9.3

Remote anchor push and verify (`nocklock anchor push`, `nocklock verify --against-remote-anchor`) need `nocklock anchor enroll` or `nocklock anchor migrate` first. There is no fallback to the v1 key-only routes. The anchor store at `NOCKLOCK_ANCHOR_URL` must be upgraded to v2 before enroll, migrate, push or verify will work.

Pruning (`nocklock log --prune`) refuses a chain whose registration is pending, enrolled, or left incomplete by an interrupted enroll (any retained registration request). To move that state to another machine or path, follow `docs/runbooks/chain-identity-move.md`.

`nocklock anchor emit` refuses an unsigned or stripped database. It needs existing signing adoption and the original key.

The text output of audit and anchor verification now ends with a `COVERAGE: LIMITED` block, including on errors. Verdicts and exit codes are unchanged; JSON and live-probe output are unchanged.

`nocklock wrap -- <cmd>` no longer finds an executable in the current directory. Use an explicit path such as `./<cmd>` where you relied on that.

`nocklock wrap` now protects the trusted audit-chain state directory before it starts the child, and refuses to start when it cannot. The refusals from the protection step (the first, second and last bullets below) are also written to the audit log as a blocked `file_blocked` row. What you may see and what to do:

- `trusted chain identity requires an enabled filesystem fence; refusing to start with a remote pin at risk`: the chain has a trusted identity but `[filesystem] root` is empty, so no filesystem fence is enabled. Set `filesystem.root` to enable the fence. Sessions with no trusted identity and no fence root still start unfenced.
- `trusted chain identity requires Linux Landlock enforcement; refusing to start with a remote pin at risk` (Linux): the chain has a trusted identity and `filesystem.linux_enforcement` is `off`. Remove the `off` setting (the default, `required`, is enough), or do not use a trusted chain identity in that session.
- `filesystem fence requires Linux Landlock, but this kernel does not support it` (Linux): the empty and `preferred` values of `filesystem.linux_enforcement` behave as `required`, so a kernel without Landlock refuses to start. Run on a kernel with Landlock, or set `linux_enforcement = "off"` if you accept an unenforced filesystem fence.
- `failed to build Landlock rules: deny path "<dir>" overlaps Landlock-granted tree "<tree>" and cannot be enforced by Landlock (allow-only); narrow the root/allow grant so it does not include the deny path` (Linux): a `filesystem.root` or `allow` grant contains the audit state directory. Narrow the grant so it does not include that directory.
- `cannot protect trusted chain identity; refusing to start: ...` and `cannot protect future trusted chain state; refusing to start: ...`: NockLock could not resolve the state directory; the wrapped error names the cause. Fix it and start again.

`file_blocked` audit rows from the filesystem fence now carry a versioned JSON detail envelope when the fence knows the connecting peer. The envelope has `version` (currently `1`), `report` (the fence report), and `connection_peer` (`credentials_status`, optional `credentials`, `executable`). Rows without peer information keep the old `op=<op> path=<path> reason=<reason>` text. A log parser that reads the `detail` field must accept both forms.

## [0.9.3] - 2026-10-14

### Documentation

- Document the current one-remote-anchor-identity-per-signing-key limit, its cross-project collision and workaround; specify a versioned per-chain identity and explicit legacy migration for the later protocol change (N11707).

### Security

- Linux netns proxy sidecars now clear supplementary groups process-wide before dropping to uid/gid 65534. Previously, `__netns-proxy` and `__netns-host-proxy` could retain the root launcher's supplementary groups on other Go threads. The affected source tags are v0.5.0 through v0.9.2.

### Fixed

- Tests: hold dead proxy ports open until health probes finish, preventing parallel tests from reusing those ports and receiving stray `/healthz` requests (N11729).

## [0.9.2] - 2026-10-13

v0.9.2 makes `doctor` check the signing-key directory, which changes some `doctor` verdicts and exit codes for the same machine; it also documents signing-key replacement and fixes a proxy shutdown race.

### Changed

- `nocklock doctor` verdicts change. `doctor` now checks the managed signing-key directory against the effective fence, so it can return `PARTIAL` (exit 3) or `GAPS FOUND` (exit 2) where v0.9.1 reported `PROTECTED` (exit 0). Exit codes are unchanged: 0 `PROTECTED`, 2 `GAPS FOUND`, 3 `PARTIAL`, 4 `UNPROTECTED` (`nocklock doctor --help`, `docs/reference/cli.md`). Automation that fails on any non-zero `doctor` exit may now fail where it passed. With Landlock disabled the signing-key boundary is advisory and the verdict cannot be `PROTECTED`.
- Docs: propose a signed Linux release tarball, explicit egress-helper installation,
  and clean-machine Linux/macOS acceptance in `docs/design/linux-packaging.md`
  (N11643), baseline v0.9.1 (`89c1bb6e`). Design only; no installer or release assets added.

### Documentation

- Align the public onboarding, contributor guide, CLI reference and roadmap with v0.9.0: select an agent preset before first launch, explain existing-config migration with `init --diff`, and document the Linux Unix-socket `PARTIAL` verdict and strict option. Correct proxy, audit coverage and empty secret-pass-list claims, link the docs index, and add a discoverable security-reporting policy.
- Document the current remote-anchor identity collision: projects sharing a signing key share one store identity, so off-box anchoring supports only one audit chain per identity until a versioned chain namespace exists.
- Add "Replacing the signing key" to `docs/how-it-works/audit-log.md`: what `wrap` and `verify` do after the managed key moves aside, how to archive the old log and public key so old rows still verify, and the limits (N11718).

### Fixed

- Serialize concurrent `ProxyServer.Stop` calls so shutdown and its proxy-stop audit event run once. The unsynchronized production method could race when two callers stopped the same proxy; the Linux netns proxy-death test exposed it under `-race`. The proxy shutdown code was present in v0.1.0 through v0.9.1. Every `ProxyServer` method that reads or writes the fields `Stop` clears (`Start`, `StartOn`, `StartUnix`, `Addr`) now takes the same lock; `MarkDegraded` touches only the atomic degraded flag and the never-reassigned transport (to close idle connections), none of the fields the stop lock guards, so it takes no lock and stays lock-free. No egress bypass was observed.
- `doctor` now checks the resolved managed signing-key directory against the effective Seatbelt deny set or Landlock grants, reports its path and posture in `doctor --json`, and cannot return `PROTECTED` when the key boundary is readable or unenforceable. `doctor` and `wrap` build the key-directory deny from one shared helper, so doctor adds no deny of its own, and a deny list that omits the resolved key directory is reported as a gap (N11717).
- `verify` works with a fresh macOS config: it no longer requires the Linux interposer, probes Seatbelt's outside-root write boundary, and explicitly skips the Linux-only syscall probe. Filesystem/network probe inputs now travel as private command arguments so the secret filter cannot strip them; the synthetic secret control is allowed without overriding block rules.

## [0.9.1] - 2026-10-13

### Security

- Protect the managed Ed25519 signing-key directory from fenced children even when `XDG_CONFIG_HOME` relocates it outside `~/.config`. Linux Landlock refuses an overlapping filesystem grant; macOS denies the canonical key directory and prevents renaming sensitive-path ancestors to move protected files outside their deny rules. Parent signing and normal project reads/writes remain available.
- Who is affected: anyone who sets `XDG_CONFIG_HOME` to a directory outside `~/.config`. On macOS v0.9.0, a fenced child could read the 32-byte signing seed while `doctor` reported `PROTECTED`. Every release since v0.5.0 (#90) carries the same key-path logic; only v0.9.0 was reproduced directly. On Linux, a relocated key was readable only when it sat under a granted tree, such as the project or `/tmp`. If a wrapped agent could have read the key, rows signed with that key no longer prove the agent did not write them. NockLock has no supported way to replace the signing key yet; a documented procedure is the next fix.
- Linux `--net-fence=netns`: the `__netns-child` process now keeps the capability drop, the supplementary-group drop, the NO_NEW_PRIVS latch and the exec of the agent on one OS thread. Before, Go could run those steps on different threads. CI saw the fail-closed form: `wrap` refused to start with `capability 12 remains`. The fail-open form, where the agent starts on a thread that still has CAP_NET_ADMIN in its bounding set and no NO_NEW_PRIVS, was not observed. The bounding-set gap matters only when nothing later in the chain sets NO_NEW_PRIVS: Landlock is off (`filesystem.root = ""` or `filesystem.linux_enforcement = "off"`) and `syscall.enforcement` is `"off"`, or `"preferred"` on a kernel without seccomp. With the default `__landlock-exec` shim, a setuid binary still cannot regain the capability. In any configuration, that thread could also have kept the root helper's supplementary groups. Every release with the netns egress helper is affected, v0.5.0 through v0.9.0.

## [0.9.0] - 2026-10-13

### Breaking

- Linux `CONFINED` below Landlock ABI 9 (every kernel we have tested): `nocklock doctor` now reports the Unix-socket boundary as unavailable and returns `PARTIAL` (exit 3) where v0.8.0 returned `PROTECTED` (exit 0). Automation that fails on any non-zero `doctor` exit will fail on these kernels. That is intended: Unix sockets are reachable there. Set `network.require_unix_socket_isolation = true` to make `wrap` refuse instead.

### Changed

- Red-team bench hardening (N11676): a verifier, version or process-group cleanup fault after scoring now fails the run (`no_harness_fault_after_scoring`); a nonzero NockGuard proxy exit at shutdown is a HARNESS-FAULT; the raw-socket and DNS attacks exit 42 when refused, so Python's own exit 1 (an uncaught exception) is a fault, not a block; datagrams already queued at the sink when an attack's deadline passes are counted before scoring. Test fixes: the interrupt test now requires the attack to have started, and the symlink-plant test checks the victim file while it still exists.
- Docs: `docs/` is now organized as a map for contributors and users: `docs/README.md`, `docs/REPO-MAP.md`, `docs/setup.md`, `docs/how-it-works/` (one page per fence or feature with its limits), `docs/reference/cli.md` (commands, exit codes and config schema as shipped, not yet a compatibility promise), `docs/runbooks/` (release, incident), `docs/decisions/` (records 006-014) and `docs/ROADMAP.md` (the path to 1.0). `CLAUDE.md` is rewritten as a short map and `AGENTS.md` points to it.

### Security

- Linux `CONFINED` egress below Landlock ABI 9: default non-strict `wrap` runs, warns once, and records a signed session-start row with `unix_sockets=reachable reason=landlock_abi_<n>_below_9`. `doctor` reports the Unix-socket boundary as unavailable and returns `PARTIAL` (exit 3); `status` includes the ABI reason. ABI 9 enforcement has not run on a real kernel yet.
- `network.require_unix_socket_isolation = true` makes `wrap` refuse when the Unix-socket boundary cannot be enforced. The removed `--allow-unix-sockets` flag is not supported.
- Record the pre-ABI-9 Linux `CONFINED` limitation: a non-root probe confirmed that a wrapped child can connect to both a throwaway pathname socket and a throwaway abstract socket while a direct AF_INET datagram socket syscall is denied. The design and probe are in `docs/design/unix-socket-reachability.md` and `docs/probes/n11650/`.
- Linux CONFINED io_uring regression test: bound probe subprocesses, kill their process groups on timeout, skip runners missing `linux/io_uring.h`, and distinguish setup ENOSYS from `IORING_OP_SOCKET` failure.

### Documentation

- Linux source-install docs now say where `libfence_fs.so` must be placed (`findTrustedLibFenceFS`, `internal/cli/wrap.go`); `verify --audit` exit codes per verdict, secret-preflight platform build tags, and the CONFINED socket-family override are documented from code (N11689).
- README: macOS denied-file logging now has one statement (best-effort `file_blocked` tailer); new "What the signed log proves" section on observation coverage (N11642).
- Follow-ups to the docs split (N11692): setup now builds as the user and installs the CLI with `sudo install`, never `sudo make install`, states when a legacy in-project `.nock/events.db` is agent-writable on Linux, README and ROADMAP share one Linux install story, `verify --audit` documents the local-key `AUTHENTIC` path, and `docs/reference/cli.md` and `docs/runbooks/release.md` match the code.

## [0.8.0] - 2026-10-13

### Breaking

- `nocklock doctor` no longer reports PROTECTED for a config with disabled or advisory boundaries. New verdicts PARTIAL (exit 3) and UNPROTECTED (exit 4); GAPS FOUND now exits 2 (was 1). Exit codes are now 0 PROTECTED, 2 GAPS FOUND, 3 PARTIAL, 4 UNPROTECTED. A project that used to read PROTECTED with fences off now exits non-zero (3 or 4); that is intended, and automation that fails on any non-zero exit will now fail for such configs. Scripts matching exit 1 must change to 2. A network fence whose egress is UNREACHABLE reports posture `unavailable` and the verdict is GAPS FOUND (exit 2), since wrap refuses to start. `doctor --json` gains `boundaries` and `egress_level`. A config with `filesystem.root = ""`, `network.allow_all = true`, empty secret patterns and `syscall.enforcement = "off"` is now UNPROTECTED instead of PROTECTED.
- `nocklock init` now exits non-zero when `.nock/config.toml` already exists; scripts that call `init` repeatedly should check for that file first. See Changed for `--diff`.

### Added

- Red-team bench, slice 1 (`bench/redteam/`): `attacks.toml` lists scripted attacks (off-allowlist HTTPS and HTTP egress, raw sockets, direct DNS, secret file and env reads, a write outside the fence root, and an MCP `tools/call` denied by a NockGuard policy through `nockguard proxy`). `run.sh` runs each inside `nocklock wrap`, runs `nocklock verify --audit` and `nockguard verify`, and writes `REPORT.md` and `report.json` pairing every attempt with the signed row that stopped it (event id, rule, chain hash). Two allowed actions are negative controls. New `redteam-bench` CI job installs NockGuard v0.5.0 from its release (sha256 pinned in the workflow) and uploads the report. Nothing the verifiers read is reachable from inside the fence, and the bench proves that before it runs: scratch lives under `$RUNNER_TEMP` (or `~/.cache/nocklock-bench`), never `/tmp`, and the driver stops with `SETUP-FAULT` if the canary, outside directory, audit state, NockGuard key, trail or policy lies under any grant. The two MCP rows run on the host (`host = true`), the MCP client driving `nockguard proxy` directly; the proof is NockGuard's signed policy deny, the fence adds nothing to it, and REPORT.md labels them "NockGuard (host)". Two attacks inside the fence (read the key, append to the trail) must be blocked and `nockguard verify` must still pass; the private seed is read only by the proxy and `verify` receives only the public key. Harness logs open with `O_NOFOLLOW`. An MCP call that reached the upstream is recorded as `UPSTREAM-EXECUTED` the moment the reply arrives, and a shutdown timeout afterwards is a separate `HARNESS-FAULT`, never `BLOCKED`. The driver always writes `REPORT.md` and `report.json` (a wrap that fails to launch is a FAIL row; a failed process-group cleanup is a `HARNESS-FAULT` that fails the run). Each attack runs in its own session with output sent to a file (no pipe) under one deadline; on expiry the process group is SIGKILLed, and a process that is still not reaped is recorded as `HARNESS-FAULT`. Only the exit codes an attack declares as `blocked_exit` count as a block; any other exit is a `HARNESS-FAULT`. `nockguard verify` gets the trail and public key by explicit flags (`--ed25519-pub-env`, `--audit`) under an empty HOME. The direct-DNS attack is scored by receipt: a host receiver on UDP 53 that logs nothing means blocked, whether or not the client got a reply. Two attempts (a direct TCP connect to a literal public IP on 443, a direct resolver query) are stopped by the kernel floor, which writes no per-attempt row today, so the report pins the session's signed fence-state row for them and labels them `blocked by kernel floor`. Each is also run once outside `nocklock wrap`; if that control does not reach, the attack is `INCONCLUSIVE`, not a pass.
- Docs: compare NFLOG, seccomp and Seatbelt denial evidence and propose bounded,
  signed Linux packet-drop observations in `docs/design/kernel-floor-denial-evidence.md`
  (N11634). Design only; no enforcement or audit behavior changed.

### Security

- Linux CONFINED: the syscall fence now denies `io_uring_setup`, `io_uring_enter` and `io_uring_register`. In v0.7.0 and earlier a fenced process could open and connect a socket through io_uring (`IORING_OP_SOCKET` / `IORING_OP_CONNECT`), which went around the socket-family filter. Upgrade. Regression test: `TestEnforce_IORingSocketConnectDenied`.

### Changed

- `nocklock status` says "configured" instead of "active": it reads config and does not track running wrap sessions.
- `nocklock init` exits non-zero when `.nock/config.toml` already exists instead of reporting success, and `nocklock init --runtime <name> --diff` prints the policy entries the preset would add or remove (no write; array elements print as `+ key += "v"` / `- key -= "v"`, other values as `key = value`), comparing the two configs key by key and `[[network.lookback]]` entries in order. The "config already exists" error no longer prints the Cobra usage. The macOS `claude` hint now points at `--diff`.
- `--ed25519-pub` accepts the `ed25519 <base64>` line that `verify --export-pubkey` prints, as well as bare base64 or hex.
- A legacy `[cloud]` section is reported as inert, naming `[audit.forward]`, the real delivery transport.
- Look-back race test: the POST target records how each request body ended and counts a bodyless request apart from a finished body; new `TestLookbackTripLeavesTargetBodyIncomplete` pins that a trip cuts Content-Length and chunked bodies. Test-only.

### Fixed

- Linux netns: the concurrent subnet test now checks atomic reservation claims instead of random, unreserved bridge candidates; two processes also contend for one subnet in a regression test.

### Known issues

- Linux CONFINED does not yet stop a fenced process from connecting to Unix sockets (pathname or abstract), so a reachable socket such as `docker.sock` is a way out; a fix is in progress.
- The Homebrew formula installs only the `nocklock` binary; on Linux the default config's `wrap` needs `libfence_fs.so` and refuses to start without it, and `make install` does not install it either, so build from source per the README until packaging lands.

### Upgrading from 0.7.x

Scripts that treat any non-zero `doctor` exit as failure now also see 3 (PARTIAL) and 4 (UNPROTECTED), and GAPS FOUND moves from exit 1 to 2. Scripts that call `init` repeatedly must check for `.nock/config.toml` first. `status` prints "configured" instead of "active".

## [0.7.0] - 2026-10-12

On macOS, the Seatbelt profile now acts as a kernel network floor: with the network fence active, outbound traffic can only reach the local proxy, and the signed egress level is the new `SEATBELT`. This release also adds look-back rules, slice 1 (Linux `CONFINED` egress only), and opt-in `[audit.forward]` delivery of fence decisions to Command's ops log. The `claude-code` preset also changes how it treats tokens in the secret fence (see Security below).

### Added

- `claude-code` preset (all platforms): passes `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) through the secret fence; the preset's `*_TOKEN*` block pattern is dropped because block outranks pass, and `pass` is an allowlist so other tokens stay blocked. On macOS, `wrap` prints a one-line hint when the wrapped command is `claude` and neither it nor `ANTHROPIC_API_KEY` reaches the child: it says whether the secret fence stripped a variable set in the parent (naming the preset fix, or removing the matching `secrets.block` pattern and adding the name to `secrets.pass`) or it is unset (run `claude setup-token`), and never prints a value. The keychain stays closed. The macOS Quick start now uses `nocklock init --runtime claude-code`. See README.
- macOS kernel network floor: with the network fence active, the Seatbelt profile denies `network-outbound` except TCP to `localhost:<proxy port>` (`remote tcp`; UDP to that port stays denied) and allows no Unix-socket connect, and denies Mach lookups of `com.apple.mDNSResponder` and `com.apple.mDNSResponderHelper` so `getaddrinfo` inside the fence fails instead of querying DNS (other resolver services are not claimed closed). The proxy listener is bound once and handed to the proxy (no reserve-close-rebind), `[::1]:<port>` is held or wrap refuses to start, and `doctor` reports SEATBELT only when `sandbox-exec` is usable. The signed egress level is the new `SEATBELT` (not `CONFINED`, which is Linux syscall-fence specific; look-back rules still require `CONFINED`). `--require-enforced-egress` now passes on macOS when the floor is engaged. A rejected profile or an unhealthy proxy refuses to start. `sandbox-exec` is deprecated by Apple and reads outside the root remain unconfined.
- Opt-in `[audit.forward]` delivery of committed file, network, and secret fence decisions to Command's ops log. Payloads carry the session ID and audit-chain entry hash; delivery failures leave local decisions and `events.db` unchanged.

- Look-back rules, slice 1: `[[network.lookback]]` with `on = "file_blocked"` and `then = "deny_egress"` (optional `within`). Once the filesystem interposer reports a denied open, the HTTP proxy denies every later CONNECT and plain-HTTP request and closes tunnels and requests already open, before the interposer's EACCES returns (250 ms ack bound). Denials are signed `network_blocked` rows citing `rule=lookback:<name> trigger=<id>`. Linux CONFINED egress only: `wrap` refuses to start at any other level. Design: `docs/design/look-back-rules.md`.
- Look-back rule names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, because the name is written into the signed denial row's detail. A committed trigger that reads back empty keeps egress denied for the rest of the session.
- `Logger.LogImmediate` and `Logger.LatestBlockedEvent`.

### Security

- `claude-code` preset (all platforms): the `*_TOKEN*` block pattern was removed so that `CLAUDE_CODE_OAUTH_TOKEN` can pass the secret fence. A variable whose name matches `*_TOKEN*` is no longer blocked by that pattern. The preset still blocks `*_SECRET*` and `*_PASSWORD*`. Tokens that are not in `secrets.pass` are still stripped, because `pass` is an allowlist (the test `TestClaudeCodePresetPassesOAuthToken` shows `GITHUB_TOKEN` stripped and `CLAUDE_CODE_OAUTH_TOKEN` passing). If you upgrade from v0.6.x: `nocklock init` copies the preset into `.nock/config.toml` and never overwrites an existing file. So a config made by an earlier `init` keeps the old lists: `CLAUDE_CODE_OAUTH_TOKEN` is blocked by `*_TOKEN*` and is missing from `secrets.pass`. To use the token, add `CLAUDE_CODE_OAUTH_TOKEN` to `secrets.pass` and remove `*_TOKEN*` from `secrets.block`. Removing the pattern lets every `*_TOKEN*` name listed in `secrets.pass` reach the child, so check that list first.
- CI: `claude.yml` now runs only when the triggering author is an `OWNER`,
  `MEMBER` or `COLLABORATOR`, checked per event type. `claude-code-review.yml`
  skips pull requests opened from forks instead of failing on missing secrets.

### Changed

- Windows probes (N10825/N11601): record the second desktop run (Probe 1 pivot PASS, Probe 2 needs no admin); `run-probe.ps1` runs python in the container by absolute path with a package-SID grant revoked at teardown. Probe 1 adds a literal-IP off-box packet step (`VERDICT(1-ip)`, scored on its own line: only curl exit 7 is BLOCKED, a timeout is INCONCLUSIVE), python is skipped with a SETUP-FAULT when only the Store alias exists, and the README gains a one-shot Scheduled Task recipe for SSH runs (`schtasks /Create` + `/Run` as `nlprobe-runner`, output redirected to `probe-<ts>.log`, stopped and polled before `/Delete`; independent of the SSH session; a one-line `nlprobe-run.cmd` launcher keeps `/TR` short, any old `output.txt` is renamed to `output-prev-<ts>.txt` before the run so completion means `output.txt` ends with a `RUN:` line, and the recipe states one operator, one run at a time), and `run-probe.ps1` fails loudly if a Probe 1 fault entry lacks its step-name prefix and records a SETUP-FAULT (skipping python) when the package-SID `icacls` grant fails.
- Docs: `docs/design/look-back-rules.md` design note for look-back policy rules over the audit event history. The valid `on` list is now the event types written with `blocked=1`, and the contention paragraph records that `Logger.Log` does not honour `busy_timeout`.
- Docs: the `.claude/diagrams` Mermaid diagrams now describe the shipped v0.6.1
  fences instead of the original "planned" design, and a new
  `network-egress.mermaid` shows the three egress levels.

### Fixed

- Tests: the audit-log prune fractional-cutoff test now passes outside UTC. Its
  negative control formatted the cutoff in local time; `Prune` was unaffected.

## [0.6.1] - 2026-10-01

Security patch release for macOS. In v0.6.0 the default config marked the
syscall fence `required` but enforced nothing at the syscall level on macOS.

### Breaking

- macOS: `nocklock wrap` now refuses to start when `syscall.enforcement` is
  `"required"` (including when unset) and `filesystem.root = ""`, because the
  Seatbelt profile that carries the syscall rules does not exist. Set
  `filesystem.root`, or set `syscall.enforcement = "off"` if the fence is
  intentionally disabled. With `"preferred"` and an empty root, wrap continues
  without the rules and `nocklock doctor` warns.

### Security

- macOS: `syscall.enforcement = "required"` (the `nocklock init` default) no
  longer starts silently without a syscall fence. On macOS the fence is the
  hardened Seatbelt rules, previously applied only with
  `filesystem.hardened = true`: deny `mach-priv-host-port`, `iokit-open` and
  `system-socket`, and limit writes under `/dev` to the common pseudo-devices.
  `nocklock wrap` now applies them whenever enforcement is `"required"` or
  `"preferred"`, announces `macOS syscall hardening ENGAGED`, and records a
  `syscall` audit event. v0.6.0 macOS users get these stricter defaults after
  upgrading; set `syscall.enforcement = "off"` to opt out. `"required"` with an
  empty `filesystem.root` has no Seatbelt profile to carry the rules, so wrap
  refuses to start (`REFUSED-TO-START`); set `filesystem.root` or
  `syscall.enforcement = "off"`.

### Fixed

- macOS: `nocklock doctor` no longer fails a fresh `nocklock init` config with
  `syscall [configured-but-backend-missing]`. Doctor and wrap now share one
  rule, so the default config passes `doctor` and is enforced by `wrap`.

## [0.6.0] - 2026-10-01

### Breaking

- Removed the macOS `filesystem.macos_allow_unfenced` escape hatch, as v0.5.0
  promised. `nocklock wrap` now always refuses to start (`REFUSED-TO-START`)
  when the macOS Seatbelt fence cannot be set up. A config setting
  `macos_allow_unfenced = true` now fails to load with "macos_allow_unfenced was
  removed in v0.6.0; NockLock now always refuses to start unfenced on macOS;
  restore sandbox-exec or remove the key". Configs with
  `macos_allow_unfenced = false` keep working, and new configs from
  `nocklock init` no longer write the key.
- Fresh projects now keep audit state outside the project in
  `$XDG_STATE_HOME/nocklock` (or `~/.local/state/nocklock`). As a result,
  NockLock refuses to start when a `filesystem.deny` path is inside
  `filesystem.root`; move the denied path outside the root. It also refuses to
  start when `filesystem.root` is `$HOME` or another ancestor of the audit
  state directory; narrow `filesystem.root` to the project. If more than one
  audit chain exists for a project, NockLock refuses to guess which chain to
  use.
- `nocklock wrap` now fails closed when `logging.db` resolves
  directly to the project root, because its SQLite sidecars and chain anchor
  cannot be protected there. Move the database, sidecars, and chain anchor
  together under `<root>/.nock/` with `[logging] db = ".nock/events.db"`, or
  use the state directory with `[logging] db = "events.db"`.
  Dry runs apply the same refusal without writing audit events. Audit path
  resolution errors fail closed; fresh audit directories remain supported.
  Dry runs also reject unusable state roots and conflicting chains. They may
  create missing trusted state directories, but never a database, signing key,
  or anchor.

### Added

- macOS: file accesses the Seatbelt fence denies are recorded as `file_blocked`
  rows (category `filesystem`, detail `<operation> <path>`) in the signed audit
  chain. The profile tags its file-deny rules with
  `(with message "nocklock:<session-id>")`, and a best-effort `log stream`
  tailer attributes unified-log denials to the session by that tag. Each
  operation and path is recorded once per session, at most 500 rows are
  written, and one row counts the repeats and overflow. Only records carrying
  kernel provenance (process id 0, `/kernel`, the Sandbox kext as sender image)
  are logged, so a fenced child cannot forge denial rows by logging under the
  `Sandbox` sender name. When the wrapped command ends, the tailer reads what
  the log process already wrote before reaping it, and one warning row says so
  if a stalled reader forces truncation. A
  tailer that cannot start or stops early writes one warning row and never
  affects the wrapped command. `status` and the docs describe macOS denial
  events as best-effort (the unified log can drop lines under load; Endpoint
  Security remains the complete-events path). (N11039)
- `wrap` reports and signs the effective network egress level (`KERNEL`,
  `CONFINED`, `ADVISORY`, `OFF`, or `UNREACHABLE`). Advisory proxy mode warns
  that clients ignoring `HTTP_PROXY` can reach any host. Set
  `network.require_enforced = true` or pass `--require-enforced-egress` to
  refuse sessions without enforced egress.
- Every `wrap` signs a `config.digest` row containing the canonical resolved
  policy and prior digest. Changed policy fields warn before the child starts;
  `verify --audit` reports the history and requires each retained post-adoption
  `session_start` to have its own preceding `config.digest` row.
- Linux `filesystem.allow_rw` entries grant explicit read-write access while
  existing `filesystem.allow` entries remain read-only. `nocklock verify` keeps
  its temporary probe files outside granted paths, including `/tmp`.
- Source builds now embed `git describe --tags --always --dirty` in
  `nocklock version`.

### Changed

- Anvil removed; NockLock is public and uses GitHub-hosted runners only; PR
  review is Gander.
- Failed anchor verification now names the anchored head and row count, and
  prints the recomputed local head at that count when available.
- Fresh Linux `nocklock init` configs allow system binaries, libraries, and selected
  configuration files to be read and executed without granting writes. Missing
  optional read paths no longer prevent a wrapped shell from starting. The
  default does not grant `/etc/environment` or `/etc/ssl/private/`.
- The Linux filesystem fence rejects configurations whose `allow_rw` entries
  push the shared allow cap or the combined wire budget over its limit.
- New projects keep their audit trail outside the project, so the fenced agent
  can finally use its own project root (N10749). Two requirements had been in
  direct conflict: the agent must be able to create and remove files directly in
  `filesystem.root`, and it must not be able to touch the log that records what
  it did. Landlock checks `MAKE_REG`/`MAKE_DIR`/`REMOVE_FILE`/`REMOVE_DIR`
  against the directory holding the entry, so `touch <root>/newfile` was denied
  even in read-write mode: the ruleset granted the root's existing children but
  never the root itself, precisely so `<root>/.nock` could be skipped. No ruleset
  resolves both — the kernel walks upward from the accessed file and allows as
  soon as an ancestor rule grants the access, so a narrower rule on `.nock`
  cannot revoke the root's grant, and stacking layers does not help because
  every layer would need `MAKE_REG` on the root. They collided only because the
  audit trail sat inside the writable root.
  - The event log, its SQLite sidecars, the chain anchor and the per-session
    egress decision logs live in `$XDG_STATE_HOME/nocklock/<project-key>/` (or
    `~/.local/state/nocklock/<project-key>/`). `<project-key>` is a SHA-256
    prefix of the project root's real path, so projects never share a chain.
    This matches where the Ed25519 signing key already lived.
  - Every directory NockLock creates there is 0700, and each one is checked —
    not just the last — for being a real directory, owned by the current user,
    and not group- or world-writable. A trusted directory reached through a
    writable parent is not trusted: whoever can write the parent can rename the
    leaf away and substitute their own. The configured state root itself is
    resolved once with `EvalSymlinks` and symlinks above it are allowed, because
    `/tmp`, `/var` and the macOS default `TMPDIR` are system links into
    `/private`.
  - With no home directory available — a container with no passwd entry for the
    uid, or `HOME` unset in CI — the state root falls back to a per-uid
    directory under `/var/tmp`. Deliberately not `/tmp`, which the shipped
    presets grant.
  - A relative `logging.db` — the default, and what every `nocklock init` config
    carries — resolves there, keeping only its filename.
- **An existing `<root>/.nock/events.db` is left exactly where it is** and keeps
  being used. NockLock will not relocate an audit chain: moving a live SQLite
  database, its WAL sidecars and its chain anchor is one operation that must
  either fully succeed or not start, and a half-finished move leaves a chain that
  still verifies while missing its most recent rows. While the log sits inside
  the fence root, the fence withholds the root grant and falls back to granting
  each existing child, so work inside existing subdirectories is unaffected but
  creates directly in the root stay denied. `nocklock wrap` says so on stderr
  and names the manual move that lifts it; `nocklock state migrate` will
  automate that in a later release. Two logs for one root is still refused
  rather than silently reconciled.
- `logging.db` now has one contract for absolute paths instead of two: a path
  outside both the project and the audit state directory is rejected when the
  config loads, with an error naming the setting. `logging.db` is a setting a
  repository can ship, so an unrestricted absolute path would let a hostile
  checkout aim a SQLite write at any path the invoking user can reach.
  Absolute paths below a symlinked audit state root are evaluated in both their
  raw and resolved spellings, and every supplied intermediate component is
  `Lstat`-checked before use. An error while inspecting the state root now also
  stops resolution rather than making the root look unavailable.
  `nocklock doctor` warns when an absolute path lands back inside
  `filesystem.root`, where the agent can reach its own audit trail, and when the
  audit state directory falls inside a `filesystem.allow` grant.
- Two consequences of granting the fence root on a project with no in-project
  audit trail, both deliberate:
  - `<root>/.nock/config.toml` is inside the root grant, so a fenced agent can
    edit the fence's own config. It cannot widen the fence it is already
    running under — the config is read by the unfenced parent before the child
    starts — so a rewrite takes effect only on the next `wrap`, and it is a
    tracked file, so the edit shows up in `git status`.
  - A `filesystem.deny` path INSIDE `filesystem.root` can no longer be enforced
    by Landlock, and rule generation is refused rather than shipping a fence
    that ignores the deny. Deny paths outside the root — including every entry
    in the shipped defaults and presets — are unaffected.
- `ResolveDBPath` now refuses to guess between two coexisting legacy audit
  chains inside a project: previously, if both the conventional
  `<root>/.nock/<name>` log and a hand-written relative `logging.db` path
  existed, the scan stopped at the first one it found and silently adopted it.
  It now collects every existing, deduplicated candidate and refuses to start,
  naming all of them, unless exactly one exists.
- A relative `logging.db` containing a separator (for example
  `../audit/events.db`) is now rejected at load if it would resolve outside
  the project root, instead of silently being joined to the project root and
  adopted as the authoritative legacy log wherever it landed.
- `ResolveDBPath` now canonicalizes every candidate (resolving symlinks on
  each one's existing parent) before de-duplicating them and before naming
  them in a refusal. The state-dir candidate previously was not canonicalized
  while the in-project candidates were, so on platforms where a temp root
  reaches its real location through a symlink, the same file could be named
  with a different spelling than the other candidates, or fail to collapse
  with one that reached it another way. The existence and symlink checks
  still run against each candidate's original, uncanonicalized path first —
  de-duplicating by canonical form before that check would let a symlink
  planted at one candidate hide behind another candidate's real file whenever
  the two happened to resolve to the same target.
- An absolute `logging.db` now joins the same candidate scan as the
  conventional `.nock` path, the hand-written relative path and the state-dir
  path, instead of being returned before any of them were even looked at. A
  legacy chain already sitting in the state dir is refused rather than
  silently abandoned when logging.db is reconfigured to an absolute path.
  An absolute path that resolves inside the audit state directory also passes
  the same state-root ownership and permission checks as a relative path to
  that directory, and every directory it nests deeper than `nocklock/<hash>`
  is held to the same 0700/owner/symlink rule, so a writable directory
  planted between the state directory and the log cannot be used. Those
  components are checked as the path spells them, so a symlinked one is
  refused by the same rule as `nocklock/<hash>` -- whether it points back
  inside the audit directory or out of it (N10830).
- The configured state root (`XDG_STATE_HOME`, or the `~/.local/state`
  fallback) is now itself checked before anything is created beneath it: it
  must be owned by the current user and not group- or world-writable, or
  `nocklock` refuses to start and names the path and the fix (`chmod` for a
  permissive mode, `chown` for a foreign owner — the message no longer
  suggests one for the other's problem). The `/var/tmp` per-uid fallback used
  when no home directory is available is unaffected — it is a shared system
  directory by design, and only the per-uid component NockLock creates under
  it is held to this rule.
- Linux userspace proxy mode now bridges syscall-fenced children to the
  allowlist proxy without granting IP sockets (N10753). When the syscall fence
  narrows proxy-mode children to Unix sockets, `wrap` serves the HTTP(S) proxy on
  a Unix domain socket and the LD_PRELOAD interposer rewrites only the configured
  loopback proxy connect to that socket; unexpected AF_INET/AF_INET6 connects
  fail closed. The probe and captured Node/undici output live under
  `docs/probes/n10753/`.

### Fixed

- Interposer field-budget cap is now enforced post-ABI-detection (#10815).
  The cap on allow/deny paths (matching libfence_fs.c's MAX_PATHS and field
  tokenizer budget) previously ran unconditionally in ProcessConfig with
  headroom reserved for the self-proc grants the __landlock-exec shim injects.
  A config with linux_enforcement="off", syscall.enforcement="off" (pure
  userspace interposer, no shim) was rejected at ~253 allow paths even though
  the shim's injections would never happen. The validation now runs in wrap.go
  after both the Landlock ABI probe and the syscall-fence decision, so headroom
  is only reserved when the shim actually engages. A userspace-only config gets
  the interposer's real 256-path budget. --dry-run and validateWrapRuntimeConfig
  still catch configs that exceed the interposer's absolute ceiling (>256 per
  category or >257 combined) via a floor check with reserve=0; the exact check
  with the real shim reserve runs later in wrap, after the ABI probe.

- claude-code preset: Node runtime introspection no longer breaks under the
  fence (#10757). With the broad `/proc/` grant removed in #115 (it exposed a
  same-UID sibling's `/proc/<pid>/environ`), `process.memoryUsage()` threw
  `EACCES` and `os.cpus()` silently returned an empty array — a throw can crash
  the agent and 0 CPUs mis-sizes worker pools. The narrow reads Node needs are
  now granted without any path to another process: the preset allows the
  system-wide `/proc/cpuinfo`, `/proc/stat` and `/proc/meminfo`, and the wrapped
  child's OWN `/proc/<pid>/{stat,status,statm}` — the three files, never the
  whole directory — is granted to both fences self-scoped. Because the
  `__landlock-exec` shim execve's the child in place (its pid IS the child's),
  the literal `/proc/self/{stat,status,statm}` Landlock rules bind to the
  child's own proc dir, and the shim appends the same concrete
  `/proc/<pid>/{stat,status,statm}` files to the interposer allowlist. Round 2
  (Gander): granting the whole `/proc/self` directory bound Landlock to the
  child's `/proc/<pid>` dir inode, and a descendant inherits that rule — so a
  grandchild could read the wrapped child's own `environ`/`cmdline`/`mem`, the
  sibling leak #115 removed reopened one level down. Narrowing to the three
  files closes it: a descendant that inherits the rule can read only those
  files' identical inodes, never `environ`/`cmdline`/`mem`/`maps`/`fd`, proven
  by a negative-control test where a grandchild is denied its wrapped parent's
  `environ`. A sibling's `/proc/<pid>/environ` and `/cmdline` stay denied at the
  kernel layer too, proven by a `CGO_ENABLED=0` raw-syscall reader test that
  bypasses the userspace interposer. The Go-side filesystem config now also
  reserves headroom below the interposer's combined allow+deny field budget
  (`libfence_fs.c`'s `char *fields[MAX_PATHS + 4]` — allow and deny paths
  share ONE 260-slot array, not independent 256-slot caps) for these injected
  self-proc grants, and fails closed with a clear config error instead of
  silently tripping the interposer's own cap — including the case where the
  interposer's tokenizer would otherwise drop trailing deny paths — at
  runtime. Verified empirically (LD_PRELOAD/strace diagnostic, no NockLock
  fence involved) that Node tolerates the narrower grant: startup also
  touches `/proc/self/{exe,maps,cgroup}`, but degrades gracefully when denied.
- Config discovery resolves the project directory before `wrap` and
  `verify --audit` derive audit state or signed config-digest paths, while
  preserving the `.nock/config.toml` leaf so projects sharing a symlink target
  retain separate audit state. Digest verification also keeps that association
  through teardown rows emitted after `session_end`, so an untampered wrapped
  session verifies successfully.
- `verify --audit` now treats sessions that started before the first
  `config.digest` row as legacy (and reports their count), while still
  rejecting a post-adoption session without a digest. The signed canonical
  policy now records the resolved network-fence mode, and each digest records
  its committed predecessor atomically.
- `verify --audit` treats setup events before `session_start` as covered by a
  pending config digest and accepts a missing first digest predecessor only
  when the signed chain records an authenticated prune boundary.
- `ResolveDBPath` now fails closed when the audit state root stats as an
  existing directory but cannot be resolved (`EvalSymlinks` erroring on a
  mid-call symlink swap or `ELOOP`), matching the sibling Stat-error branch
  added by PR #128: previously that case silently left the state root
  unavailable, dropping its candidates out of the scan and letting a legacy
  in-project chain be adopted while a real state-dir chain sat behind the
  unresolvable root (N10860).
- Concurrent logger opens now set SQLite's busy timeout before enabling WAL,
  avoiding lock failures during simultaneous first-time database setup.
- `ResolveDBPath` now resolves the audit state root once and carries that
  canonical path through its candidate scan and final directory setup, so a
  retargeted state-root symlink cannot make it inspect one audit location and
  return another.
- claude-code preset now runs real programs under the strongest non-root fence
  (N10748, parts b+c). Two field-reported breakages are closed: (1) writes to
  `/dev/null` and `/dev/tty` are permitted and `/dev/zero` is readable, so `git`
  and shells work — the Landlock ruleset (`baselineDeviceRules`) and the
  LD_PRELOAD interposer both grant these standard character devices as a
  baseline, independent of the allow list, since the fence otherwise grants a
  regular file read+execute only (the baseline also grants `/dev/urandom` and
  `/dev/random` readable, the entropy sources musl and older TLS stacks read
  directly). This baseline device set applies to **every** config, not only the
  claude-code preset — by design: any fenced program needs these nodes. (2) The
  preset's filesystem allow list now includes the standard system read paths
  (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, `/sys`), without which the
  child could not resolve its dynamic loader or exec `/bin/echo` — `/lib*`,
  `/bin` and `/sbin` cover non-usr-merged distros (musl/Alpine) where the loader
  lives outside `/usr`. An explicit `deny` of a baseline device still wins.
- claude-code preset no longer grants `/proc/` or `/dev/` as directory-wide read
  paths (N10748 round 2). `/proc/` let a wrapped child read every same-UID
  process's `/proc/<pid>/cmdline`, `stat`, `status` and `comm` — process
  enumeration and secrets passed on a command line (`--token=…`); `/dev/` made
  same-user pty slaves (`/dev/pts/N`) and `/dev/shm` readable, so a wrapped agent
  could read another terminal's input. Neither is needed as a Landlock read
  grant: node startup, `git status` and a pty-attached shell run without them
  (the workloads probed), and the specific device nodes the child does need are
  granted individually by `baselineDeviceNodes`. (Measured on the fleet
  host: with `/proc/` granted, a wrapped child read a sibling's `cmdline`, `stat`,
  `status` and `comm` but NOT its `environ` or `maps` — a split a path-based
  grant cannot produce, so the live secrets exposure was `cmdline` (argv), which
  the ptrace-gated `environ`/`maps` already blocked for an unrelated sibling. The
  removal closes the world-readable `/proc/<pid>` files and denies the child its
  own and its descendants' `environ` as well.) A child that genuinely needed its
  own `/proc/<pid>` could not be served by a `/proc/self/` allow entry — a
  Landlock rule on `/proc/self` binds the wrapper's pid dir at ruleset-build time,
  not the child's — so that would require a private pid namespace, not an allow
  entry. The network half of N10748 — letting the wrapped agent reach the
  allowlisted proxy while the syscall fence keeps direct-IP egress blocked — is
  tracked separately (N10753); no standard client speaks a unix-socket HTTP
  proxy, so it needs an interposer socket()/connect() translation that is a
  distinct design decision.

### Security

- macOS Seatbelt root-write confinement no longer grants the fenced child
  write access to NockLock's audit state directory. The unfenced parent alone
  writes the event database, SQLite sidecars, and chain anchor; a macOS
  enforcement test now proves child truncate and rename attempts are denied
  while a wrapped session still produces a verifiable audit chain.

### Documentation

- Accepted-limitation record for grandchild procfs reads (#10764, follow-up to
  #10757, ADR-005). A Node subprocess spawned by the wrapped Node agent (an MCP
  server or tool that execs under a new pid) still throws `EACCES` on
  `process.memoryUsage()`, because the `/proc/self/{stat,status,statm}` grants
  are Landlock inode-bound to the directly wrapped child's own files. Every path
  to reach grandchildren was assessed and rejected: a broad `/proc/` or
  directory-level grant re-opens the #115 `/proc/<pid>/environ` leak; a
  userspace interposer grant can never widen what the kernel Landlock policy
  denies (rulesets only intersect); and a per-process PID namespace + fresh
  `/proc` mount requires forking (abandoning the in-place `execve` that makes the
  #10757 grant correct), a `CLONE_NEWUSER` that hands the tree the
  namespaced-root surface `allow_namespaces=false` exists to deny, and the
  privileged-helper lifecycle of ADR-004. `os.cpus()` is unaffected tree-wide.
  `TestLandlockProcSelfAllowPathsStaysNarrow` pins the grant to one read-only
  `/proc/self/<file>` entry per curated file, and
  `TestSelfProcFilesExcludesSecretBearingEntries` keeps `environ`, `cmdline`,
  `mem`, `maps` and `fd` off that list, and `TestSelfProcFilesPinsExactSet`
  pins the list to exactly `stat`, `statm` and `status`, so this cannot be
  "fixed" by widening it.
- Windows feasibility study (`docs/design/windows-feasibility.md`) for running
  the fence in an AppContainer with an empty capability set and a single loopback
  exemption, without admin rights, with a desktop probe script
  (`docs/probes/n10825/run-probe.ps1`) and the output of its first run.
  NockLock still runs on Linux and macOS only.

### Testing

- A strict Linux claude-code preset regression proof checks that `ls .` and
  `os.listdir('.')` can read a fresh project's root while the relocated audit
  database and a path outside the allowlist (default-deny) remain inaccessible
  to the wrapped child.
- CI acceptance tests that run the three July-2026 DNS-based egress-escape tricks
  (from the Hugging Face sandbox-escape writeup) against NockLock's egress fence
  on both platforms (N10813). On Linux, `TestNetnsDNSEscape` drives the real netns
  tproxy floor and, from inside the namespace, attempts each trick: (T1) an
  in-process resolver override: a getaddrinfo-style connect to a disallowed IP
  carrying the allowlisted SNI, a raw-IP connect to that same disallowed IP with
  no SNI, and the child's own UDP+TCP/53 query to an off-namespace resolver;
  (T2) a `resolv.conf` rewrite to 8.8.8.8; and (T3) an `/etc/hosts` pin of the
  allowed name to a disallowed IP. The centerpiece (T1a) dials the attacker IP
  while presenting the allowlisted SNI and must still read back the **real
  allowed upstream's 200**, a race-free, synchronous receipt that the tproxy
  floor redirected by port and re-resolved the SNI itself, so the trick changed
  only what the child thought an address is, never where the proxy connected.
  The raw-IP no-SNI attempt's connection is terminated at the proxy (checked by
  the child), and the parent separately asserts the run's deny log carries a
  matching tls/empty-host receipt after the child exits; the direct
  off-namespace resolver query gets no answer (default-drop). The
  `resolv.conf`/`hosts` writes are **asserted** to fail closed: the test fails
  the run with a distinct exit code unless the write returns EACCES/EPERM/EROFS,
  and only then connects by the allowed NAME and requires it still lands on the
  allowed upstream. The test log carries a per-trick outcome line (e.g. "T1a:
  redirected to allowed upstream, 200 read", "T2/T3: write_denied (<errno>)") as
  evidence, not just `--- PASS`. On macOS,
  `TestWrapMacOSDNSEscapeRecordsProxyEnforcement` records the proxy-only model:
  it asserts a proxied disallowed host is denied and signed, the allowed host
  works and is signed, and `verify --audit` is clean, while logging that
  direct-IP egress and hosts-pinning are not kernel-blocked (macOS has no netns
  floor). Both run in new `network-egress.yml` jobs (the Linux job as root, the
  macOS job on a hosted runner), each emitting a per-trick verdict table to the
  step summary.
- CI runs the claude-code preset enforcement tests strict in a non-root Linux
  job, with `NOCKLOCK_AUDIT_REQUIRE=1` so missing prerequisites fail rather
  than skip. A raw-syscall read of a sibling's `/proc/<pid>/environ` must print
  `DENIED`, and the `cmdline` leak check catches a broadened `/proc` grant
  (N10755).
- CI fuzz smoke no longer fails spuriously under runner load (N10854). The
  three fuzz steps budgeted wall time (`-fuzztime=25s`), and Go's fuzz
  coordinator can surface its own timeout as `--- FAIL ... context deadline
  exceeded` with no crasher. The steps now budget an exec count
  (`-fuzztime=Nx`, per target, set below the fewest execs each target reached
  in 25s on CI), so a slow runner takes longer instead of failing; the job gets
  a 15-minute ceiling. Seed-corpus and newly found crashers still fail the job.
  `test.yml` also accepts `workflow_dispatch` for manual reruns.

---

## [0.5.0] - 2026-09-26

### Added

- Goose runtime preset: `nocklock init --runtime goose` scaffolds a default-deny
  config for Block's Goose agent (N8860, `23ad362`). Filesystem allows the three
  Goose XDG directories plus `/tmp` and denies `~/.ssh`, `~/.aws`, `~/.gnupg` and
  `~/.nock`; network is default-deny over Goose's core provider APIs; secrets pass
  the supported provider keys and `GOOSE_*` and block every other credential;
  syscall enforcement is required.
- `nocklock verify`: adversarial fence self-test that runs benign proof-of-block
  probes under the live wrap fence path.
- `nocklock doctor` now warns when a curated network allowlist is inert (#67). On Linux,
  when the network fence is active (`allow_all = false`) and the syscall fence is
  on, the child is restricted to unix-domain sockets, so the TCP proxy that
  enforces `network.allow` is unreachable and the posture collapses to no IP
  network: the allowlist reaches *none* of the configured domains, not a subset.
  This is the intended hardened no-network posture, but it silently defeats a user
  who curated `network.allow` expecting selective access, so doctor surfaces it
  with the fix (set `[syscall] enforcement = "off"` for a working, userspace
  boundary, or accept no-network by design).
- `nocklock egress-probe` (#70): a repeatable, structured feasibility probe for the
  Linux network-egress-enforcement track (Candidate B: netns + transparent
  redirect). It codifies the Phase 0 VPS probe runs so every fleet kernel, CI
  runners included, is measured the same way before Phase 1 locks the
  privileged-helper design. Non-mutating: it attempts unprivileged
  userns/userns+netns creation via throwaway `unshare` subprocesses (with the
  receipted flags verbatim), reads the classic and AppArmor userns sysctls,
  and detects `nft`/`nft_tproxy` and passwordless-sudo reachability, then emits
  a versioned JSON result (`--json`) with an `observed`/`indicated`/`not-probed`
  evidence field per check and a track verdict (`unprivileged-clean` /
  `privileged-helper` / `blocked` / `undetermined` on Linux, `unsupported` on
  non-Linux hosts). The root-only acceptance
  tests (Q6 post-drop mutation, protocol-matrix egress, AppArmor toggle) are
  enumerated follow-ups and are intentionally out of this increment. On the
  dev VPS the probe reproduces the receipted root-mapping denial and
  additionally records that bare unmapped userns+netns creation *succeeds*, a
  narrower blocker than the one-off 2026-08-03 run captured.
- `nocklock wrap --net-fence=netns` (Linux, opt-in; N9916): the Phase-1 FOUNDATION of
  the network-egress fence (Candidate B). A privileged helper, acquired via
  passwordless `sudo -n` under the DECIDED capability model (spec amendment
  2026-08-24), creates a fresh network namespace (`CLONE_NEWNET`), brings
  loopback up, installs a default-drop `nftables` base across ALL transports and
  both IPv4 and IPv6 (QUIC/UDP/SCTP/TCP all denied, no allowances yet), drops
  `CAP_NET_ADMIN`+`CAP_SYS_ADMIN` from all five capability sets (reusing the
  receipted Q6 cap-drop harness), drops to the invoking user, and execve's the
  agent as a non-root child inside the namespace. Fail-closed: if privilege
  cannot be acquired or the five-set drop cannot complete, NockLock refuses to
  exec, with no advisory/degraded fallback. Default `wrap` behavior is unchanged;
  the flag is Linux-only and refuses on other platforms. This is the
  kernel-enforced hardened (no-network) floor; the transparent HTTP(S)/DNS
  allowlist on top of it is a later increment (gated on Q7). A new root-gated
  acceptance test (`TestNetnsFoundation_DefaultDropDeniesEgress`) proves the
  capped child is denied all egress and runs beside the Q6 bar in the
  `network-egress` CI workflow.
- CI (#82): a `macos-enforce` job in `.github/workflows/test.yml` that runs the SBPL
  filesystem fence's runtime ENFORCEMENT proof on a GitHub-hosted `macos-latest`
  runner. It exercises the existing
  darwin-tagged `TestSeatbeltEnforcement_RealSandboxExec` and
  `TestSeatbeltDeniesWriteToFencedAuditLog` under real `sandbox-exec` (a fenced
  read/write is DENIED while an unfenced one SUCCEEDS), closing the final N9222
  acceptance gap: enforcement had never run in CI (the ubuntu job is
  generation-only, PR #80). The job runs beside, never before, the ubuntu
  `test` job, and runs on an ephemeral, isolated GitHub-hosted runner so fork PRs
  can execute code safely without trust gates. A new `NOCKLOCK_SANDBOX_REQUIRE=1`
  gate on the two tests (mirroring the netns suite's `NOCKLOCK_NETNS_REQUIRE`)
  turns their normally-green "sandbox-exec unavailable" skip into a hard failure
  under CI, so
  a runner that has lost `sandbox-exec` cannot silently re-open the gap.
- `nocklock wrap --net-fence=netns` now layers the Phase-1b working egress (N10399, #84)
  allowlist onto its kernel default-drop floor. A per-run link-local veth grants
  the namespace no default route and reaches only a host-side allowlist proxy;
  nftables `tproxy` intercepts child TCP/80 and TCP/443 into a separate,
  unprivileged transparent proxy that gates TLS SNI or HTTP Host before opening a
  CONNECT tunnel to that host proxy. The namespace also bind-mounts a fixed-answer
  DNS resolver that maps every A/AAAA name to the intercept address, keeping
  denied-domain decisions at the proxy while UDP/TCP queries to other resolvers,
  UDP/443 (QUIC), SCTP, and other raw egress remain default-dropped. Both policy
  proxies are health-checked by the helper, which terminates the fenced child on
  proxy death. A root-required CI protocol matrix now exercises the positive
  HTTP(S) paths, proxy denial paths, DNS stub and bypass attempts, denied
  transports, and curl/Node/Python TCP fallback clients.
- Tamper-evident audit log v1: a SHA-256 hash chain over every row of the SQLite
  event store (#89). `nocklock verify --audit` reports CONSISTENT or TAMPERED. A
  prune re-anchors the chain and is surfaced as a NOTE, never a silent
  CONSISTENT. Migration normalizes legacy timestamps to the canonical 9-digit
  form so query, prune and stats comparisons are uniform. The chain is unkeyed,
  so it does not resist a writer with file access; the verify output and README
  state that limit.
- Audit-log v1.1: Ed25519 signing over the hash chain (#90). Every row is signed
  over the same canonical bytes the chain already hashes, and the chain head is
  signed over domain-separated bytes, so an attacker who recomputes hashes in
  lockstep still needs the private key. The key is NockLock-managed, generated
  0600 on first use outside `events.db` (default
  `~/.config/nocklock/signing-ed25519.key`); a world- or group-readable,
  non-regular or symlinked key file is rejected, and an adopted log opened
  without its key refuses writes. `nocklock verify --audit` reports AUTHENTIC,
  CONSISTENT (unsigned or unchecked), FORGED, or SUSPECT (signed verification was
  required but every signature is gone). `nocklock verify --export-pubkey` prints
  the public key for out-of-band verification. Pre-adoption rows stay unsigned
  and signing goes forward.
- Per-host network egress allow and deny decisions made by the netns transparent
  proxy are now signed into the hash-chained audit trail with the host named
  (N10649, `7c5a818`). The proxy appends to a per-session decision log that the
  child is denied, and `wrap` streams it into the signed log, failing the
  session closed if a decision cannot be recorded or signed.
- Shipped egress-helper install path (#92): `scripts/install-egress-helper.sh` and
  `make install-egress-helper` install a root-owned shim and a
  `visudo`-validated, exactly-scoped NOPASSWD sudoers drop-in by atomic same-dir
  rename, and `nocklock doctor` gained an `egress-helper` check (Lstat, root
  ownership, no group/world write, passwordless-sudo reachability). A CI job
  installs via the shipped script and asserts the drop-in is exactly scoped
  (N10654).
- Audit-log v1.2: an external, Ed25519-signed chain-head anchor (#93). `nocklock
  anchor emit` writes it, `wrap` emits one on teardown, and `nocklock verify
  --against-anchor` authenticates the anchor and recomputes the cumulative
  hashes before trusting its counts. It detects tail truncation or rollback to an
  older legitimately signed snapshot, which the signed chain head alone reads as
  AUTHENTIC.
- Off-box anchor delivery (#95): `nocklock anchor push` sends an anchor to the
  store at `NOCKLOCK_ANCHOR_URL` (bearer token from `NOCKLOCK_ANCHOR_TOKEN`), and
  `nocklock verify --against-remote-anchor` checks the local chain against the
  latest anchor fetched back; an absent or unreachable anchor is reported as
  `anchor_unavailable` with a non-zero exit. The `wrap` teardown push is fail-open
  with a 5 second bound, and the anchor URL and token are stripped from the
  child's environment.
- `nocklock wrap` exports `NOCKLOCK_SESSION_ID` to the child (N10647, #96). The
  value is the session id recorded in `events.db`, so a co-located tool can stamp
  the same id; any inherited value is overwritten.
- `pkg/receipt` (N10647, #97): a public, read-only `VerifySession(dbPath, pub, sessionID)`
  that another module can import to verify one session's audit chain offline
  with only the Ed25519 public key. It opens the log read only (never creates,
  writes, or migrates it), walks the whole hash chain in id order because the
  link spans sessions, checks every session row's signature, and returns exactly
  one fail-closed verdict: `INTACT`, `TAMPERED`, `UNSIGNED`, `NO_ROWS`, or
  `UNVERIFIABLE`. A row with a valid signature and a forged `prev_hash` is
  `TAMPERED`. The chain primitives stay in `internal/logging` behind thin
  exported wrappers (`chain_export.go`), so there is one implementation.
- `pkg/receipt` tail evidence (N10647, #98): `VerifySession` now reads the signed chain head
  (the same reader `nocklock verify` uses, exported as
  `logging.ReadChainHead`) and reports `TailVerified` and `TailReason`. `INTACT`
  now requires a head that verifies under the key and anchors exactly the
  walked chain. A head whose row count or hash disagrees with the chain (rows
  deleted from the tail, or a stale head) or whose signature fails is
  `TAMPERED`, naming the anchored and found counts; a log with no signed head is
  the new non-success verdict `UNANCHORED`. A head rolled back together with its
  rows to an older genuine state still passes locally; only
  `nocklock verify --against-remote-anchor` closes that.
- Composed-default acceptance test (N10710, #100; `TestWrapComposedDefaultEgressAudit`, root/CI
  only) drives the full default stack, Landlock (required) + seccomp (required)
  + netns egress + signed audit, through `nocklock wrap` with a real child:
  one allowlisted fetch is permitted, one off-allowlist fetch is refused, both
  decisions land signed in the audit chain, and `nocklock verify --audit`
  confirms the chain and signatures. Runs in a new privileged Linux CI job
  (`netns-composed-default`). An unprivileged unit test
  (`TestEgressDecisionDirIsLandlockEnforceable`) pins the decision-dir fix and
  fails on the old `/tmp` path.
- Local `nocklock scan [path ...]` with `--env` and `--json`, bounded detection of
  AWS access-key IDs, GitHub token formats and private-key headers, and reports
  that contain locations rather than secret values. Optional `[secrets]`
  `scan_env` / `scan_paths` preflight prevents `wrap` from launching on findings,
  incomplete scans or audit-write failure. Existing configurations keep their
  behavior, and profile overlays cannot weaken enabled checks. The scanner walks
  through `os.Root` with `O_NOFOLLOW` opens and pins recursive descent to the
  enumerated parent directory handle, so a replaced intermediate directory cannot
  redirect the walk, and it rechecks inode and content before reading. Scan
  refusals are written to the audit chain. This is a prelaunch check, not runtime
  redaction or complete secret detection (#101, N10715).

### Changed

- The Anvil CI review now gates the shared Codex session behind a trust check
  (N8715, #59): the PR head must be a branch in this repository, not a fork, and
  the author must be OWNER, MEMBER or COLLABORATOR, so fork PRs and outside
  contributors can never provision the shared credential. Reviewer output is
  also redacted of any auth-file string before it is posted.
- CI (#65) now runs `go build`, `go vet`, a `gofmt` cleanliness check, and the full
  `go test ./...` suite on every push and pull request (`.github/workflows/test.yml`,
  GitHub-hosted `ubuntu-latest`). Until now no workflow ran the Go test suite, so
  the unit tests that guard the fence layers had never gated a merge.
- New `network-egress` CI workflow (#76; `.github/workflows/network-egress.yml`) for the
  Linux network-egress-enforcement track. It (1) runs the repeatable
  `nocklock egress-probe` on `ubuntu-latest`, bare image and nftables-provisioned,
  so the CI kernel's Q1 feasibility is measured identically to the dev VPS and kept
  as an uploaded receipt (the bare run's `track=blocked` reflects only that the
  runner image ships no `nft`, not a kernel that cannot host the fence); and (2)
  **actually executes the Q6 post-drop mutation acceptance test** as root with
  `NOCKLOCK_Q6_REQUIRE=1`. That test self-skips off the root path, so before this
  it had never run anywhere; Candidate B's bypass-resistance bar (a capped child
  cannot flush the `nftables`/routes/interfaces the fence depends on) is now a
  receipted CI gate, not a green skip.
- Added the TM symbol to the NockLock name and the Nock Technologies footer in the
  README (#83).
- Corrected the tamper-evident audit-log v1 specification to state the limits of
  an unkeyed, in-database hash chain and fully define its canonical byte layout.
- The CLI now compiles on darwin again (N10709, #99): the non-Linux `netns.EgressConfig` stub
  gained the `DecisionLogPath` field that `wrap.go` assigns cross-platform, which
  N10649 added only to the Linux struct (broke `GOOS=darwin go build ./...` at
  `wrap.go:413`). The darwin field is inert; its helper stub still refuses to
  run. CI now guards this: the ubuntu job cross-builds for darwin on every push,
  and the macOS job builds, vets and runs the non-root unit suite natively
  (seven darwin test-portability cases were skipped by name at that point; see
  the N10714 fix below).
- Default fence composition (`nocklock wrap --net-fence=netns` with Landlock and
  seccomp on) no longer fails to run for a project in a normal working directory
  (N10710, #100):
  - The per-session egress decision directory now lives under the audit state
    root (`<state>/.nock/sessions/<id>/egress`) instead of the system temp dir.
    The default filesystem preset GRANTs `/tmp`, and Landlock is allow-only, so
    the old `os.MkdirTemp("", …)` location put the directory in an
    always-granted tree; its child-deny then overlapped that grant and Landlock
    rule generation was rejected for EVERY default netns wrap, whatever the
    project's location. The new location is enforceable because
    `rootPathRules` skips the `.nock` child of the filesystem root, so the deny
    sits outside every granted tree. (A project physically under a granted
    ancestor, e.g. rooted inside `/tmp` or `~/.claude`, still hits the same
    grant/deny overlap for both this dir and the pre-existing audit-DB deny;
    that broader grant/deny reconciliation is out of scope here.)
  - `buildSyscallPolicy` now takes the active network-fence mode explicitly. In
    netns mode the child keeps its configured `inet`/`inet6` socket families
    (the kernel default-drop plus transparent proxy is the egress boundary);
    only the userspace-proxy mode still narrows the child to `unix` sockets.
    Previously any `allow_all=false` config forced `unix`-only, which blocked all
    IP egress under the netns fence even for allowlisted hosts.
  - `nocklock doctor`'s "network allowlist is inert under the syscall fence"
    warning no longer misreports the netns posture: it now names the
    `--net-fence=netns` escape (where the child keeps IP sockets and the kernel
    egress floor enforces the allowlist) instead of unconditionally advising
    `[syscall] enforcement = "off"`, which would have downgraded the fence.
- macOS filesystem fence (N9222 phase 1, #108): `nocklock wrap` on macOS now
  applies a kernel-enforced Seatbelt (`sandbox-exec`) profile inherited by every
  child. The initial profile was a built-in credential and sensitive-path DENYLIST
  (`~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/Library/Keychains`, plus
  configured deny paths) written as `(allow default)` with explicit denies. It was
  not the Linux root-only allowlist; `filesystem.root` write confinement was
  added in N10722 (see below) and ships in this release. The profile is
  generated fail-closed with canonicalized paths and validated with
  `sandbox-exec` before launch. Every wrap records
  exactly one durable filesystem-fence state before the child runs: `ENGAGED`
  (paths applied), `REFUSED-TO-START` (the default when the fence cannot be
  applied), or `DEGRADED` (only through the explicit, logged
  `filesystem.macos_allow_unfenced = true` escape hatch, which is temporary and
  removed in v0.6, or an explicit `filesystem.root = ""`). Per-file deny events
  are not emitted yet. Tests cover the three recorded states on darwin and run in
  the existing `macos-enforce` CI job.
- macOS filesystem-root documentation was made consistent across the product
  docs (N10712, #106), so every doc describes the same macOS `filesystem.root`
  behavior. As of this release that behavior is the Seatbelt write boundary in
  the N10722 entry below, and the 0.4.0 startup rejection of `filesystem.root`
  on macOS (N8186) no longer applies. The architecture document also now
  reflects the shipped network fence instead of describing it as planned.
- macOS `filesystem.root` now enforces a kernel Seatbelt write boundary (N10722):
  the canonical profile keeps `(allow default)`, denies all file writes, then
  allows only the configured root in read-write mode, `.nock`, the invoking
  user's required temp/cache locations, and required `/dev` pseudo-devices.
  Phase 1 credential and configured sensitive paths remain denied for reads and
  writes, including beneath the root. Read confinement outside the root is not
  claimed. This supersedes the denylist-only boundary described in the two macOS
  entries above.

### Fixed

- Documented the previously-undocumented `nocklock doctor` and `nocklock verify`
  commands in the README command table (#65).
- The audit logger no longer refuses to start on first run when the project is
  reached through a symlinked path (N10714, #102). `validatePath` resolved the project
  root's symlinks but left the not-yet-created DB path in its raw frame, so on
  macOS, where `/tmp` and `/var/folders` are `/private/*` symlinks, an in-root
  `.nock/events.db` was falsely reported as "resolves outside project root" and
  `wrap` failed closed on logger open. It now resolves the deepest existing
  ancestor of the DB directory and rejoins the missing tail, keeping both sides
  of the containment check in the same frame; the final DB component is still
  left unresolved so a symlink AT the DB path is caught by the `O_NOFOLLOW`
  guard. A symlinked *intermediate* ancestor escaping the root is now rejected
  even when the tail does not exist yet (previously admitted). An ancestor that
  is present but cannot be canonicalized, whether a dangling symlink (its target
  absent), a symlink loop, or a permission-blocked / non-directory component,
  now fails closed instead of degrading to the raw path frame, closing the
  TOCTOU window where a dangling symlink's target could be created between the
  check and the write. All are covered by negative-control tests.
- The macOS unit suite now runs in full on the `macos-enforce` CI job: the seven
  darwin test-portability failures are fixed and the `-skip` name list is
  removed (N10714, #102). The landlock rule-comparison tests normalise the temp root
  with `filepath.EvalSymlinks` (matching `RulesFromConfig`'s own
  canonicalization), the `wrap --dry-run` embedded-profile test accepts the
  configured macOS Seatbelt denylist per-platform, and
  `verifySkipReason` keys its Linux-only backend checks off the stubbable
  `caps.goos` instead of `runtime.GOOS` (a no-op in production) so verify's skip
  accounting is platform-deterministic under test.
- `verifyChain` now reports tampered, instead of an intact empty chain, when the
  `chain_head` row is missing but event rows remain (N10650, #103).
- `scripts/install-egress-helper.sh` now arms its cleanup trap before creating
  either temp file, so an interrupt or error between the two `mktemp` calls no
  longer leaks a temp file (N10655, #104). The INT and TERM handlers now terminate
  (`exit 130` / `exit 143`, which runs the EXIT trap once) instead of only
  cleaning up and returning: previously a signal delivered between `mktemp` and
  the `install` step removed the temp files and then let the privileged install
  continue, recreating the predictable path without `O_EXCL` (a symlink-plant /
  root-owned overwrite window for another local user). Pinned by a sandboxed
  signal-injection test with a negative control that reverts the handler.
- Audit DB validate-then-open window documented (N10717, #105): a same-uid writer that
  swaps a validated ancestor for a symlink can redirect the DB. That racer is out
  of NockLock's threat model; see ARCHITECTURE.md. Removed the redundant
  path-based `os.Chmod` (the descriptor-based chmod already covers it) and added
  `TestResidual_AncestorSwapBetweenValidateAndOpen` with a no-swap control.
- `nocklock wrap --net-fence=netns` no longer consumes the child's stdin
  (N10711, #107). The privileged `setup` request previously rode the helper's stdin, so
  the fenced child inherited a drained stream: `printf 'x' | nocklock wrap
  --net-fence=netns -- cat` printed nothing and interactive/MCP agents lost input
  entirely. The request now travels in a 0600 per-session file whose path rides
  argv (`setup --request-file <path>`; validated regular/0600/owned-by-`SUDO_UID`,
  opened `O_NOFOLLOW` and unlinked after read, both relative to a retained
  directory fd so a swapped parent directory cannot redirect the root unlink),
  and the sidecar payloads ride a dedicated inherited descriptor (fd 3), so the caller's real stdin, a TTY or a
  pipe, flows through to the child unchanged. This was forced by `sudo` closing
  descriptors ≥ 3 (`closefrom`), which rules out passing the request itself on an
  fd across the sudo boundary; see ADR-004. Fence semantics are unchanged; both
  the helper and sidecar legs fail closed if their setup channel is missing,
  covered by negative-control tests. **Host installers must update the NOPASSWD
  sudoers grant to `setup --request-file *`.**

### Testing

- SBPL generator acceptance coverage (N10058, #80): closed the residual test
  gaps named by the macOS-fence Phase-1a acceptance criteria against the already
  shipped generator (`sbpl.go`, #27/#38): a table-driven test asserting a config
  of N sensitive paths yields exactly N canonical `(subpath …)` deny rules; a
  preamble-ordering assertion (`(version 1)` first, `(allow default)` before the
  first `(deny …)`, never `(deny default)`); and a fail-CLOSED negative control
  proving an unresolvable path makes `GenerateProfile` error and emit no profile
  (never a silent unfenced drop). No production code changed.
- Fuzz coverage over the fence decision surface (#66): the project's first fuzz
  targets, seeded from the v0.4.0 known-bypass regressions, hunt the next bypass
  class continuously in CI (bounded `-fuzztime`, one target per package). The
  seed corpus also runs as normal regression cases under `go test` (no `-fuzz`):
  - `FuzzConfigLoad` (`internal/config`) fuzzes `Load` and `LoadOverlay` with
    arbitrary bytes. Asserts untrusted-config parsing never panics, a rejected
    config is returned nil (never a partially-populated, possibly permissive
    one), and, differentially against a restrictive profile base, that an
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
    a granted tree (N8441); the allow-only grant/deny decision fails closed.

### Dependencies

- `golang.org/x/sys` 0.46.0 to 0.48.0 (`477b9d1` #60, `1aea68a` #85)
- `modernc.org/sqlite` 1.53.0 to 1.59.0 (`9532c7c` #64, `54dc9de` #75, `5bc127c` #78, `30e9316` #94)

---

## [0.4.0] - 2026-07-09

Users on v0.3.0 should upgrade: this release closes ten bypass paths across
the Landlock, seccomp, LD_PRELOAD interposer, and audit-logging layers. The
two feature additions (runtime profile presets and `nocklock init --runtime`)
are also included.

### Security

- N8614: Audit-log symlink attack closed (#57): the log-path resolver
  previously validated only the parent directory, so a symlink at `.nock/events.db`
  pointed outside the project was followed, chmod'd, and written before fences engaged.
  Now: `lstat`-reject a symlink at the final path, open with `O_NOFOLLOW`, post-open
  re-validate via `f.Stat` + `os.SameFile`, and `chmod` by fd rather than path.
- N8537: Landlock root symlink escape closed (#56): root children are now
  resolved to canonical paths before Landlock rule emission; any child whose canonical
  target falls outside the configured root is rejected, preventing a project symlink
  from granting access to host paths outside the fence.
- N8441: Landlock deny/allow overlap fails closed (#53): a `deny` path that
  overlaps a Landlock-granted tree (root child or `allow` path) is rejected at startup
  with a clear error. Previously the deny rule was silently ignored; Landlock is
  allow-only at the kernel level and the LD_PRELOAD interposer cannot be relied upon
  for static binaries or children that clear `LD_PRELOAD`.
- N8431: Reachable Go stdlib CVEs closed (#52): bumped `go` directive
  1.26.1 to 1.26.4. Affected paths include the live network proxy and TLS stacks
  (GO-2026-5039 `net/textproto`, GO-2026-4976 `net/http/httputil`,
  GO-2026-4918 `net/http` ReverseProxy, GO-2026-4866/4870 `crypto/x509` + `crypto/tls`).
- N8332: seccomp x32 ABI bypass closed (#48): the BPF filter compared syscall
  numbers against the amd64 denylist and defaulted to `ALLOW`. Linux multiplexes the
  x32 ABI onto `AUDIT_ARCH_X86_64` by OR-ing `__X32_SYSCALL_BIT` (0x40000000) into
  the syscall number, so any denied call could be re-issued with the bit set and
  bypass the filter. The filter now denies any nr carrying `__X32_SYSCALL_BIT` on
  amd64 via `BPF_JSET` before any number comparison. Arm64 is unaffected.
- N8291: Metadata mutator fence bypass closed: `libfence_fs.c` mutator hooks
  did not guard null pathnames before `pathname[0]` dereferences and did not preserve
  `EBADF` for invalid-fd path resolution failures. A crafted `AT_EMPTY_PATH` call with
  a valid fd could slip through unrecorded. Now: null pathname guard, `EBADF` preserved,
  `AT_EMPTY_PATH` events reported with fd identifier, original arguments passed through
  after fence checks.
- N8186: Medium hardening (#46): seccomp enforcement mode now defaults to
  `required` when absent from config (was `preferred`); Linux `filesystem` `preferred`
  mode is treated as fail-closed at runtime; `filesystem.root` on macOS is rejected at
  startup (Seatbelt cannot enforce root-only isolation; a denylist is not a root
  sandbox); network-fenced runs with syscall enforcement active restrict `socket()` to
  `AF_UNIX` only so IP sockets cannot bypass the network proxy.
- N8185: Inherited `NOCKLOCK_FS_ALLOWED` stripped before fence append (#44):
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
  and `continue` are intentionally absent; their default egress cannot be pinned
  from first-party docs.

### Dependencies

- `golang.org/x/sys` 0.44.0 to 0.46.0 (#54)
- `modernc.org/sqlite` 1.52.0 to 1.53.0 (#49)

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

- `modernc.org/sqlite` 1.50.1 to 1.52.0 (#33)

---

## [0.2.0] - 2026-06-14

Users on v0.1.0 should upgrade: this release closes multiple bypass paths in the
filesystem, network, and audit-logging layers.

### Security

- CRITICAL: Network proxy fails closed on start or runtime failure (#9, #15):
  proxy bind and health check gate child startup; a watchdog goroutine monitors proxy
  health throughout the session and kills the child process group on unexpected proxy
  death. `--allow-unfenced` is rejected; NockLock fails closed when the network fence
  is unavailable.
- CRITICAL: Process group isolation (#9): wrapped child placed in its own process
  group (`Setpgid: true`); context cancellation sends `SIGKILL` to the entire group;
  Linux additionally sets `Pdeathsig: SIGKILL` so descendants cannot escape the fence
  by forking before the wrapper process exits.
- CRITICAL: stat-family TOCTOU closed (#9, #17, `43e558d`): all
  stat/lstat/fstatat/faccessat/readlinkat/`__xstat`/`__lxstat`/`__fxstatat`/statx hooks
  now pass the resolved canonical path to the real syscall, closing the symlink-swap
  race between `check_path` and the actual operation. Non-path fds (`AT_EMPTY_PATH`,
  procfs magic fds) bypass path resolution safely.
- CRITICAL: open/write-family TOCTOU closed (#32): all mutating/open hooks
  (open/openat, unlink, mkdir, rename, link, chmod, chown, truncate, symlink/symlinkat)
  pass the resolved canonical path to the real syscall. The symlink-swap window between
  the fence check and the kernel call is closed for the entire mutating surface.
- HIGH: DNS rebinding prevention (#9): `DNSCache` pins the first resolved IP set
  for each hostname; subsequent lookups return the cached result. Rebinding attempts are
  blocked and logged.
- HIGH: DNS cache key normalization (#9): hostnames are lowercased and trailing
  dots stripped before lookup and store so mixed-case variants share one pinned cache
  entry and cannot produce divergent IP sets.
- HIGH: Link-local / cloud-metadata blocked unconditionally (#28): `169.254.169.254`
  and all link-local unicast addresses remain blocked even when `--allow-private-ranges`
  is set. RFC-1918, loopback, and CGNAT ranges remain permittable for local development.
- Audit log fenced from fenced child (#31): the `.nock/` audit directory is injected
  into the filesystem fence deny list before fence activation, preventing a fenced agent
  from tampering with or deleting `events.db`. Applies to both the Linux LD_PRELOAD
  interposer and the macOS Seatbelt SBPL deny list.
- Fail closed when event log cannot open (#30): a session that cannot write the audit
  log does not start. Matches the network fence posture: unrecorded operation is treated
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
  enforced via `sandbox-exec`. Path canonicalization via `EvalSymlinks` is mandatory:
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

- `modernc.org/sqlite` 1.48.1 to 1.50.1 (#24)

---

## [0.1.0] - 2026-04-06

### Added
- CLI skeleton: `wrap`, `init`, `config`, `log`, `status`, `version` commands (PR #1, #2)
- TOML config parsing with strict validation (reject unknown keys)
- `nocklock init` creates `.nock/config.toml` with security-first defaults
- `nocklock wrap` passes through to child process (fences coming in PR #3-6)
- Cross-platform exit code handling (no Unix-only syscall dependencies)
- Makefile with build, test, lint targets
- Default config: deny `~/.ssh/`, `~/.aws/`, `~/.gnupg/`; block `AWS_*`, `*_SECRET*`, `*_TOKEN*`
