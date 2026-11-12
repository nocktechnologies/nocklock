# CLI, exit codes and config schema

This page records current code behavior, starting from the `v0.9.0` baseline (`f2b0d04`) and including later changes listed in `CHANGELOG.md`.

Contract tests in `internal/cli/contract_test.go` pin the command tree with each command's aliases and every cobra flag with its shorthand, type and default (`internal/cli/testdata/contract/commands.golden`), the tokens `wrap` accepts, every config key with its type (`internal/cli/testdata/contract/config-schema.golden`), the egress levels, the `verify --audit` run states, and the exit codes below for `doctor` and `Execute()`. For `wrap`, they pin exit `1` for no command, an unknown flag or a command not found; exit `2` when `--require-enforced-egress` is unmet or a `session_end` write fails; the child's code passed through; and a signal mapped to `1`. The other `wrap` refusal codes below are documented and held in review. The tests fail when a pinned surface changes or this page stops naming it. A deliberate change updates this page, then regenerates the golden files with `go test ./internal/cli -run TestCLIContract -update-contract-golden` and reviews the diff.

## Compatibility promise

Starting with 1.0, the public commands, command aliases, flags, defaults, config keys, egress levels, run states and exit codes documented on this page are the compatibility contract. Flag defaults are held by the contract tests; config-key defaults are the values in `internal/config/defaults.go` (noted on this page where a key's default matters) and are enforced in review.

Removing or changing a documented command, command alias, flag, default, config key, egress level, run state or exit code is breaking: add a `CHANGELOG.md` Breaking entry and, from 1.0, release a new major version. Adding one is not breaking: make an ordinary `CHANGELOG.md` entry, update this page, and update the contract goldens.

## Commands
Registered in `internal/cli/` (one file per command). `README.md` "Commands" has the user-facing table.

| Command | Flags | Source |
|---|---|---|
| `wrap [flags] -- <cmd> [args]` | `--profile <name>` or `--profile=<name>` (`list` lists presets), `--dry-run`, `--net-fence netns` or `--net-fence=netns` (`netns` is the only accepted value), `--require-enforced-egress`, `--allow-private-ranges`; `--allow-unfenced` is removed and errors. Any other token before `--` is an error. Without `--`, the arguments are NockLock flags only when every one is a recognized flag; otherwise they are all the child command | `wrap.go`, `flagparse.go` |
| `init [--runtime <name>]` | `--diff` with `--runtime` prints policy changes without writing; an existing config makes plain `init` fail | `init_cmd.go` |
| `validate [config-path]` | | `validate.go` |
| `config` | | `config.go` |
| `doctor [--json]` | | `doctor.go` |
| `verify [--json]` | `--audit`, `--export-pubkey`, `--ed25519-pub <key>`, `--against-anchor <file>`, `--against-remote-anchor` (the last two are mutually exclusive), `--require-closed`, `--walk-timeout <dur>`, `--export ocsf [--out <file>]` | `verify.go`, `verify_export.go` |
| `scan [path ...]` | `--env`, `--json` | `scan.go` |
| `anchor emit [--out <file>]`, `anchor push [--file <file>]` | `--walk-timeout <dur>` | `anchor.go` |
| `anchor enroll`, `anchor migrate` | enroll: `--acknowledge-no-legacy-history` | `anchor_v2.go` |
| `log` | `--session`, `--blocked`, `--since`, `--json`, `--stats`, `--prune <age>` | `log.go` |
| `status`, `version` | | `status.go`, `version.go` |
| `egress-probe [--json]` | Linux feasibility probe | `egress_probe.go` |
| `help [command]`, `completion bash\|zsh\|fish\|powershell` | Added by cobra; `completion` subcommands take `--no-descriptions` | cobra |
| `__landlock-exec`, `__netns-helper`, `__netns-proxy`, `__netns-host-proxy`, `__netns-child`, `__netns-cleanup`, `__netns-child-kill-watchdog`, `__probe` | Hidden internal re-exec entry points; not part of the interface, nor are their flags | `landlock_exec.go`, `netns_helper.go`, `probe.go` |

There are no global flags beyond cobra's `-h`/`--help`.

`log --prune` passes the project root resolved from its configuration. Library
callers must also supply an explicit project root; rootless prune is refused,
even for a legacy database.

On Linux and macOS, pruning remains available when neither a trusted identity
record nor a DB identity exists, or when both agree and registration is `none`,
provided no original registration request is retained, the external state directory can be resolved and validated and its
shared lock acquired. Prune refuses before deleting events if one identity copy
is missing while the other exists, registration is `pending` or `enrolled`,
an original registration request is retained (even in state `none`), identity metadata is corrupt or inconsistent, storage is unusable, or the lock
times out. Storage is unusable when its path cannot be accessed or created,
fails ownership/permission/symlink checks, lies inside the project, or is not
strictly below the configured state root. These storage and locking failures also refuse
legacy prune. Platforms without identity-lock support permit only legacy chains
with neither a trusted record, DB identity nor retained registration request.

Preserve incomplete or moved state and follow the
[offline state-move procedure](../runbooks/chain-identity-move.md).

### Audit export

`verify --export ocsf` runs the `verify --audit` checks, printing their report to stderr, and then writes the whole audit log as OCSF JSON events, one per line (JSONL), to stdout or to the `--out` file. It accepts `--ed25519-pub` and `--require-closed` with their `--audit` meaning, and `--walk-timeout` as the budget for each of its two chain walks (so up to twice the value in all), and cannot be combined with `--against-anchor`, `--against-remote-anchor`, `--json` or `--audit`. A failed verification (`TAMPERED`, `FORGED`, `SUSPECT`, a run integrity failure, or an unclosed run with `--require-closed`) exits `1` and writes nothing: no stdout, and no `--out` file, which appears only by rename once complete. The `--out` directory must exist. An `--out` path that names, after symlinks, the audit database, its `-wal`, `-shm` or `-journal` file, its `chain-anchor.json`, the managed signing key, or a trusted chain identity file (`chain-identity.json`, its lock, `anchor-registration.json`) is refused once the checks pass, against the database they read and before the export is read (exit `1`, the file untouched); names compare case-insensitively. The directory is opened once, before the checks, and the export is written and renamed into that opened directory, so changing a symlink in the `--out` path while the export runs cannot move where it lands. The rows are read in the same read transaction as a second chain verification, and the export is refused (exit `1`, nothing written) unless that chain ends at the same head the checks covered, so every exported row passed the run and config-digest checks; re-run it if a wrap appended rows in between. The export is built in memory before it is written, and refuses past 256 MiB (exit `1`, nothing written). If writing to stdout fails partway (a closed pipe), it prints `EXPORT: INCOMPLETE` and exits non-zero: discard what was received, which has no trailer. The mapping and the trailer are described in `docs/how-it-works/audit-log.md`.

### Remote anchor commands

`anchor enroll` explicitly creates a random trusted identity and a new remote v2 pin after checking the signed local chain and retained legacy history. `--acknowledge-no-legacy-history` confirms this project has no claim to a legacy pin belonging to another project. `anchor migrate` selects the owning local project, verifies the legacy prefix, and conditionally migrates its exact signed witness. Both require successful remote verification before reporting completion. Back up the DB, legacy anchor and trusted directory before migration. A retry uses the original request and mode; errors never clear pending.

`anchor emit` verifies an existing signed log and original key without adopting or re-signing its database. It emits v2 when trusted identity exists, otherwise a local v1 file. `verify --against-anchor` supports explicit v1 and v2 files; v2 requires local expected identity agreement. `anchor push [--file <file>]` accepts v2 only, requires enrollment, and validates both candidate and previous remote prefixes before compare-and-swap. An absent remote pin cannot be recreated by push.

`--walk-timeout <dur>` (on `anchor emit`, `anchor push`, `verify --against-anchor` (v1 and v2 files), `verify --audit` and `verify --against-remote-anchor`) bounds only the local chain-verification walk; its default is `0` (unbounded), so these commands complete on a large store, and a signed verification receipt keeps the walk short on an unchanged prefix (`docs/how-it-works/audit-log.md`). The identity-lock waits and network steps keep their own 30 s budget. Set a positive duration (e.g. `--walk-timeout=30s`) to cap the walk.

`verify --against-remote-anchor` fetches only the trusted signed pair, authenticates it before any row-count verdict, and exits non-zero for missing/unreachable anchors, absent identity, unsupported v2 routes, malformed records or mismatches. Projects sharing a managed key have separate random chain IDs. No remote command falls back to v1; upgrade the store first. After v2 registration the store freezes ordinary v1 access, retaining legacy history for explicit migration.

The URL and bearer token come from `NOCKLOCK_ANCHOR_URL` / `NOCKLOCK_ANCHOR_TOKEN`; the token is never a flag/config key. Anchor commands and anchor verification share a 30-second budget for identity-lock waits and HTTP. Wrap teardown starts its five-second budget before the first identity read; failure warns and preserves the child exit code. Synchronous filesystem and SQLite work completes on the caller and is not interrupted by these deadlines. An unenrolled legacy chain writes a local v1 file and warns that explicit enrollment is required when a URL is configured. Opt-in in-run checkpoints upload the committed head every `NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL` under a per-upload `NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE`; failures never fail the run, and teardown prints a summary line. See [audit log](../how-it-works/audit-log.md) for routes, trust boundaries and retries.

`verify --audit`, `verify --against-anchor` (v1 or v2 files), and
`verify --against-remote-anchor` append one `COVERAGE: LIMITED` notice to their
text output, including unsuccessful verification and early input or availability errors. It
states that verification checks recorded events, cannot prove every action was
logged, and does not establish past enforcement or recording coverage. Individual
allowed file accesses and some denied or bypassed actions can have no audit row;
see [audit recording limits](../how-it-works/audit-log.md#what-is-recorded).
The original verdict and exit code remain unchanged. This adds no aggregate grade,
host probe or audit JSON format; `--json` remains the live fence-probe format.
Public-key export and anchor enrollment/push output are unchanged.

`verify --audit` also reports each run's observed lifecycle over the intact chain
(`internal/logging/run_close.go`, design `docs/design/run-lifecycle-contract.md`),
on a `RUNS:` summary line plus a `RUN <id>:` line per integrity failure:

| Status | Meaning |
|---|---|
| `closed` | one signed `session_close`, recomputed row count and root equal the signed binding, no later row under the run's `session_id` |
| `unclosed` | the run's signed `session_start` owes a close (`lifecycle=1`) but none is present — a crash, kill, or failed close are indistinguishable; neutral |
| `pruned` | a recomputed value differs under a recorded prune, and the post-prune checks pass; neutral |
| `close_mismatch` | a recomputed value differs with no prune to explain it; a failure |
| `rows_after_close` | a row carries the run's `session_id` after its close, or a second close; a failure |
| `legacy` | a `session_start` with no `lifecycle=1` and no close, written before this contract; never a failure |

`close_mismatch` and `rows_after_close` fail verification (exit `1`) regardless of
`--require-closed`, and the run output then ends with an explicit
`AUDIT: RUN INTEGRITY FAILURE` verdict line — so the chain's own
`AUDIT: AUTHENTIC` line, printed earlier, is never mistaken for the overall
result. A neutral `unclosed` run fails only when `--require-closed` is set (then an
`AUDIT: UNCLOSED` line is printed); by default it passes but is named in the
`COVERAGE: LIMITED` notice, since a missing close cannot prove the run's recorded
extent is complete.

## Exit codes
Exit codes travel as `exitCodeError` and `Execute()` calls `os.Exit` once (`root.go`). Any other error prints to stderr and exits `1` (`root.go`). Before any command runs, `Execute()` acquires the installation lease; if a managed installation is unavailable (for example, a stale binary after an upgrade), every command prints `NockLock: installation unavailable:` and exits `2` (`root.go`, `install_lease_linux.go`).

| Code | Meaning | Where |
|---|---|---|
| `0` | Success; for `wrap`, the child exited 0 | |
| `1` | A verification or validation failure: `verify` not blocked / not consistent (`verify.go`), an anchor verification that does not pass (`verify.go`, `anchor_v2.go`), `scan` finding or incomplete (`scan.go`), `validate` errors (`validate.go`), config-digest mismatch (`config_digest.go`), `__probe` escape (`probe.go`); any other error, including flag and usage errors. For `wrap` this includes every startup refusal not listed under `2`: no command, an invalid or untrusted config, `--net-fence=netns` off Linux or with `network.allow_all = true`, an `[audit.forward]` mismatch with the operator environment, an audit database that cannot be resolved or opened, a failed config-digest write, a syscall or filesystem fence that cannot be enforced (Landlock missing, interposer or Seatbelt setup failure), an unprotectable signing key or trusted chain identity, and proxy socket setup errors (`wrap.go`). A child that cannot be resolved or launched after the run has started (command not found, the netns helper request cannot be built, the exec fails) also exits `1`, with `session_end` `exit_code=1` (`wrap.go`) | |
| `2` | `doctor` `GAPS FOUND`, including a missing or unparseable `.nock/config.toml` (`doctor.go`); the installation lease is unavailable (`root.go`); `wrap` refused to start for one of these reasons: signing unavailable (`refusing to run without signed audit`), `network.require_durable_audit` with `--net-fence=netns`, the blocked-environment rows or the effective egress level could not be written to the audit log, egress `UNREACHABLE`, `require_enforced` or `--require-enforced-egress` not met, a look-back rule at the wrong level, `require_unix_socket_isolation` not satisfiable, Landlock Unix-socket isolation could not be configured, the netns helper preflight failed, or the proxy failed to start or become healthy (`wrap.go`); `wrap` lost its proxy during the run or could not sign an egress decision (`wrap.go`); `wrap` could not write one of its own blocked-event rows (filesystem denials, macOS denial rows, network fence errors, each blocked network request including allowlist and look-back denials, DNS rebinding blocks and the row for a degraded network fence), the blocked-secret rows or `session_end` to the audit log, which overrides the child's exit code and stops the child if it is still running (`wrap.go`, `audit_recorder.go`); a denied request is still refused. Rows for allowed network requests stay best-effort by default; with `network.require_durable_audit = true`, a failed signed intent commit refuses the request and fails the run with exit 2 | |
| `3` / `4` | `doctor` `PARTIAL` / `UNPROTECTED` (`doctor.go`); a reachable [deputy](../how-it-works/deputies.md) the fence does not block also keeps `doctor` at `PARTIAL` (`doctor_deputies.go`) | |
| child's code | `wrap` returns the child's exit code when every blocked-event row and `session_end` were written (`wrap.go`); a negative code (signal or abnormal exit) becomes `1` (`internal/cli/wrap.go`) | |

### Child exit codes and NockLock failures overlap

`wrap` passes the child's exit code through unchanged, so a child exiting `1` or `2` cannot be told apart from a NockLock failure by the exit code alone; no exit code is reserved for NockLock. Scripts that must tell them apart read stderr and the audit log:

- A NockLock failure always writes a line to stderr: `Error: <reason>` (cobra) for exit-1 errors other than a child that could not be resolved or launched (the bare error, `root.go`) and for the two errors-joined refusals (durable audit with netns, signing unavailable), otherwise a line starting `NockLock: fatal:` or `NockLock: installation unavailable:`. NockLock writes none of these when it passes a child's code through, but the child shares stderr and can print the same text.
- Once a run has started, its `session_end` row records the verdict: `exit_code=<n>` alone for a child's own code or for a child that could not be resolved or launched (`exit_code=1`; `wrap` silences cobra here and `Execute()` prints the bare error to stderr, `root.go`), and `exit_code=2` with `decision_audit_failed=true`, `audit_write_failed=true` or `proxy_failed=true` when NockLock overrode it. The signed `session_close` row's `end=` field separates the launch cases: `end=refused` when the command could not be resolved or the netns helper request could not be built, `end=child_exit` for a child's own code and for an exec that failed (`wrap.go`, `internal/logging/run_close.go`), so an exec failure and a child exiting `1` differ only on stderr. If `session_end` itself cannot be written, `wrap` prints `NockLock: fatal: failed to record session_end` and exits `2`. A refusal before the run starts has no `session_end` row; some refusals write a blocked row first (`wrap.go`).

The 1.0 contract keeps this pass-through behavior and the existing `1` and `2` startup refusals. Moving every refusal to `2` would still collide with a child exiting `2` and would change existing scripts.

`doctor` checks the managed Ed25519 signing-key directory resolved from `XDG_CONFIG_HOME` (or `~/.config`) against the effective filesystem fence. On macOS it must be inside a Seatbelt deny path. On Linux with Landlock it must be outside every read grant; if a deny overlaps a grant (for example, a key under the project or `/tmp`), `wrap` refuses to start and `doctor` reports `GAPS FOUND` (exit 2). With Landlock disabled, the userspace-only signing-key boundary is `advisory`, so the verdict cannot be `PROTECTED`. `doctor --json` includes `signing_key.directory` and `signing_key.posture`; the `signing-key` check and boundary explain any gap.

## Egress levels
`wrap` reports one effective egress level in its banner, the signed audit log and `doctor` (`internal/cli/egress_level.go`, the only definition):

| Level | When | Meets `require_enforced` |
|---|---|---|
| `KERNEL` | Linux with `--net-fence=netns` | yes |
| `CONFINED` | Linux proxy mode with syscall enforcement and the filesystem interposer's proxy bridge | yes |
| `SEATBELT` | macOS with the Seatbelt network floor (`filesystem.root` set, `network.allow_all = false`) | yes |
| `ADVISORY` | Userspace proxy only; a client that ignores `HTTP_PROXY` reaches any host | no |
| `OFF` | `network.allow_all = true` | no |
| `UNREACHABLE` | Linux syscall enforcement without the interposer's proxy bridge; `wrap` refuses to start (exit `2`). `--net-fence=netns` off Linux would also be `UNREACHABLE`, but `wrap` refuses it earlier (exit `1`) | no |

`network.allow_all = true` gives `OFF` before any other rule applies.

## Config schema (`.nock/config.toml`)
Strict: unknown keys are a load error (`internal/config/config.go`). Structs at `internal/config/config.go`; defaults in `internal/config/defaults.go`; validation in `internal/config/validate.go`.

| Table | Keys |
|---|---|
| `[project]` | `name`, `root`, `runtime` (preset-owned login store on macOS, exempt only when the wrapped command runs that agent or `--profile` selects it; otherwise all agent stores are denied) |
| `[filesystem]` | `root`, `mode` (`read-write`, `read-only`), `linux_enforcement` (`required`, `preferred`, `off`), `allow`, `allow_rw`, `read_allow`, `deny`, `hardened`, `confine_home_reads` (default `false`, macOS only); `macos_allow_unfenced` (only `false` loads) |
| `[network]` | `allow`, `allow_all`, `allow_private_ranges`, `require_enforced`, `require_durable_audit` (default off; explicit proxy only), `require_unix_socket_isolation`, `[[network.lookback]]` (`name`, `on`, `within`, `then`) |
| `[syscall]` | `enforcement` (`required`, `preferred`, `off`), `allow_namespaces`, `socket_families`, `extra_deny` |
| `[secrets]` | `pass`, `block`, `scan_env`, `scan_paths`, `scan_env_allow` |
| `[logging]` | `db`, `level` (`info`, `debug`, `warn`, `error` or empty; `internal/config/validate.go`) |
| `[audit.forward]` | `enabled`, `url`, `api_key_env` (the operator environment must supply the matching URL and key; README "Forward fence decisions") |
| `[cloud]` | Legacy settings: `enabled`, `api_key`, `endpoint`. An enabled section without a key fails validation; with a key it is accepted but sends nothing. Use `[audit.forward]` for delivery |

`network.require_unix_socket_isolation = true` requires Linux `CONFINED` egress with Landlock ABI 9 or later; `wrap` refuses other modes or unavailable enforcement. Without it, `CONFINED` below ABI 9 warns, records Unix sockets as reachable, and `doctor` returns `PARTIAL` (exit 3). The ABI 9 enforcement branch has not yet run on a real kernel.

Runtime presets (`internal/config/presets/*.toml`) use the same schema. Profile overlays may only tighten a base profile (`wrap.go`).

On macOS, `confine_home_reads = true` denies file data reads beneath the invoking UID's passwd home, then permits reads beneath `filesystem.root`, `filesystem.allow`, `filesystem.allow_rw`, the explicit `read_allow` paths, and the developer-tool cache folders listed below, plus a literal grant for the user's `.gitconfig` file. An existing `.gitconfig` that resolves to a directory refuses startup. Metadata operations such as `stat` remain allowed. Sensitive paths remain denied for reads and writes even inside an allowed path. The home and every emitted path must resolve before launch; `filesystem.root` must be set. This opt-in covers only the passwd home: `/Users/Shared`, `/Volumes`, `/tmp`, and other locations outside it remain outside the read boundary. `read_allow` adds no read grant on Linux or when the opt-in is off, but its entries are still validated. `doctor` and the signed macOS filesystem fence-state row show the mode; `verify --audit` authenticates that row as part of the chain.

Under `confine_home_reads`, only the listed developer-tool cache folders are readable; add others with `read_allow`: `go-build`, `pip`, `pnpm`, `Yarn`, `node-gyp`, `ms-playwright`, `deno`, `typescript`, and `Homebrew` beneath the user cache directory. The user cache directory's write grant remains unchanged.

## Environment variables read by NockLock
`NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN` (`internal/cli/anchor_push.go`), `NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL`, `NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE` (`internal/cli/anchor_checkpoint.go`), `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` (`internal/cli/wrap.go`, `internal/config/config.go`), `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG` (operator opt-in to accept a config in a directory other users can write; read from the environment only, never from the config file, and only a value of `1`, `true`, `yes` or `on` counts; `internal/config/config_trust.go`), `NOCKLOCK_EGRESS_USER` (installer, `scripts/install-egress-helper.sh`), `XDG_STATE_HOME` (audit state, `internal/config/state.go`), `XDG_CONFIG_HOME` (managed signing key, `internal/logging/signing.go`), `XDG_RUNTIME_DIR` (Linux proxy socket directory and `doctor` deputy socket search, `internal/cli/wrap.go`, `internal/cli/doctor_deputies.go`), `SUDO_UID` (the invoking user, read by the root netns helper, `internal/fence/network/netns/helper_linux.go`). The first six are stripped from the child. Other `NOCKLOCK_*` variables pass state between NockLock and its own hidden re-exec entry points or test fixtures; they are not part of the interface.
