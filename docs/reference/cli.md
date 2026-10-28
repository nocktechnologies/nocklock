# CLI, exit codes and config schema

This page records current code behavior, starting from the `v0.9.0` baseline (`f2b0d04`) and including later changes listed in `CHANGELOG.md`. It is **not yet a compatibility promise**. Making it one is the fourth bar for 1.0 (`docs/ROADMAP.md`); until then, anything here can change in a minor release with a `CHANGELOG.md` "Breaking" entry.

## Commands
Registered in `internal/cli/` (one file per command). `README.md` "Commands" has the user-facing table.

| Command | Flags | Source |
|---|---|---|
| `wrap [flags] -- <cmd> [args]` | `--profile <name>` (`list` lists presets), `--dry-run`, `--net-fence=netns`, `--require-enforced-egress`, `--allow-private-ranges`; `--allow-unfenced` is removed and errors | `wrap.go`, `flagparse.go` |
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
| `__landlock-exec`, `__netns-*`, `__probe` | Hidden internal re-exec entry points; not part of the interface | `landlock_exec.go`, `netns_helper.go`, `probe.go` |

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
Exit codes travel as `exitCodeError` and `Execute()` calls `os.Exit` once (`root.go`). Any other error prints to stderr and exits `1` (`root.go`).

| Code | Meaning | Where |
|---|---|---|
| `0` | Success; for `wrap`, the child exited 0 | |
| `1` | A verification or validation failure: `verify` not blocked / not consistent (`verify.go`), `scan` finding or incomplete (`scan.go`), `validate` errors (`validate.go`), config-digest mismatch (`config_digest.go`), `__probe` escape (`probe.go`); any unhandled error | |
| `2` | `doctor` `GAPS FOUND`, including a missing or unparseable `.nock/config.toml` (`doctor.go`); `wrap` refused to start or lost its proxy: egress `UNREACHABLE`, look-back rule at the wrong level, `require_enforced` not met, a required fence unavailable, an unwritable audit decision, proxy failure (`wrap.go`); `wrap` could not write one of its own blocked-event rows (filesystem denials, macOS denial rows, network fence errors, each blocked network request including allowlist and look-back denials, DNS rebinding blocks and the row for a degraded network fence), the blocked-secret rows or `session_end` to the audit log, which overrides the child's exit code and stops the child if it is still running (`wrap.go`, `audit_recorder.go`); a denied request is still refused. Rows for allowed network requests stay best-effort by default; with `network.require_durable_audit = true`, a failed signed intent commit refuses the request and fails the run with exit 2 | |
| `3` / `4` | `doctor` `PARTIAL` / `UNPROTECTED` (`doctor.go`); a reachable [deputy](../how-it-works/deputies.md) the fence does not block also keeps `doctor` at `PARTIAL` (`doctor_deputies.go`) | |
| child's code | `wrap` returns the child's exit code when every blocked-event row and `session_end` were written (`wrap.go`); a negative code (signal or abnormal exit) becomes `1` (`internal/cli/wrap.go`) | |

Caveat: a wrapped child exiting `1` or `2` can overlap CLI failure codes. The banner on stderr (`NockLock: fatal:`) and the `session_end` audit row (`exit_code=<n>`) disambiguate (`wrap.go`).

`doctor` checks the managed Ed25519 signing-key directory resolved from `XDG_CONFIG_HOME` (or `~/.config`) against the effective filesystem fence. On macOS it must be inside a Seatbelt deny path. On Linux with Landlock it must be outside every read grant; if a deny overlaps a grant (for example, a key under the project or `/tmp`), `wrap` refuses to start and `doctor` reports `GAPS FOUND` (exit 2). With Landlock disabled, the userspace-only signing-key boundary is `advisory`, so the verdict cannot be `PROTECTED`. `doctor --json` includes `signing_key.directory` and `signing_key.posture`; the `signing-key` check and boundary explain any gap.

## Config schema (`.nock/config.toml`)
Strict: unknown keys are a load error (`internal/config/config.go`). Structs at `internal/config/config.go`; defaults in `internal/config/defaults.go`; validation in `internal/config/validate.go`.

| Table | Keys |
|---|---|
| `[project]` | `name`, `root`, `runtime` (preset-owned login store on macOS, exempt only when the wrapped command runs that agent or `--profile` selects it; otherwise all agent stores are denied) |
| `[filesystem]` | `root`, `mode` (`read-write`, `read-only`), `linux_enforcement` (`required`, `preferred`, `off`), `allow`, `allow_rw`, `deny`, `hardened`; `macos_allow_unfenced` (only `false` loads) |
| `[network]` | `allow`, `allow_all`, `allow_private_ranges`, `require_enforced`, `require_durable_audit` (default off; explicit proxy only), `require_unix_socket_isolation`, `[[network.lookback]]` (`name`, `on`, `within`, `then`) |
| `[syscall]` | `enforcement` (`required`, `preferred`, `off`), `allow_namespaces`, `socket_families`, `extra_deny` |
| `[secrets]` | `pass`, `block`, `scan_env`, `scan_paths`, `scan_env_allow` |
| `[logging]` | `db`, `level` |
| `[audit.forward]` | `enabled`, `url`, `api_key_env` (the operator environment must supply the matching URL and key; README "Forward fence decisions") |
| `[cloud]` | Legacy settings: `enabled`, `api_key`, `endpoint`. An enabled section without a key fails validation; with a key it is accepted but sends nothing. Use `[audit.forward]` for delivery |

`network.require_unix_socket_isolation = true` requires Linux `CONFINED` egress with Landlock ABI 9 or later; `wrap` refuses other modes or unavailable enforcement. Without it, `CONFINED` below ABI 9 warns, records Unix sockets as reachable, and `doctor` returns `PARTIAL` (exit 3). The ABI 9 enforcement branch has not yet run on a real kernel.

Runtime presets (`internal/config/presets/*.toml`) use the same schema. Profile overlays may only tighten a base profile (`wrap.go`).

## Environment variables read by NockLock
`NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN` (`internal/cli/anchor_push.go`), `NOCKLOCK_ANCHOR_CHECKPOINT_INTERVAL`, `NOCKLOCK_ANCHOR_CHECKPOINT_DEADLINE` (`internal/cli/anchor_checkpoint.go`), `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` (`internal/cli/wrap.go`, `internal/config/config.go`), `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG` (operator opt-in to accept a config in a directory other users can write; read from the environment only, never from the config file, and only a value of `1`, `true`, `yes` or `on` counts; `internal/config/config_trust.go`), `NOCKLOCK_EGRESS_USER` (installer, `scripts/install-egress-helper.sh`), `XDG_STATE_HOME` (audit state, `internal/config/state.go`), `XDG_CONFIG_HOME` (managed signing key, `internal/logging/signing.go`). The first six are stripped from the child.
