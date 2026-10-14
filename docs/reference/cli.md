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
| `verify [--json]` | `--audit`, `--export-pubkey`, `--ed25519-pub <key>`, `--against-anchor <file>`, `--against-remote-anchor` (the last two are mutually exclusive) | `verify.go` |
| `scan [path ...]` | `--env`, `--json` | `scan.go` |
| `anchor emit [--out <file>]`, `anchor push [--file <file>]` | | `anchor.go` |
| `anchor enroll`, `anchor migrate` | enroll: `--acknowledge-no-legacy-history` | `anchor_v2.go` |
| `log` | `--session`, `--blocked`, `--since`, `--json`, `--stats`, `--prune <age>` | `log.go` |
| `status`, `version` | | `status.go`, `version.go` |
| `egress-probe [--json]` | Linux feasibility probe | `egress_probe.go` |
| `__landlock-exec`, `__netns-*`, `__probe` | Hidden internal re-exec entry points; not part of the interface | `landlock_exec.go`, `netns_helper.go`, `probe.go` |

`log --prune` keeps its legacy behavior for chains without a v2 identity, and
for an initialized identity in registration state `none`. A local trusted record
in `pending` or `enrolled`, a missing record with an existing DB identity, or
inconsistent identity metadata refuses prune before changing events. The error
names the remote-pin risk and the [offline state-move procedure](../runbooks/chain-identity-move.md).

### Remote anchor commands

`anchor enroll` explicitly creates a random trusted identity and a new remote v2 pin after checking the signed local chain and retained legacy history. `--acknowledge-no-legacy-history` confirms this project has no claim to a legacy pin belonging to another project. `anchor migrate` selects the owning local project, verifies the legacy prefix, and conditionally migrates its exact signed witness. Both require successful remote verification before reporting completion. Back up the DB, legacy anchor and trusted directory before migration. A retry uses the original request and mode; errors never clear pending.

`anchor emit` verifies an existing signed log and original key without adopting or re-signing its database. It emits v2 when trusted identity exists, otherwise a local v1 file. `verify --against-anchor` supports explicit v1 and v2 files; v2 requires local expected identity agreement. `anchor push [--file <file>]` accepts v2 only, requires enrollment, and validates both candidate and previous remote prefixes before compare-and-swap. An absent remote pin cannot be recreated by push.

`verify --against-remote-anchor` fetches only the trusted signed pair, authenticates it before any row-count verdict, and exits non-zero for missing/unreachable anchors, absent identity, unsupported v2 routes, malformed records or mismatches. Projects sharing a managed key have separate random chain IDs. No remote command falls back to v1; upgrade the store first. After v2 registration the store freezes ordinary v1 access, retaining legacy history for explicit migration.

The URL and bearer token come from `NOCKLOCK_ANCHOR_URL` / `NOCKLOCK_ANCHOR_TOKEN`; the token is never a flag/config key. Anchor commands and anchor verification share a 30-second budget for identity-lock waits and HTTP. Wrap teardown starts its five-second budget before the first identity read; failure warns and preserves the child exit code. Synchronous filesystem and SQLite work completes on the caller and is not interrupted by these deadlines. An unenrolled legacy chain writes a local v1 file and warns that explicit enrollment is required when a URL is configured. See [audit log](../how-it-works/audit-log.md) for routes, trust boundaries and retries.

## Exit codes
Exit codes travel as `exitCodeError` and `Execute()` calls `os.Exit` once (`root.go`). Any other error prints to stderr and exits `1` (`root.go`).

| Code | Meaning | Where |
|---|---|---|
| `0` | Success; for `wrap`, the child exited 0 | |
| `1` | A verification or validation failure: `verify` not blocked / not consistent (`verify.go`), `scan` finding or incomplete (`scan.go`), `validate` errors (`validate.go`), config-digest mismatch (`config_digest.go`), `__probe` escape (`probe.go`); any unhandled error | |
| `2` | `doctor` `GAPS FOUND`, including a missing or unparseable `.nock/config.toml` (`doctor.go`); `wrap` refused to start or lost its proxy: egress `UNREACHABLE`, look-back rule at the wrong level, `require_enforced` not met, a required fence unavailable, an unwritable audit decision, proxy failure (`wrap.go`) | |
| `3` / `4` | `doctor` `PARTIAL` / `UNPROTECTED` (`doctor.go`) | |
| child's code | `wrap` returns the child's exit code (`wrap.go`); a negative code (signal or abnormal exit) becomes `1` (`internal/cli/wrap.go`) | |

Caveat: a wrapped child exiting `1` or `2` can overlap CLI failure codes. The banner on stderr (`NockLock: fatal:`) and the `session_end` audit row (`exit_code=<n>`) disambiguate (`wrap.go`).

`doctor` checks the managed Ed25519 signing-key directory resolved from `XDG_CONFIG_HOME` (or `~/.config`) against the effective filesystem fence. On macOS it must be inside a Seatbelt deny path. On Linux with Landlock it must be outside every read grant; if a deny overlaps a grant (for example, a key under the project or `/tmp`), `wrap` refuses to start and `doctor` reports `GAPS FOUND` (exit 2). With Landlock disabled, the userspace-only signing-key boundary is `advisory`, so the verdict cannot be `PROTECTED`. `doctor --json` includes `signing_key.directory` and `signing_key.posture`; the `signing-key` check and boundary explain any gap.

## Config schema (`.nock/config.toml`)
Strict: unknown keys are a load error (`internal/config/config.go`). Structs at `internal/config/config.go`; defaults in `internal/config/defaults.go`; validation in `internal/config/validate.go`.

| Table | Keys |
|---|---|
| `[project]` | `name`, `root` |
| `[filesystem]` | `root`, `mode` (`read-write`, `read-only`), `linux_enforcement` (`required`, `preferred`, `off`), `allow`, `allow_rw`, `deny`, `hardened`; `macos_allow_unfenced` (only `false` loads) |
| `[network]` | `allow`, `allow_all`, `allow_private_ranges`, `require_enforced`, `require_unix_socket_isolation`, `[[network.lookback]]` (`name`, `on`, `within`, `then`) |
| `[syscall]` | `enforcement` (`required`, `preferred`, `off`), `allow_namespaces`, `socket_families`, `extra_deny` |
| `[secrets]` | `pass`, `block`, `scan_env`, `scan_paths`, `scan_env_allow` |
| `[logging]` | `db`, `level` |
| `[audit.forward]` | `enabled`, `url`, `api_key_env` (the operator environment must supply the matching URL and key; README "Forward fence decisions") |
| `[cloud]` | Legacy settings: `enabled`, `api_key`, `endpoint`. An enabled section without a key fails validation; with a key it is accepted but sends nothing. Use `[audit.forward]` for delivery |

`network.require_unix_socket_isolation = true` requires Linux `CONFINED` egress with Landlock ABI 9 or later; `wrap` refuses other modes or unavailable enforcement. Without it, `CONFINED` below ABI 9 warns, records Unix sockets as reachable, and `doctor` returns `PARTIAL` (exit 3). The ABI 9 enforcement branch has not yet run on a real kernel.

Runtime presets (`internal/config/presets/*.toml`) use the same schema. Profile overlays may only tighten a base profile (`wrap.go`).

## Environment variables read by NockLock
`NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN` (`internal/cli/anchor_push.go`), `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` (`internal/cli/wrap.go`, `internal/config/config.go`), `NOCKLOCK_EGRESS_USER` (installer, `scripts/install-egress-helper.sh`), `XDG_STATE_HOME` (audit state, `internal/config/state.go`), `XDG_CONFIG_HOME` (managed signing key, `internal/logging/signing.go`). The first four are stripped from the child.
