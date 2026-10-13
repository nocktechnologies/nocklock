# CLI, exit codes and config schema (current 0.8.0 behavior)

This page records what the code does at `origin/main` 89c02fa. It is **not yet a compatibility promise**. Making it one is the fourth bar for 1.0 (`docs/ROADMAP.md`); until then, anything here can change in a minor release with a `CHANGELOG.md` "Breaking" entry.

## Commands
Registered in `internal/cli/` (one file per command). `README.md` "Commands" has the user-facing table.

| Command | Flags | Source |
|---|---|---|
| `wrap [flags] -- <cmd> [args]` | `--profile <name>` (`list` lists presets), `--dry-run`, `--net-fence=netns`, `--require-enforced-egress`, `--allow-private-ranges`; `--allow-unfenced` is removed and errors | `wrap.go:36`, `flagparse.go:64-94` |
| `init [--runtime <name>]` | `--diff` with `--runtime` prints policy changes without writing; an existing config makes plain `init` fail | `init_cmd.go:16,233` |
| `validate [config-path]` | | `validate.go:12` |
| `config` | | `config.go:12` |
| `doctor [--json]` | | `doctor.go:36-59` |
| `verify [--json]` | `--audit`, `--export-pubkey`, `--ed25519-pub <key>`, `--against-anchor <file>`, `--against-remote-anchor` (the last two are mutually exclusive) | `verify.go:60,77,114-119` |
| `scan [path ...]` | `--env`, `--json` | `scan.go:23,49-50` |
| `anchor emit [--out <file>]`, `anchor push [--file <file>]` | | `anchor.go:22,36,55-57` |
| `log` | `--session`, `--blocked`, `--since`, `--json`, `--stats`, `--prune <age>` | `log.go:18,230-235` |
| `status`, `version` | | `status.go:16`, `version.go:11` |
| `egress-probe [--json]` | Linux feasibility probe | `egress_probe.go:172,200` |
| `__landlock-exec`, `__netns-*`, `__probe` | Hidden internal re-exec entry points; not part of the interface | `landlock_exec.go:41`, `netns_helper.go:52-142`, `probe.go:36` |

## Exit codes
Exit codes travel as `exitCodeError` and `Execute()` calls `os.Exit` once (`root.go:12-37`). Any other error prints to stderr and exits `1` (`root.go:36`).

| Code | Meaning | Where |
|---|---|---|
| `0` | Success; for `wrap`, the child exited 0 | |
| `1` | A verification or validation failure: `verify` not blocked / not consistent (`verify.go:106-107`, `:197`), `scan` finding or incomplete (`scan.go:44`), `validate` errors (`validate.go:34`), config-digest mismatch (`config_digest.go:347`), `__probe` escape (`probe.go:49`); any unhandled error | |
| `2` | `doctor` `GAPS FOUND` (`doctor.go:41-59`); `wrap` refused to start or lost its proxy: egress `UNREACHABLE`, look-back rule at the wrong level, `require_enforced` not met, a required fence unavailable, an unwritable audit decision (`:1029`), proxy failure (`wrap.go:587-610`, `:1037`) | |
| `3` / `4` | `doctor` `PARTIAL` / `UNPROTECTED` (`doctor.go:41-59`) | |
| child's code | `wrap` returns the child's exit code (`wrap.go:1039-1048`); a negative code (signal or abnormal exit) becomes `1` (`.claude/lessons/cross-platform-exit-codes.md`) | |

Caveat: a wrapped child exiting `1` or `2` can overlap CLI failure codes. The banner on stderr (`NockLock: fatal:`) and the `session_end` audit row (`exit_code=<n>`) disambiguate (`wrap.go:1028-1046`).

## Config schema (`.nock/config.toml`)
Strict: unknown keys are a load error (`internal/config/config.go:480-481`). Structs at `internal/config/config.go:271-396`; defaults in `internal/config/defaults.go`; validation in `internal/config/validate.go:29`.

| Table | Keys |
|---|---|
| `[project]` | `name`, `root` |
| `[filesystem]` | `root`, `mode` (`read-write`, `read-only`), `linux_enforcement` (`required`, `preferred`, `off`), `allow`, `allow_rw`, `deny`, `hardened`; `macos_allow_unfenced` (only `false` loads) |
| `[network]` | `allow`, `allow_all`, `allow_private_ranges`, `require_enforced`, `[[network.lookback]]` (`name`, `on`, `within`, `then`) |
| `[syscall]` | `enforcement` (`required`, `preferred`, `off`), `allow_namespaces`, `socket_families`, `extra_deny` |
| `[secrets]` | `pass`, `block`, `scan_env`, `scan_paths`, `scan_env_allow` |
| `[logging]` | `db`, `level` |
| `[audit.forward]` | `enabled`, `url`, `api_key_env` (the operator environment must supply the matching URL and key; README "Forward fence decisions") |
| `[cloud]` | `enabled`, `api_key`, `endpoint` |

Runtime presets (`internal/config/presets/*.toml`) use the same schema. Profile overlays may only tighten a base profile (`wrap.go:160-161`).

## Environment variables read by NockLock
`NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN` (`internal/cli/anchor_push.go`), `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` (`internal/cli/wrap.go`, `internal/config/config.go`), `NOCKLOCK_EGRESS_USER` (installer, `scripts/install-egress-helper.sh`), `XDG_STATE_HOME` (audit state, `internal/config/state.go`). All of the first four are stripped from the child.
