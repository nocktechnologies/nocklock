# Secret preflight scan

Citations name source files at `origin/main` 89c02fa (no line numbers, so they do not go stale). Full detail and bounds: `README.md` "Secret preflight scanning"; design: `docs/superpowers/specs/2026-09-25-secret-preflight-design.md`.

## What it does
`nocklock scan [path ...] [--env] [--json]` checks selected files, and with `--env` the invoking environment, for credential-shaped values before an agent sees them (`internal/cli/scan.go`, scanner `internal/fence/secrets/scan.go`). Exit 0 only when the scan completes with no findings; otherwise 1 (`scan.go`). Reports show detector IDs and locations, never values.

To require it on every launch, set `secrets.scan_env`, `scan_paths` and optional `scan_env_allow` (`internal/config/config.go`). A required scan that finds something, or is incomplete, prevents the child from starting and is recorded in the audit log; failing to record also prevents launch. Profile overlays can add scan paths but cannot disable a base scan.

## Honest limits
- Format checks only: AWS access-key IDs, GitHub token formats, PEM private-key headers. A match does not mean the credential is valid; encoded or compressed secrets go undetected.
- Point-in-time. It does not redact reads, watch agent context, or stop files changing after the scan.
- Bounded (1 MiB per file or value, 32 MiB total, 10,000 entries, 64 levels). Exceeding a bound, a symlink, an unreadable path or a detected concurrent change makes the scan *incomplete*, which is a failure, not a skip.
- No implicit exclusions: hidden and binary files are scanned and ignore files are not read.
- Safe opens are Linux and macOS (`scan_open_unix.go`, `scan_open_other.go`).

## Tests
`internal/fence/secrets/scan_test.go`, `scan_unix_test.go`, `internal/cli/scan_test.go`, `internal/config/scan_test.go`.
