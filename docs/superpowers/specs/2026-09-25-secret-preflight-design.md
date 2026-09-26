# Secret preflight scanning

Kevin approved starting the promised-feature plan on September 25, 2026.
This first increment adds local detection and a prelaunch gate. It does not
rewrite reads, monitor agent context, or promise detection of arbitrary secrets.

## User contract

- `nocklock scan [path ...]` scans files/directories relative to the current
  directory; no paths means `.`. `--env` also checks the invoking environment.
  `--json` produces a machine-readable report. No config/account is required.
- Reports contain detector ID, file or environment location, and line number,
  never the matching value or source line. Locations are escaped on output.
- Exit zero requires a complete scan with no findings. Findings or incomplete
  scans exit nonzero. No implicit exclusions (including hidden files or binary
  files); select explicit subdirectories/files to narrow scope.
- Initial detectors recognize AWS access-key IDs, GitHub token formats and PEM
  private-key headers. These are indicators, not credential validity checks.
- Existing `[secrets]` name filtering remains unchanged. Add `scan_env = false`,
  `scan_paths = []`, and `scan_env_allow = []` (exact variable names exempted
  from value scanning only). Empty/absent settings preserve old behavior.
- `wrap` scans filtered child environment values when enabled and scans paths
  relative to the project containing `.nock/config.toml` (cwd for a profile
  without project config). Paths must stay within that root. Any finding or
  incomplete required scan prevents child execution. Record a metadata-only
  audit summary/findings; failure to record it also prevents execution.
- Profile overlays cannot disable scans, remove scan paths, or add environment
  exceptions. A secret block rule still wins over all pass/scan exceptions.
- Dry run reports configured scope but does not execute the scanner.

## Safety and bounds

Use the existing Go standard library and existing dependencies only. Read via
`os.Root`, refuse symlinks/special files, and open with no-follow/nonblocking
flags on Linux/macOS. Inspect every byte of regular files, including binary
data, up to 1 MiB/file and 32 MiB/run. Limit unique traversed paths plus
environment entries to 10,000, selected-path arguments to 10,000, and recursive
depth below each selected path to 64. Count each explicit path once. Descend
from already-open directory handles so a substituted pathname cannot redirect
child reads. Keep both inode-replacement and in-place-rewrite regressions.
Oversize/unreadable/changed inputs, traversal, unsupported platforms and
cancellation make the scan incomplete. Never silently truncate or skip.
Limits are fixed in this increment to keep the policy small and predictable.
Preflight is a point-in-time check: later changes, encoded/compressed values,
unrecognized formats and paths outside the selected scope are not covered.
Identity/metadata checks and bounded content rereads detect observed changes;
they are not an atomic snapshot and cannot rule out every concurrent write.

## Implementation sequence

1. Add the bounded scanner and detector/containment/error tests in
   `internal/fence/secrets/`.
2. Add backwards-compatible config fields, validation and restrictive overlay
   handling in `internal/config/`.
3. Add the standalone CLI and audited launch gate in `internal/cli/`; test
   clean launch, detected/incomplete refusal, metadata privacy, and audit errors.
4. Document actual behavior and run full checks. Build on existing PR #99's
   Darwin compile fix; do not duplicate or merge its work.

## Verification and boundaries

Use table-driven Go tests with synthetic credentials assembled at runtime.
Follow existing exported-comment and actionable-error conventions, and gofmt.
Commands: `go test ./... -v`, `go test -race ./internal/fence/secrets
./internal/config ./internal/cli`, `go vet ./...`, `go build ./cmd/nocklock`,
`go fmt ./...`, plus Linux cross-build/vet and installed-binary smoke checks.
Existing Darwin test failures must be reported separately from new failures.
Review paths, races, environment exceptions and diagnostics for leaks. No new
dependency, website publication, runtime redaction or fence weakening is in scope.
