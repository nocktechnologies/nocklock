# Roadmap to 1.0

Status at `origin/main` 89c02fa (v0.8.0). Kevin approved the four 1.0 bars (Telegram 33132, Nock #11662). This page tracks the code and tests that must support each claim.

## The 1.0 bar

| # | Bar | Current evidence and remaining work |
|---|---|---|
| 1 | Close the Linux `CONFINED` Unix-socket and `io_uring` gaps, with red-team coverage | `io_uring_setup`, `io_uring_enter` and `io_uring_register` are denied in `internal/fence/syscallfence/denylist.go:93-96` (N11655, v0.8.0); `TestEnforce_IORingSocketConnectDenied` covers the path. Unix-socket reach remains open: `docs/design/unix-socket-reachability.md` and `docs/probes/n11650/` show accessible pathname and abstract sockets can be reached. N11660 / PR #174 is open. `bench/redteam/attacks.toml` and `.github/workflows/network-egress.yml` provide the first CI bench slice, but it has no Unix-socket or `io_uring` attack yet. Add both with allowed-action negative controls before closing this bar. |
| 2 | Ship honest `doctor` verdicts | Shipped in v0.8.0 (#168). `internal/cli/doctor.go:36-59` maps `PROTECTED`/`GAPS FOUND`/`PARTIAL`/`UNPROTECTED` to exits 0/2/3/4; tests are beside it in `internal/cli/doctor_test.go`. Keep `docs/how-it-works/doctor-and-verify.md` and the README aligned with that contract. |
| 3 | Complete the Linux install | Open. Source installation still needs `make install` and a separate privileged `make install-egress-helper` (`Makefile:28-38`, `docs/setup.md`). The signed packaging and OS acceptance design is PR #172; implementation and clean-host verification have not landed. |
| 4 | Write down the CLI, config schema and exit codes as the contract to keep | `docs/reference/cli.md` records current behavior, including the v0.8.0 doctor exits. Before 1.0, audit every public command, flag and config key against `internal/cli/` and `internal/config/`, resolve the child-exit overlap with CLI errors, and pin the chosen contract in tests. The page is a snapshot until that review is complete. |

A gap is closed only when its fix is on `main`, the red-team case runs in CI with an allowed-action negative control, and the documentation describes the tested boundary. In particular, `CONFINED` must not claim Unix-socket isolation while N11660 remains open.

## Release path

- **0.7.1 (planned, skipped):** the original no-breaking-change step for honesty and Linux gaps. Those changes were split instead: doctor and `io_uring` shipped in v0.8.0; Unix-socket isolation is still open. There is no `v0.7.1` tag.
- **0.8.0 (released):** the breaking doctor exit-code change is recorded under `### Breaking` in `CHANGELOG.md`; the first red-team bench slice and the `io_uring` deny landed. The complete Linux install and full CLI/config/exit-code contract did not land with this release. Further changes on the way to 1.0 need explicit changelog entries and upgrade instructions.
- **1.0:** all four bars above are verified. `docs/reference/cli.md` becomes the compatibility contract for the public CLI, config schema, exit codes, egress levels and `verify --audit` states. Add contract tests and update `CONTRIBUTING.md` and `CLAUDE.md` when that promise takes effect.

## Outside this bar

macOS read confinement outside `filesystem.root` (`ARCHITECTURE.md`), a Windows fence (`docs/design/windows-feasibility.md`), look-back rules beyond slice 1 (`docs/design/look-back-rules.md`), and default off-box audit anchoring (`docs/how-it-works/audit-log.md`) are separate work.

When a bar closes, replace its remaining-work text with the merge commit and the test that proves it. Record any scope change with its approval source.
