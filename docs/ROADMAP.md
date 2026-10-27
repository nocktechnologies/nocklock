# Roadmap to 1.0

Updated 2026-10-26. Released baseline: `v0.15.0`. Release history is in `CHANGELOG.md`. The planned 0.7.1 step was split across 0.8.0 and 0.9.0; there is no `v0.7.1` tag. A gap is closed only when its fix is released from `main`, the red-team case runs in CI with an allowed-action negative control, and the docs describe the tested boundary.

## Now: the four 1.0 bars

| # | Bar | State and remaining work |
|---|---|---|
| 1 | Close the Linux `CONFINED` Unix-socket and `io_uring` gaps, with red-team coverage | `io_uring` syscalls are denied (`internal/fence/syscallfence/denylist.go`, v0.8.0). Below Landlock ABI 9, Unix sockets stay reachable: `wrap` signs that limitation, `doctor` reports `PARTIAL`, and `network.require_unix_socket_isolation` refuses instead. The ABI 9 rules now run on a real kernel in CI: `.github/workflows/landlock-abi9-receipt.yml` boots a throwaway Ubuntu 26.10 KVM guest on a GitHub-hosted runner, fails unless its Landlock ABI is 9 or later, runs `bench/redteam/kernel_cases.py --require-abi 9` and signs the receipt. Under `CONFINED` it shows a pathname socket outside the root and an abstract socket denied, and, as the allowed-case control, connects succeeding to the exact proxy and fence-event sockets the ABI 9 policy allows. The allowed case is proven for those two sockets only, not for any socket inside `filesystem.root`. Receipt produced in CI, not yet released. `bench/redteam/kernel_cases.py` records the probes and gaps. Open until capable-kernel receipts ship in a release; `CONFINED` must not claim Unix-socket isolation before then. |
| 2 | Ship honest `doctor` verdicts | Shipped in v0.8.0 and extended through v0.9.2; v0.12.0 adds the Deputies section (`internal/cli/doctor.go`, `docs/how-it-works/deputies.md`, exits 0/2/3/4). v0.13.0 adds repo git-config execution warnings without changing those verdicts or exit codes; its GitSpawn enforcement proof covers Linux netns mode only. Keep `docs/how-it-works/doctor-and-verify.md` and the README consistent with that contract. |
| 3 | Complete the Linux install | Open until released and accepted. Published v0.15.0 still uses source installation. The new standalone Go installer implements signed Ubuntu 24.04 amd64 installation, upgrades, verified rollback and opt-in helper authorization; managed commands exclude upgrades with an installation lock. `packaging/linux/RELEASE-INSTALL.md` documents the authenticated bootstrap. The tag-only `release.yml` workflow prepares signed assets and fresh-VM acceptance evidence, but does not publish them. Remaining: run the tagged production path, review its receipts and publish immutable release assets; cross-version release acceptance and broader network gates remain required by `docs/design/linux-packaging.md`. |
| 4 | Pin the CLI, config schema and exit codes as a contract | `docs/reference/cli.md` records current behavior. Remaining: audit every command, flag and config key against `internal/cli/` and `internal/config/`, resolve the child-exit overlap with CLI errors, and pin the contract in tests. |

## Next: 1.0

All four bars verified. `docs/reference/cli.md` becomes the compatibility contract for the public CLI, config schema, exit codes, egress levels and `verify --audit` states. Add contract tests and update `CONTRIBUTING.md` and `AGENTS.md` when that promise takes effect.

## Later: outside the 1.0 bar

- macOS read confinement outside `filesystem.root` (`ARCHITECTURE.md`)
- A Windows fence (`docs/design/windows-feasibility.md`)
- Look-back rules beyond slice 1 (`docs/design/look-back-rules.md`)
- Default off-box audit anchoring (`docs/how-it-works/audit-log.md`); per-chain v2 anchors shipped in v0.10.0 and in-run checkpoints in v0.12.0, both opt-in
- Signing-key rotation: the offline endorsement format and library verifier shipped in v0.12.0, but no command switches keys (`docs/design/rotation-endorsement.md`)
- A public timestamp over the v2 snapshot digest (`docs/design/public-timestamp-v2-digest.md`), design only
- Kernel-drop observation (`docs/design/kernel-floor-denial-evidence.md`), design only

When a bar closes, replace its remaining work with the merge commit and the test that proves it.
