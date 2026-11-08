# Roadmap to 1.0

Updated 2026-11-05. Released baseline: `v0.17.0`. Release history is in `CHANGELOG.md`. The planned 0.7.1 step was split across 0.8.0 and 0.9.0; there is no `v0.7.1` tag. A gap is closed only when its fix is released from `main`, the red-team case runs in CI with an allowed-action negative control, and the docs describe the tested boundary.

v0.17.0 released 2026-11-02 with a fail-closed signing path, opt-in durable egress audit and an informational `doctor` personal-email warning. Prepared next release: `v0.17.1`, with the signed release-evidence gate for Landlock ABI 9 (1.0 bar 1). The six signed Linux assets are published for v0.16.0, v0.16.1 and v0.17.0 with fresh-host, cross-version and broader-network evidence. The installation bar is closed for Ubuntu 24.04 amd64 with glibc 2.39; other distributions, Linux arm64 and musl remain outside that support matrix.

## Now: the four 1.0 bars

| # | Bar | State and remaining work |
|---|---|---|
| 1 | Close the Linux `CONFINED` Unix-socket and `io_uring` gaps, with red-team coverage | `io_uring` syscalls are denied (`internal/fence/syscallfence/denylist.go`, v0.8.0). Below Landlock ABI 9, Unix sockets stay reachable: `wrap` signs that limitation, `doctor` reports `PARTIAL`, and `network.require_unix_socket_isolation` refuses instead. The ABI 9 rules run on a real kernel in CI: `.github/workflows/landlock-abi9-receipt.yml` boots a throwaway Ubuntu 26.10 KVM guest, fails unless its Landlock ABI is 9 or later, runs `bench/redteam/kernel_cases.py --require-abi 9` and signs the receipt. Under `CONFINED` it proves denial of a pathname socket outside `filesystem.root` and an abstract socket, with successful connections to the exact proxy and fence-event sockets named by the policy. It makes no claim about sockets inside `filesystem.root`. The tagged release workflow now requires a receipt at the release commit and packages its JSON, Sigstore bundle and hashes alongside Linux acceptance. This bar closes when those assets ship in the next release; no earlier release carries them. |
| 2 | Ship honest `doctor` verdicts | Shipped in v0.8.0 and extended through v0.9.2; v0.12.0 adds the Deputies section (`internal/cli/doctor.go`, `docs/how-it-works/deputies.md`, exits 0/2/3/4). v0.13.0 adds repo git-config execution warnings without changing those verdicts or exit codes; its GitSpawn enforcement proof covers Linux netns mode only. Keep `docs/how-it-works/doctor-and-verify.md` and the README consistent with that contract. |
| 3 | Complete the Linux install | Shipped in v0.16.1, main commit `13536800ab397c0b2f4a2ea3d9dc1fbc54f7e104`. [Production fresh-host acceptance](https://github.com/nocktechnologies/nocklock/actions/runs/40612628058) and [signed v0.16.0 ↔ v0.16.1 lifecycle plus Linux/macOS network acceptance](https://github.com/nocktechnologies/nocklock/actions/runs/40612879908) passed. Both releases publish their original six signed assets and [durable receipts](https://github.com/nocktechnologies/nocklock/releases/download/v0.16.1/linux-release-acceptance.json). Upgrade/retry/rollback preserve config, audit state and retained bytes; stale binaries and ordinary downgrades refuse. HTTP(S) allow/deny and direct TCP/UDP tests include unfenced controls, Linux drop counters and helper-failure refusal. The authenticated bootstrap is in `packaging/linux/RELEASE-INSTALL.md`. Support remains Ubuntu 24.04 amd64/glibc 2.39; source/candidate migration and other Linux platforms are unsupported. The below-ABI-9 Unix-socket limitation remains. |
| 4 | Pin the CLI, config schema and exit codes as a contract | `docs/reference/cli.md` was audited against `internal/cli/` and `internal/config/` and matches the code. `internal/cli/contract_test.go` pins commands, flags, `wrap` tokens, config keys, egress levels, `verify --audit` run states, command aliases, and the exit codes of `doctor`, `Execute()` and `wrap`, and fails when the code or that page drifts. Remaining: decide whether `wrap` keeps passing child exit codes through unchanged, with stderr and the `session_end` row as the way to tell a child's `1` or `2` from NockLock's, or reserves codes and moves every startup refusal to `2`; then make the page the compatibility promise. |

## Next: 1.0

All four bars verified. `docs/reference/cli.md` becomes the compatibility contract for the public CLI, config schema, exit codes, egress levels and `verify --audit` states, held by the contract tests in `internal/cli/contract_test.go`. Update `CONTRIBUTING.md` and `AGENTS.md` when that promise takes effect.

## Later: outside the 1.0 bar

- macOS read confinement outside `filesystem.root` (`ARCHITECTURE.md`)
- A Windows fence (`docs/design/windows-feasibility.md`)
- Look-back rules beyond slice 1 (`docs/design/look-back-rules.md`)
- Default off-box audit anchoring (`docs/how-it-works/audit-log.md`); per-chain v2 anchors shipped in v0.10.0 and in-run checkpoints in v0.12.0, both opt-in
- Signing-key rotation: the offline endorsement format and library verifier shipped in v0.12.0, but no command switches keys (`docs/design/rotation-endorsement.md`)
- A public timestamp over the v2 snapshot digest (`docs/design/public-timestamp-v2-digest.md`), design only
- Kernel-drop observation (`docs/design/kernel-floor-denial-evidence.md`), design only

When a bar closes, replace its remaining work with the merge commit and the test that proves it.
