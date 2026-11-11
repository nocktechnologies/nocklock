# NockLock 1.0 roadmap

Updated 2026-11-12. Released baseline: `v1.0.0`. Release history is in `CHANGELOG.md`. The planned 0.7.1 step was split across 0.8.0 and 0.9.0; there is no `v0.7.1` tag. A gap is closed only when its fix is released from `main`, the red-team case runs in CI with an allowed-action negative control, and the docs describe the tested boundary.

1.0 released 2026-11-12 with the signed release-evidence gate for Landlock ABI 9 and the CLI compatibility promise in effect. Signed Linux installer assets for earlier releases have fresh-host, cross-version and broader-network evidence. Ubuntu 24.04 amd64 with glibc 2.39 is the supported Linux installation target; other distributions, Linux arm64 and musl remain outside that support matrix.

## The four completed 1.0 bars

| # | Bar | State and evidence |
|---|---|---|
| 1 | Close the Linux `CONFINED` Unix-socket and `io_uring` gaps, with red-team coverage | Closed in [v0.17.1](https://github.com/nocktechnologies/nocklock/releases/tag/v0.17.1): its release publishes landlock-abi9-receipt.json and landlock-abi9-receipt.json.sigstore.json. `io_uring` syscalls are denied (`internal/fence/syscallfence/denylist.go`, v0.8.0). Below Landlock ABI 9, Unix sockets stay reachable: `wrap` signs that limitation, `doctor` reports `PARTIAL`, and `network.require_unix_socket_isolation` refuses instead. The ABI 9 rules run on a real kernel in CI: `.github/workflows/landlock-abi9-receipt.yml` boots a throwaway Ubuntu 26.10 KVM guest, fails unless its Landlock ABI is 9 or later, runs `bench/redteam/kernel_cases.py --require-abi 9` and signs the receipt. Under `CONFINED` it proves denial of a pathname socket outside `filesystem.root` and an abstract socket, with successful connections to the exact proxy and fence-event sockets named by the policy. It makes no claim about sockets inside `filesystem.root`. The tagged release workflow requires a receipt at the release commit and packages its JSON, Sigstore bundle and hashes alongside Linux acceptance. |
| 2 | Ship honest `doctor` verdicts | Done. Shipped in v0.8.0 and extended through v0.9.2; v0.12.0 adds the Deputies section (`internal/cli/doctor.go`, `docs/how-it-works/deputies.md`, exits 0/2/3/4). v0.13.0 adds repo git-config execution warnings without changing those verdicts or exit codes; its GitSpawn enforcement proof covers Linux netns mode only. Keep `docs/how-it-works/doctor-and-verify.md` and the README consistent with that contract. |
| 3 | Complete the Linux install | Done. Shipped in v0.16.1, main commit `13536800ab397c0b2f4a2ea3d9dc1fbc54f7e104`. [Production fresh-host acceptance](https://github.com/nocktechnologies/nocklock/actions/runs/40612628058) and [signed v0.16.0 ↔ v0.16.1 lifecycle plus Linux/macOS network acceptance](https://github.com/nocktechnologies/nocklock/actions/runs/40612879908) passed. Both releases publish their original six signed assets and [durable receipts](https://github.com/nocktechnologies/nocklock/releases/download/v0.16.1/linux-release-acceptance.json). Upgrade/retry/rollback preserve config, audit state and retained bytes; stale binaries and ordinary downgrades refuse. HTTP(S) allow/deny and direct TCP/UDP tests include unfenced controls, Linux drop counters and helper-failure refusal. The authenticated bootstrap is in `packaging/linux/RELEASE-INSTALL.md`. Support remains Ubuntu 24.04 amd64/glibc 2.39; source/candidate migration and other Linux platforms are unsupported. The below-ABI-9 Unix-socket limitation remains. |
| 4 | Pin the CLI, config schema and exit codes as a contract | Done for 1.0. `docs/reference/cli.md` is the compatibility promise, held by `internal/cli/contract_test.go` for commands, flags, `wrap` tokens, config keys, egress levels, `verify --audit` run states, aliases, `doctor` and `Execute()` exit codes, and these `wrap` cases: exit `1` for no command, an unknown flag or a command not found; exit `2` for unmet `--require-enforced-egress` or a failed `session_end` write; the child's code passed through; and a signal mapped to `1`. Other `wrap` refusal codes are documented and held in review. Stderr and the signed `session_end` row distinguish overlapping codes in the cases the CLI reference lists; a refusal before the run starts has no `session_end` row. |

## 1.0 released: the compatibility promise is in effect

All four bars are complete. The public CLI, config and exit-code promise in `docs/reference/cli.md` applies from v1.0.0.

## Later: outside the 1.0 bar

- macOS read confinement outside `filesystem.root` (`ARCHITECTURE.md`)
- A Windows fence (`docs/design/windows-feasibility.md`)
- Look-back rules beyond slice 1 (`docs/design/look-back-rules.md`)
- Default off-box audit anchoring (`docs/how-it-works/audit-log.md`); per-chain v2 anchors shipped in v0.10.0 and in-run checkpoints in v0.12.0, both opt-in
- Signing-key rotation: the offline endorsement format and library verifier shipped in v0.12.0, but no command switches keys (`docs/design/rotation-endorsement.md`)
- A public timestamp over the v2 snapshot digest (`docs/design/public-timestamp-v2-digest.md`), design only
- Kernel-drop observation (`docs/design/kernel-floor-denial-evidence.md`), design only
