# Repo map

One line per directory or key package: what lives there and where its tests are. Paths verified at `origin/main` 89c02fa. For the file-level tree see `ARCHITECTURE.md`; if this page and the code disagree, the code wins.

Go tests sit beside the code as `*_test.go`. Files ending `_linux_test.go` or `_darwin_test.go` run on that OS only.

## Top level

| Path | What it is | Tests |
|---|---|---|
| `cmd/nocklock/` | Entry point; calls `cli.Execute()` | none (thin) |
| `internal/` | All implementation packages (below) | beside each package |
| `pkg/receipt/` | Public, read-only per-session audit-chain verifier (`VerifySession`, `pkg/receipt/receipt.go`), importable by other modules | `pkg/receipt/receipt_test.go`, `external_test.go` (imports it as an outside module would), `testdata/` |
| `integration/` | End-to-end test of the built binary | `integration/integration_test.go`, run with `go test -tags=integration ./...` (`CONTRIBUTING.md`) |
| `scripts/` | `install-egress-helper.sh` (root-owned helper plus sudoers grant), `test-init-default-linux.sh` (fresh `init` then wrapped shell), `credential-mutation-overlay.py` (test-only credential mutations), `test-landlock-probe-thread-affinity.py` (deterministic cross-thread control and optional unpinned soak), `check-public-content.py` (tracked-file disclosure guard), `check-gitleaks-baseline.py` (historical scan fingerprint comparison) | helper: `internal/fence/network/netns/install_helper_script_linux_test.go`; hosted credential jobs in `network-egress.yml`; thread-affinity classifier/cleanup tests in `test_landlock_probe_thread_affinity.py` and non-root controls in `test.yml`; public-content check in `test.yml`; secret scan comparison in `gitleaks.yml` |
| `docs/` | This documentation set; index at `docs/README.md` | none |
| `bench/redteam/` | NockLock + NockGuard scripted attack bench (`attacks.toml`, `run.sh`, `redteam.py`) and signed receipt report; `kernel_cases.py` records Unix-socket/io_uring proof and explicit kernel coverage gaps separately | bench cases in `attacks.toml`, Python driver/receipt tests, CI `redteam-bench` job in `.github/workflows/network-egress.yml` |
| `.claude/` | Agent config: branch-lock hook, `decisions/` (ADR-001..005), `design/`, `diagrams/`, `lessons/` | none |
| `.github/workflows/` | CI: `test.yml`, `network-egress.yml`, `gitleaks.yml`, `claude.yml`, `claude-code-review.yml` | n/a |
| `.githooks/` | Local pre-commit hook (`pre-commit`) | no direct tests |
| `.nock/` | Example project config (`config.toml.example`) | none |
| `Makefile` | `build`, `build-all`, `install`, `install-egress-helper`, `fmt`, `vet`, `lint`, `test` | n/a |
| `ARCHITECTURE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `README.md` | Package tree, contribution rules, release notes, user-facing guide | n/a |

## `internal/`

| Package | What lives there | Tests |
|---|---|---|
| `internal/cli/` | Cobra command tree. `wrap.go` is the main command; `doctor.go`, `verify.go`, `scan.go`, `anchor.go`, `init_cmd.go`, `validate.go`, `log.go`, `status.go`, `config.go`, `version.go` are the others. Hidden `__landlock-exec`, `__netns-*`, `__probe` are internal re-exec entry points. `egress_level.go` defines the egress levels. `exec_fingerprint.go` hashes the requested command for the start row. `interposer_trust*.go` validates Linux library ownership, permissions and symlink paths. `root.go` holds `exitCodeError` and `Execute()` | `internal/cli/*_test.go`, including `verify_coverage_test.go` (history-verification output and exit contracts); platform-specific `wrap_*_linux_test.go` and `wrap_*_darwin_test.go` |
| `internal/config/` | Strict TOML load (`config.go`), defaults (`defaults.go`), validation (`validate.go`), profile overlays (`overlay.go`, `profiles.go`), audit-state path resolution (`state.go`) | `internal/config/*_test.go`, `fuzz_test.go` |
| `internal/config/presets/` | Embedded runtime presets: `claude-code`, `codex`, `aider`, `gemini-cli`, `opencode`, `goose` (`.toml`) | `internal/config/profiles_test.go` |
| `internal/fence/secrets/` | Secret fence (`secrets.go`: pass/block glob filter) and the preflight scanner (`scan.go`) | `secrets_test.go`, `scan_test.go`, `scan_unix_test.go` |
| `internal/fence/fs/` | Filesystem fence: config processing (`config.go`), Go wrapper (`fence.go`), collector-only connection-peer snapshots and detail envelopes (`peer*.go`), macOS Seatbelt profile (`sbpl.go`, `seatbelt.go`), macOS denial-log tailer (`denylog.go`) | `*_test.go` here, `peer_test.go` (portable spoof/signing/legacy controls), `peer_linux_test.go` (real Unix sockets and inherited writer), `seatbelt_darwin_test.go`, `fuzz_test.go` |
| `internal/fence/fs/landlock/` | Linux Landlock ruleset and exec (`landlock_linux.go`, `rules.go`); `landlock_stub.go` for other OSes | `rules_test.go`, `landlock_linux_test.go`, `defaults_linux_test.go`, `unix_socket_abi9_linux_test.go` (real kernel proof or named gap), `fuzz_test.go`, `testdata/staticprobe` |
| `internal/fence/fs/interposer/` | C `LD_PRELOAD` library `libfence_fs.c` (Linux only) that reports denied opens and maps the loopback proxy address onto a Unix socket; own `Makefile` | `internal/fence/fs/interposer_ack_linux_test.go`, `interposer_bridge_linux_test.go`, `interposer_source_test.go` |
| `internal/fence/syscallfence/` | Linux seccomp syscall fence: denylist (`denylist.go`), policy (`policy.go`), filter build (`seccomp_linux.go`); `seccomp_stub.go` elsewhere | `program_test.go`, `denylist_test.go`, `seccomp_enforce_linux_test.go` |
| `internal/fence/network/` | Local HTTP/HTTPS CONNECT proxy and domain allowlist (`proxy.go`, `handler.go`, `connect.go`), DNS cache, watchdog, look-back rules (`lookback.go`) | `*_test.go` here, `lookback_race_linux_test.go` |
| `internal/fence/network/netns/` | Linux `--net-fence=netns`: network namespace, nftables floor, transparent proxy, egress helper, subnet reservation | `*_linux_test.go` here (`netns_bypass`, `protocol_matrix`, `dns_escape`, `subnet_reservation`) |
| `internal/logging/` | SQLite event log: hash chain, Ed25519 signing (`signing.go`), default v1 anchors (`anchor.go`), opt-in v2 record format (`anchor_v2.go`), trusted identity/enrollment and prune lock (`chain_identity.go`, `chain_identity_lock_*.go`), verified v2 lifecycle and durable registration replay (`anchor_chain.go`), signed verification receipt / prefix rescan (`verify_receipt.go`), durable signed run close and lifecycle verifier (`run_close.go`), chain export | `logger_test.go`, `signing_test.go`, `anchor_test.go`, `anchor_v2_test.go`, `chain_identity*_test.go`, `anchor_chain_test.go`, `anchor_remediation_test.go` (retained-request, strict-open and WAL controls), `anchor_verify_profile_test.go` (env-gated profiling recipe), `anchor_head_only_test.go` (head-only shortcut negative control), `verify_receipt_test.go` (receipt negative controls 1-19, differential and mutation), `run_close_test.go` (run lifecycle acceptance controls), `testdata/anchor-v2/` (public interoperability vectors), `logger_symlink_test.go` |
| `internal/anchorclient/` | HTTP clients for explicit legacy compatibility (`client.go`) and authenticated v2 registration/migration/CAS (`client_v2.go`) | `client_test.go`, `client_v2_test.go` |
| `internal/forward/` | Opt-in `[audit.forward]` queue that sends decisions to Command's ops log (`forward.go`) | `forward_test.go` |
| `internal/version/` | Version string, set by ldflags | `version_test.go` |

## Where to start
- Changing a fence: the matching page in `docs/how-it-works/`, then its package above.
- Adding a CLI flag or exit path: `docs/reference/cli.md` and `internal/cli/`.
- Shipping: `docs/runbooks/release.md`.
