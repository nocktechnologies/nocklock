# Setup: install, first run, verify

Everything here restates `README.md` (Quick start, Installation, Linux network-egress helper). If they disagree, the README and the code win.

## 1. Install

**Homebrew** (macOS, recommended):

```bash
brew install nocktechnologies/tap/nocklock
```

On Linux the formula builds only `nocklock`, and the default config's `wrap` refuses to start without `libfence_fs.so`. Build from source with `make build-all` until packaging lands.

**From source** (Go 1.26 or newer; `go.mod` pins 1.26.4):

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
make build-all     # ./nocklock; on Linux also builds libfence_fs.so
```

`build-all` compiles the Linux `LD_PRELOAD` interposer and skips it on macOS (`Makefile`), where the filesystem fence uses `sandbox-exec`.

**Linux, opt-in kernel egress fence** (`--net-fence=netns`) needs a root-owned helper and a constrained sudoers grant. Install the binary first, then the helper:

```bash
make install                      # nocklock to /usr/local/bin
sudo make install-egress-helper   # /usr/libexec/nocklock-egress-helper + /etc/sudoers.d/nocklock-egress
```

Without the helper the netns fence fails closed. Skip this step if you only use the default proxy mode.

## 2. First run

```bash
cd your-project
nocklock init                 # writes .nock/config.toml with safe defaults
nocklock wrap -- claude       # or any agent CLI
```

Pick a preset instead of the generic defaults with `nocklock init --runtime <name>` (`claude-code`, `codex`, `aider`, `gemini-cli`, `opencode`, `goose`; list them with `nocklock wrap --profile list`). `init` never overwrites an existing `.nock/config.toml`.

`nocklock wrap --dry-run` validates the config without starting any fence or command. `nocklock validate [path]` prints the effective policy.

**Claude Code on macOS**: the fence denies `~/Library/Keychains`, so the login must arrive through the environment. Run `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`), and use `nocklock init --runtime claude-code`. See the README note under Quick start.

## 3. Verify

| Check | Command | Good result |
|---|---|---|
| Binary | `nocklock version` | prints a version |
| Host can enforce each fence | `nocklock doctor` | verdict `PROTECTED`, exit 0; `GAPS FOUND` exits 2, `PARTIAL` 3, `UNPROTECTED` 4 (`internal/cli/doctor.go`) |
| Fence actually blocks | `nocklock verify` | adversarial self-test passes, exit 0 (`internal/cli/verify.go`) |
| Egress helper (Linux netns) | `sudo -n /usr/libexec/nocklock-egress-helper check` | prints nothing, exit 0 |
| Audit log intact | `nocklock verify --audit` | `AUTHENTIC` (signed) or `CONSISTENT` (unsigned chain); see `docs/how-it-works/audit-log.md` |
| What was blocked | `nocklock log --blocked`, `nocklock status` | per-session blocked events |

`wrap` prints and signs the effective egress level each session (`KERNEL`, `CONFINED`, `SEATBELT`, `ADVISORY`, `OFF`, `UNREACHABLE`). Read it: `ADVISORY` means a client that ignores `HTTP_PROXY` can reach any host. Set `network.require_enforced = true` or pass `--require-enforced-egress` to refuse such levels (`docs/how-it-works/network-fence.md`).

## 4. Where state goes
The audit log lives in `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`), not in the project, so the agent cannot edit it. The Ed25519 signing key is `~/.config/nocklock/signing-ed25519.key`. See `docs/how-it-works/audit-log.md`.

## Trouble
`wrap` exits `2` when it refuses to start (a requested fence cannot engage). Read the `NockLock: fatal:` or `fix:` line it prints, then run `nocklock doctor`. For anything that looks like a fence failure, see `docs/runbooks/incident.md`.
