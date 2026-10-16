# Setup: install, first run, verify

Everything here restates `README.md` (Quick start, Installation, Linux network-egress helper). If they disagree, the README and the code win.

## 1. Install

**Homebrew** (macOS, recommended):

```bash
brew install nocktechnologies/tap/nocklock
```

On Linux the formula installs only the `nocklock` binary, not `libfence_fs.so`, and the default config's `wrap` refuses to start without it. No supported Homebrew step installs the library today; use the source install below. Packaging is the open card N11643.

**From source** (Go 1.26 or newer; `go.mod` pins 1.26.4):

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
make build-all     # as your user: ./nocklock; on Linux also libfence_fs.so
sudo mkdir -p /usr/local/bin                            # some Macs lack it
sudo install -m 0755 nocklock /usr/local/bin/nocklock   # copy only
```

Build as your user, then copy with `sudo install`. Do not run `sudo make install`. Its `install` target depends on `build` (`Makefile`), so it runs `go build` as root. Root's `PATH` often has no Go, and a root build can leave root-owned files in the Go caches. `sudo install` only copies the binary, and the copy is root-owned. Every user needs this step, including default proxy-mode users. On macOS that is the whole install. On Linux continue with the next step.

`build-all` compiles the Linux `LD_PRELOAD` interposer to `internal/fence/fs/interposer/libfence_fs.so` and skips it on macOS (`Makefile`), where the filesystem fence uses `sandbox-exec`.

**Linux: place `libfence_fs.so`.** The step above installs only `nocklock`. No `make` target installs the library, and packaging is the open card N11643. `wrap` looks for the library only in these places, in order: the directory of the `nocklock` executable, `/usr/local/lib/nocklock/`, then `/usr/lib/nocklock/` (`findTrustedLibFenceFS` in `internal/cli/wrap.go`). A copy inside the current working directory is skipped, so running `./nocklock` from the checkout does not find the library built beside it. There is no setting or environment variable that points at another path. Copying it by hand to one of those paths is the only way to satisfy the lookup today:

```bash
sudo install -D -m 0644 internal/fence/fs/interposer/libfence_fs.so /usr/local/lib/nocklock/libfence_fs.so
```

If no candidate exists, `wrap` refuses to start with `trusted filesystem fence library not found. Install libfence_fs.so next to the nocklock binary, at /usr/local/lib/nocklock/libfence_fs.so, or at /usr/lib/nocklock/libfence_fs.so; refusing to launch with an untrusted LD_PRELOAD path`.

**Linux, opt-in kernel egress fence** (`--net-fence=netns`) needs a root-owned helper and a constrained sudoers grant. Install the binary first (the source install above), then the helper:

```bash
sudo make install-egress-helper   # /usr/libexec/nocklock-egress-helper + /etc/sudoers.d/nocklock-egress
```

Without the helper the netns fence fails closed. Skip this step if you only use the default proxy mode.

## 2. First run

```bash
cd your-project
nocklock init --runtime claude-code   # choose your agent
# Configure the agent credential below, then:
nocklock wrap -- claude
```

Choose a runtime preset with `nocklock init --runtime <name>` (`claude-code`, `codex`, `aider`, `gemini-cli`, `opencode`, `goose`; list them with `nocklock wrap --profile list`). `init` never overwrites an existing `.nock/config.toml`. For an existing project, run `nocklock init --runtime <name> --diff`, review the changes, and edit the config. Use plain `nocklock init` for a generic command that needs no provider credentials.

`nocklock wrap --dry-run` validates the config without starting any fence or command. `nocklock validate [path]` prints the effective policy.

**Claude Code on macOS**: the fence denies `~/Library/Keychains`, so the login must arrive through the environment. Run `claude setup-token`, export `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`), and initialize with the `claude-code` preset as above. For an existing config, use `--diff` and apply the reviewed changes before launching. See the README note under Quick start.

## 3. Verify

| Check | Command | Good result |
|---|---|---|
| Binary | `nocklock version` | prints a version |
| Host can enforce each fence | `nocklock doctor` | verdict `PROTECTED`, exit 0; `GAPS FOUND` exits 2, `PARTIAL` 3, `UNPROTECTED` 4 (`internal/cli/doctor.go`) |
| Fence actually blocks | `nocklock verify` | adversarial self-test passes, exit 0 (`internal/cli/verify.go`) |
| Egress helper (Linux netns) | `sudo -n /usr/libexec/nocklock-egress-helper check` | prints nothing, exit 0 |
| Audit log intact | `nocklock verify --audit` | `AUTHENTIC` (signed and checked against the local managed key or `--ed25519-pub`), or `CONSISTENT` (chain intact; unsigned, or signed with no key available to check it); see `docs/how-it-works/audit-log.md` |
| What was blocked | `nocklock log --blocked`, `nocklock status` | per-session blocked events |

On Linux `CONFINED` below Landlock ABI 9, `doctor` returns `PARTIAL` (exit 3) because other Unix sockets remain reachable. Default `wrap` warns and runs; set `network.require_unix_socket_isolation = true` to refuse instead. The ABI 9 enforcement branch still needs real-kernel validation.

`wrap` prints and signs the effective egress level each session (`KERNEL`, `CONFINED`, `SEATBELT`, `ADVISORY`, `OFF`, `UNREACHABLE`). Read it: `ADVISORY` means a client that ignores `HTTP_PROXY` can reach any host. Set `network.require_enforced = true` or pass `--require-enforced-egress` to refuse such levels (`docs/how-it-works/network-fence.md`).

Bare commands are resolved against the caller's `PATH` before fence helpers are added. A relative PATH entry cannot implicitly select a program in the working directory; use an explicit `./tool` path when intended. Lookup failure exits 1 with a `resolve command` error. Fence policy still governs whether the selected program may execute.

## 4. Where state goes
The audit log lives in `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`), not in the project, so for a fresh project the agent cannot edit it. An existing `.nock/events.db` is kept in place, inside the project (`docs/decisions/010-audit-state-outside-project.md`, `ResolveDBPath` in `internal/config/config.go`). Whether the agent can write it on Linux depends on the filesystem fence:

- **Landlock engaged (the default, `filesystem.linux_enforcement = "required"`):** `wrap` withholds the grant on the `.nock` directory (`ProtectedRootSubdir`, `internal/fence/fs/landlock/rules.go`), so the agent cannot write the legacy log unless another rule covers it, such as a `filesystem.allow_rw` entry that contains `.nock`. The price is that the agent cannot create or remove entries directly in the fence root; `wrap` prints that on stderr. If `.nock` is not a direct child of `filesystem.root`, rule generation refuses instead.
- **Landlock not engaged (`linux_enforcement` set to `preferred` or `off` and Landlock unavailable or off):** only the `LD_PRELOAD` interposer applies. It does not receive `ProtectedRootSubdir` (`internal/fence/fs/config.go`), so treat the legacy log as agent-writable.

To get the fresh-project guarantee, move `events.db`, its `-wal`/`-shm` sidecars and `chain-anchor.json` into this project's audit state directory while no session is running. That is `$XDG_STATE_HOME/nocklock/<project-key>/`, or `~/.local/state/nocklock/<project-key>/`. To print `<project-key>`, run `printf %s "$(pwd -P)" | sha256sum | cut -c1-16` from the project root (on macOS use `shasum -a 256`). Create it with `s="${XDG_STATE_HOME:-$HOME/.local/state}"; install -d -m 0700 "$s/nocklock" "$s/nocklock/<project-key>"` if it does not exist (`install -d` sets the mode on every directory it names; `mkdir -p -m` sets it only on the last). With the default `logging.db`, NockLock then uses the log there; setting `logging.db` to that absolute path also works. Any other place outside the project is rejected when the config loads. Run `nocklock status` and check that the `Event log:` line names the new path (`README.md` "Event log"). The Ed25519 signing key is `~/.config/nocklock/signing-ed25519.key`. See `docs/how-it-works/audit-log.md`.

## 5. Config file trust
Before any command reads `.nock/config.toml`, NockLock checks that no other user can rewrite it: the file and every ancestor directory up to the filesystem root must not be group- or world-writable (the sticky bit is not an exemption), and must be owned by root or the invoking user. Symlinks in the path are followed, and the check covers both the directory holding each symlink and the directories it leads into: a system symlink such as macOS's `/var -> /private/var` passes, while a symlink planted in `/tmp` or one leading into a writable directory is refused. The file it checks is the file it reads. This is why a config that loaded from a world-writable directory — a planted `/tmp/.nock/config.toml`, for instance — is refused with a message naming the offending path and its fix (`chmod go-w` or `chown`). A project anywhere under `/tmp` or `/var/tmp` is refused for the same reason; keep projects under your home directory. With a umask of `002`, new directories are group-writable; run `chmod g-w` on the project directory chain. It is the cross-user defense; a same-user change to a config the invoker already owns is surfaced by the signed `config.digest` row, not this check.

For a layout you know is safe but that the check refuses — a shared build directory owned by a trusted service account, say — set `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG=1`. It is read only from the operator environment, never from the config file, so a fenced child cannot turn it on for the next run. Only a truthy value (`1`, `true`, `yes`, `on`) disables the check.

## Trouble
`wrap` exits `2` when it refuses to start (a requested fence cannot engage). Read the `NockLock: fatal:` or `fix:` line it prints, then run `nocklock doctor`. For anything that looks like a fence failure, see `docs/runbooks/incident.md`.
