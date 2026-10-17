# Deputies: helpers the agent can ask to act for it

Most coding-agent escapes do not break the sandbox. The agent asks a helper with more power to do the work instead. It might ask the Docker daemon to start a privileged container that mounts your disk. It might write a config file that a trusted tool loads later, outside the fence. Security people call this a confused deputy.

`nocklock doctor` lists the deputies on your machine that the wrapped agent can reach. For each one it says what it is, whether the fence blocks it, and why it matters. It changes nothing. You decide what to remove, lock down, or accept.

## What doctor looks for

| Deputy | Where doctor looks | Why it matters |
|---|---|---|
| Container sockets | Linux: `/var/run/docker.sock`, `/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/podman/podman.sock`, the rootless Docker and Podman sockets under `$XDG_RUNTIME_DIR`, `~/.docker/desktop/docker.sock`. macOS: `/var/run/docker.sock`, `~/.docker/run/docker.sock`, `~/Library/Containers/com.docker.docker/Data/docker.raw.sock` | Anyone who can talk to the daemon can start a privileged container that mounts the host. |
| systemd user bus (Linux) | `$XDG_RUNTIME_DIR/bus` | It can start or change user services that run outside the fence. |
| Service directories | Linux: `~/.config/systemd/user`. macOS: `~/Library/LaunchAgents` | A unit or agent placed here runs as you, outside the fence. |
| Shell startup files | `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.config/fish/config.fish` | Your shell runs it the next time you open a terminal. |
| Agent config and hooks | Claude Code (`~/.claude.json`, `~/.claude/settings.json`, `~/.claude/hooks`, and in the project `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.claude/hooks`), Codex (`config.toml` under `~/.codex` and the project's `.codex`), Cursor (`mcp.json` and `hooks.json` under `~/.cursor` and the project's `.cursor`), Gemini CLI (`settings.json` under `~/.gemini` and the project's `.gemini`) | The tool loads it on its next run, and it can name commands to run. |
| sudo without a password prompt | `/usr/bin/sudo -k -n true`, which fails at once instead of asking for a password, with a 3 second limit. Doctor runs only `/usr/bin/sudo`, never a `sudo` found on `PATH`, and skips the check when that file is not a root-owned executable | A command run through sudo acts as root. |

Doctor lists a socket only if it exists and you can connect to it. It lists a file or directory if you can write to it, or if you can write to the folder that holds it, because then the agent can delete the entry and put its own in place. A symlink counts both ways: a link to a file outside the fence is still reachable when the link sits in a folder the agent can write. The same holds for a linked folder: if the path as listed (for example `.claude/settings.json` in the project, with `.claude` a link to `~/.claude`) is inside a write grant, the agent can delete the link and create a real folder in its place, so the row is reachable. Doctor lists only paths on disk at scan time, so a path the agent could create later is not listed.

The sudo row passes only for a NOPASSWD rule. The `-k` flag makes sudo ignore a cached sudo login from a recent `sudo` where you typed your password, so that cache does not count, and the check does not refresh it.

## When the fence blocks a deputy

- **Sockets.** On Linux the fence blocks Unix-socket connections only in `CONFINED` egress with Landlock ABI 9 or later. On macOS the Seatbelt network floor blocks every Unix-socket connection when it is active, which is the `SEATBELT` egress level.
- **Files and directories.** The kernel filesystem fence (Landlock on Linux, Seatbelt on macOS) limits writes to `filesystem.root` in `read-write` mode, `allow_rw` paths on Linux, and the per-user temporary and cache directories on macOS. A path under `filesystem.deny` (and on macOS the built-in sensitive paths, such as `~/.config` and `~/.docker`) stays blocked. With `filesystem.linux_enforcement = "off"`, only the userspace fence applies, so doctor does not count it as blocked.
- **sudo.** On Linux, Landlock and the syscall fence both set `no_new_privs`, so sudo cannot raise privileges. On macOS, Seatbelt does not stop sudo.

Project agent config sits inside `filesystem.root`, so the agent can write it. Doctor reports that honestly. On macOS you can add the file's path to `filesystem.deny`. On Linux, Landlock cannot deny a path inside the granted root, and `wrap` refuses to start if you try. Keep agent config out of the root, or accept the `PARTIAL` and review the file before you run the tool again outside the fence.

## How the verdict changes

A deputy the fence does not block keeps the verdict at `PARTIAL` (exit 3), and the summary names the count. It is never a gap: it does not turn the verdict into `GAPS FOUND`, and it does not change a worse verdict. A blocked deputy is listed for your information only.

`network.require_unix_socket_isolation = true` works as before: below Landlock ABI 9, `wrap` refuses to start and doctor reports `GAPS FOUND`. The deputies section still lists the sockets.

## Example

```
Deputies
⚠ docker-socket [reachable]: Docker daemon socket /var/run/docker.sock: not blocked by the fence, because Landlock Unix-socket isolation needs CONFINED egress and Landlock ABI v9. Whoever can talk to it can start a privileged container that mounts the host.
✓ shell-startup [blocked]: shell startup file /home/you/.bashrc: blocked by the fence. Your shell runs it the next time you open a terminal, outside the fence.
✓ sudo-no-prompt [blocked]: sudo runs without a password prompt (a NOPASSWD rule): blocked by the fence. A command run through sudo acts as root.

VERDICT: PARTIAL
- unix-sockets: advisory
  Option: use a Linux kernel with Landlock ABI v9 or later to enforce isolation, or set network.require_unix_socket_isolation = true to make wrap refuse below ABI 9.
- deputies: 1 reachable and not blocked by the fence (listed under Deputies)
```

`doctor --json` reports the same rows in `checks` with `"group": "Deputies"`. The `status` is `reachable` or `blocked`, and `message` names the path.

## Limits

- Doctor checks the deputies above and no others. Other helpers, such as git hooks or editor tasks, are not listed.
- Doctor cannot see a `--net-fence=netns` run. It reports the proxy-mode fence.
- On Linux, doctor counts a path under `filesystem.deny` as blocked. It does not check whether that deny overlaps a grant. If it does, `wrap` refuses to start.
- The scan is a point-in-time check of this user's access. It does not prove what a past session could reach. Use `nocklock verify` and the signed session rows for that.

Code: `internal/cli/doctor_deputies.go`. Tests: `internal/cli/doctor_deputies_test.go`.
