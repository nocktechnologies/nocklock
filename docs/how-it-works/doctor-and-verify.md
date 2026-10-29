# doctor and verify

Citations name source files at `v0.9.0` (`f2b0d04`) (no line numbers, so they do not go stale).

## `nocklock doctor`: can this host enforce each fence?
Static check of the configuration plus host capabilities (`internal/cli/doctor.go`). Each boundary has a posture: `enforced`, `advisory`, `disabled`, `enabled` (configured but backend missing), or `unavailable`. `--json` includes these postures and the effective proxy-mode egress level (`doctor.go`). The verdicts and exits are `PROTECTED` (0), `GAPS FOUND` (2), `PARTIAL` (3), and `UNPROTECTED` (4), as mapped in `doctor.go`. A missing required backend is a gap; a deliberately disabled or advisory boundary does not count as protected. The honest verdicts landed in v0.8.0 (#168, `CHANGELOG.md`).

Since v0.9.0, `doctor` reports `PARTIAL` (exit 3) for Linux `CONFINED` below Landlock ABI 9 because the Unix-socket boundary is unavailable. Default `wrap` warns and records that limitation; `network.require_unix_socket_isolation = true` refuses launch instead. The ABI 9 enforcement branch has not yet run on a real kernel. See [the network boundary](network-fence.md).

`doctor` also lists deputies: more-privileged helpers the wrapped agent can ask to act for it, such as a reachable `docker.sock`, a writable shell startup file or agent config, or sudo that runs without a password prompt. Each row says whether the fence blocks it. A deputy the fence does not block keeps the verdict at `PARTIAL`; doctor fixes nothing (`internal/cli/doctor_deputies.go`). See [deputies](deputies.md).

`doctor` inspects `.env` and `.env.*` files (case-insensitive names) at
`filesystem.root` and in its immediate child directories, using the bounded,
no-symlink secret scanner. It skips `.git`, `node_modules`, `bower_components`,
`vendor`, `.venv`, `venv`, `build`, `dist`, `target`, `coverage`, `__pycache__`,
`.cache`, `.next`, `.nuxt`, `.output`, `.yarn`, and `.pnpm-store` directories.
Deeper files are outside the check's scope. The check retains the scanner's
entry/content bounds and a two-second deadline.

Secret-shaped assignments or recognized credential formats in that scope
produce a `project-dotenv` warning and `PARTIAL` (exit 3) when the other boundaries
are protected. More severe verdicts remain unchanged. An incomplete inspection
(for example, a symlink, unreadable file, or time/size limit) says `not checked`
with informational severity and does not lower the verdict. Values are never
reported, and project files remain readable. `PROTECTED` describes the configured
fences; it does not claim a full-project secret scan or absence of secrets. This
shallow heuristic is not a runtime fence.

`doctor` also looks for a personal email address the wrapped agent can read and
copy into commits or request headers; the network fence sees hostnames, not
headers. It checks the effective git `user.email` at `filesystem.root` (a
3-second bounded `git config --get`), environment variables `wrap` passes to
the child (after the secret fence and the proxy-variable strip; with the
default `secrets.pass` list only the listed variables reach the child), and `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`
and `.github/copilot-instructions.md` at the root only (first 256 KiB each).
Noreply addresses (`noreply@`, `no-reply@`, `users.noreply.github.com`) and
`example.com`, `example.org` and `localhost` are not flagged, nor is a
`user@host` followed by `:` (an scp-style git remote) or preceded by `/` (URL
userinfo). A finding is a
`personal-email` warning (`exposed`) naming the source: a masked address
(`k***@domain`) with `git user.email` or `file:line`, or only the variable name
for the environment. A git timeout or an unreadable file says `not-checked`, unless another source
already produced a finding; the warning then names what was not checked. The check
is informational and does not change the verdict or exit code; doctor changes
nothing, and deeper files are not checked (`internal/cli/doctor_email.go`).

Limit: `doctor` reports configuration and host capability, not proof that a particular session ran with every fence. Use `verify` for an active self-test and inspect that session's signed fence-state rows for evidence.

## Repo git config that runs code ("GitSpawn")
A cloned repository can set git config keys whose value is a program, and git runs it on the next `git status`, `git diff` or `git fetch`: `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, diff `textconv`, filter and merge drivers, credential helpers, `!` aliases and similar. An agent that runs git runs that program without any approval prompt of its own.

`doctor` lists each such key in the config of the repository it runs in (`.git/config`, `config.worktree` and the files they include, so `core.hooksPath` too) as a `git-config-exec` warning with the key, its value and the file it came from (`internal/cli/doctor_gitconfig.go`). It reads the config with `git config --list`, ignores your system and global config, and runs no hook. Doctor scans the repository it is run from (the current directory), which can differ from the project root that holds `.nock/`. A config git cannot parse or open (a bad line, an unreadable include) makes every git command fail with git's own error (`fatal: bad config line N`, `fatal: unable to access`), and git then runs nothing, so no program it sets can execute; doctor stays silent in that case. A config doctor cannot read (an include such as a FIFO that stalls the read past 3 seconds, or git older than 2.26) is reported as an `incomplete` `git-config-exec` warning instead of silence. The key list covers the common program-running keys, not every key git or its helpers may honor. The warning does not change the verdict or the exit code, and doctor removes nothing.

What the fence does about it is tested on Linux only. The `gitspawn-proof` job (`.github/workflows/network-egress.yml`, `internal/cli/wrap_gitspawn_linux_test.go`) plants a `core.fsmonitor` program that tries to reach a host the claude-code preset does not allow, read a file under `~/.ssh/` (denied by the preset and outside every grant, so the test does not separate the deny rule from the default deny) and write outside the project. Run unwrapped, `git status` fires it and all three succeed; that is the negative control. Under `nocklock wrap --profile claude-code --net-fence=netns -- git status`, on a GitHub-hosted Ubuntu runner with Landlock, seccomp and the netns egress floor, the program still runs and all three fail. The event log holds a signed `network_blocked` row for the host and a `file_blocked` row for each path, and `verify --audit` reports `AUTHENTIC`.

Limits: the program runs inside the fence like any other child, so it keeps everything the agent has: it can change project files, read allowed paths and send data to allowlisted hosts. Only a git run under `wrap` is fenced; git run by you, your editor or an unwrapped tool runs the program with your full rights. Proxy-mode networking (without `--net-fence=netns`) and macOS Seatbelt are not covered by this test.

## `nocklock verify`: does the fence block?
Runs an adversarial self-test through fenced child processes (`internal/cli/verify.go`, hidden `__probe` re-exec at `internal/cli/probe.go`). The report lists a result and reason for each filesystem, network, secret and syscall probe. `PASS` proves the tested operation was blocked; `SKIP` is not proof. Any failed probe, or a run with no passing probe, exits 1. A passing run with skipped probes covers only the tests that passed; read the per-probe results. Design: `.claude/design/003-verify-fence-selftest.md`.

`verify --audit`, `--against-anchor` and `--against-remote-anchor` check the audit log instead. `--export-pubkey` prints the managed public key without running a fence probe. See [audit verification](audit-log.md).

## `nocklock egress-probe`
Linux-only structured feasibility probe for the netns egress fence (`internal/cli/egress_probe.go`).

## Tests
`internal/cli/doctor_test.go`, `doctor_deputies_test.go`, `doctor_gitconfig_test.go`, `verify_test.go`, `probe_test.go`, `egress_probe_test.go`. The GitSpawn proof is `wrap_gitspawn_linux_test.go` (CI job `gitspawn-proof`).
