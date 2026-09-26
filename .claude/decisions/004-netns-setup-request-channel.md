# ADR-004: netns setup request travels in a file, not on stdin

**Status:** Accepted
**Date:** 2026-09-26
**Author:** Beck (AI builder), N10711

## Context
Under `nocklock wrap --net-fence=netns`, the unprivileged parent hands the
composed child (argv, env, credential, egress config) to the privileged helper
via `sudo -n <helper> setup`. The request was JSON-encoded onto the helper's
**stdin**. That consumed the caller's stdin: the fenced child — reached several
processes deep (wrap → sudo → setup helper → `__netns-child` sidecar → child) —
inherited a drained stdin, so `printf 'x' | nocklock wrap --net-fence=netns -- cat`
printed the setup JSON (or nothing), and interactive/MCP agents lost their input
stream entirely. The helper's own doc comment carried this as a known
"FOUNDATION LIMITATION."

The obvious fix — pass the JSON on a dedicated inherited descriptor (fd 3) and
leave stdin alone — does not survive the `sudo` boundary: sudo's default
`closefrom=3` closes every descriptor ≥ 3 before exec'ing the helper, and
`closefrom_override` (`sudo -C`) is not permitted under the shipped policy
(verified empirically on the target host). Env vars are also stripped by
`env_reset`. Across sudo only fd 0/1/2 and argv survive, and argv is pinned to
the fixed `check`/`setup` sudoers vectors.

## Decision
- **Helper leg (wrap → sudo → setup):** wrap writes the JSON request to a fresh
  **0600 file** in the wrap-owned, 0700 per-session directory and invokes
  `sudo -n <helper> setup --request-file <path>`. Only the *path* rides argv. The
  sudo command inherits the caller's real stdin (`cmd.Stdin = os.Stdin`); the
  helper reads the request from the file — never stdin — so stdin flows through to
  the child untouched (a real TTY stays a TTY). The helper opens the file
  `O_NOFOLLOW`, requires a regular 0600 file owned by `SUDO_UID`, and unlinks it
  after read. `validateChildCredential` remains the real credential boundary; the
  file checks are defense-in-depth and a fail-closed setup channel.
- **Sidecar leg (setup → `__netns-child` / proxies):** no sudo here, so the JSON
  payload rides a **dedicated inherited descriptor (fd 3)** via `ExtraFiles`
  (matching the existing cleanup/watchdog pattern). The `__netns-child` sidecar
  inherits the helper's stdin (the caller's real stdin); the two policy proxies
  get `/dev/null`. Every sidecar fails closed if fd 3 is absent.

## Rationale
- The file+path split is the only channel that both survives `sudo` and keeps the
  request off argv — the request's argv/env/credential still never ride the sudo
  argument vector, so the sudoers policy stays a fixed vector, not an
  argument-injection surface. Only a small, owner-validated path token is added.
- No new `netns.Request` field is introduced, so the darwin mirror
  (`helper_other.go`) is untouched.
- Fence semantics are unchanged: same namespace, cap drop, credential drop,
  NO_NEW_PRIVS, and audit chain.
- Deferred (out of scope for N10711): a persistent privileged helper reached over
  a unix socket with `SCM_RIGHTS` fd-passing — instead of a fresh `sudo` exec per
  session — could collapse both legs onto a single channel and hand the child's
  real stdin fd across directly. That is a larger architectural change to the
  helper's lifecycle and sudoers model; recorded here so the option stays visible.

## Consequences
- **SUDOERS POLICY CHANGE (host installer):** the NOPASSWD grant must permit
  `setup --request-file *` in place of bare `setup`. Document this with the helper
  install.
- Both legs fail closed if their setup channel cannot be established (missing/bad
  request file; missing fd 3), covered by negative-control unit tests.
- Acceptance (privileged CI only): `printf 'hello\n' | nocklock wrap
  --net-fence=netns -- cat` prints `hello`; a PTY test shows an interactive child
  reads keystrokes; existing netns tests stay green.
- **Stdin parity, not new job control:** the child inherits the caller's stdin
  *fd* unchanged (TTY or pipe), reaching parity with a directly-run wrapped agent
  (`cli/wrap.go` sets `child.Stdin = os.Stdin` + `Setpgid` for the non-netns path
  too). This change adds no terminal job-control handling (no `setsid`, `Ctty`,
  `Foreground`, or `tcsetpgrp`) — foreground-process-group / SIGTTIN behavior is
  identical to the rest of the product and is out of scope for N10711.
- **Grant drift is not auto-detected:** the runtime preflight probes only the
  unchanged `check` vector, so a host that upgrades the binary but not the sudoers
  grant passes preflight and fails later at child launch with sudo's generic
  denial. No safe non-mutating runtime probe distinguishes "vector not permitted"
  from "helper ran and refused" (`sudo -l` may itself require a password under a
  NOPASSWD-only policy, yielding false negatives), so the required grant update is
  surfaced via the installer, README, and CHANGELOG rather than a runtime check.
