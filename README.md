# nocklock

AI agent security fence. Prevent your coding agents from escaping their sandbox.

## The Problem

AI coding agents (Claude Code, Cursor, Copilot, Windsurf) run with full access
to your filesystem, network, and environment variables. One prompt injection,
one hallucinated command, one bad dependency — and your agent can:

- Read your SSH keys and AWS credentials
- Exfiltrate code to external servers
- Delete files outside the project directory
- Access production databases
- Push to repos it shouldn't touch

## The Solution

NockLock wraps your agent in an invisible fence. Three boundaries:

- **Filesystem fence** — agent can only read/write inside the project directory
- **Network fence** — agent can only reach approved domains (GitHub, npm, PyPI)
- **Secret fence** — agent only sees environment variables you explicitly allow

Zero config defaults. The fence is invisible until something hits it.

> **Current status:** All three fences are active. The secret fence, filesystem fence
> (Linux via LD_PRELOAD), and network fence (local HTTP/HTTPS proxy) are working.
> NockLock MVP is complete.

## Install (from source)

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
go build -o nocklock ./cmd/nocklock
```

## Usage

```bash
# Initialize fence config in your project
cd my-project
nocklock init

# View your config
nocklock config

# Wrap your agent with all three fences active
nocklock wrap -- claude --dangerously-skip-permissions

# Check version
nocklock version
```

## What It Will Look Like (once fences are active)

```
$ nocklock log
2026-04-05 02:14:33 | filesystem | BLOCKED | open ~/.ssh/id_rsa
2026-04-05 02:14:35 | network    | BLOCKED | CONNECT evil.com:443
2026-04-05 02:15:01 | secret     | BLOCKED | env AWS_SECRET_ACCESS_KEY
2026-04-05 02:15:44 | filesystem | allowed | open src/main.py
```

Your agent never knew the fence was there. You sleep better at night.

## Filesystem Fence

The filesystem fence uses **LD_PRELOAD** to intercept libc file-system calls
(open, rename, unlink, etc.) before they reach the kernel. A thin C shared library
(`libfence_fs.so`) checks every path against the configured allow/deny rules and
blocks access outside the project directory tree.

### Config Example

```toml
[filesystem]
root = "~/projects/my-app"
mode = "read-write"            # or "read-only"
allow = ["~/.config/gh"]       # extra paths (read-only)
deny  = ["~/.ssh", "~/.aws"]   # always blocked, overrides allow
```

### Build

```bash
make build-fence-fs    # builds internal/fence/fs/interposer/libfence_fs.so
make build-all         # builds Go binary + C shared library
```

### How It Works

- NockLock spawns the child process with `LD_PRELOAD` pointing at `libfence_fs.so`
- The library intercepts 27 libc functions including `open`, `openat`, `fopen`, `access`, `unlink`, `rename`, `mkdir`, `rmdir`, `readlink`, `realpath`, `symlink`, `link`, `chmod`, `chown`, `truncate`, `creat`, and their `*at`/64-bit variants
- Every intercepted path is resolved with `realpath` (symlink-safe) and checked against the allow/deny rules
- Blocked calls return `EACCES` and report events over a Unix domain socket
- Events are logged to SQLite and visible via `nocklock log`

### Known Limitations

- **Environment variable protection:** The wrapped process can call `unsetenv("LD_PRELOAD")` and spawn unfenced subprocesses. This is inherent to LD_PRELOAD-based sandboxing. Future versions may intercept `execve` to re-inject the preload.
- **TOCTOU races:** A time-of-check-to-time-of-use window exists between path resolution and the actual syscall. Kernel-level sandboxing (seccomp, landlock) can eliminate this in a future PR.
- **LD_PRELOAD ordering:** If the wrapped process has its own `LD_PRELOAD` libraries, they sit between the fence and glibc and could theoretically intercept `realpath` to lie about path resolution. The fence library is always placed first in the chain.
- **stat/lstat:** Not currently intercepted. The primary attack surface (file read/write/create/delete) is covered.

### Platform Support

| Platform | Status |
|----------|--------|
| Linux    | Supported (LD_PRELOAD) |
| macOS    | Coming soon (DYLD_INSERT_LIBRARIES) |
| Windows  | Not planned |

## Network Fence

The network fence starts a local HTTP/HTTPS proxy on `127.0.0.1:<random-port>` and injects
proxy environment variables into the child process. Every outbound request is checked against
the domain allowlist before being forwarded.

### Config Example

```toml
[network]
allow = [
    "github.com",           # also matches *.github.com
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
]
allow_all = false           # set true to disable the fence
```

### How It Works

- `nocklock wrap` starts a local proxy and sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` in the child's environment
- `NO_PROXY`/`no_proxy` are explicitly removed to prevent bypass
- For HTTP requests: proxy checks the destination hostname and either forwards or returns 403
- For HTTPS requests: proxy inspects the hostname from the HTTP CONNECT request — **no MITM, no certificate injection, encrypted payload is never decrypted**
- Raw IP addresses are blocked (fail closed — no reverse DNS lookup)
- If the proxy fails to start, the agent still runs but unfenced (logged as `network_error`)

### Domain Matching

| Rule | Matches |
|------|---------|
| `"github.com"` | `github.com`, `api.github.com`, `*.github.com` |
| `"*.example.com"` | `sub.example.com` but **not** `example.com` |
| Raw IP `1.2.3.4` | Always blocked |

### Platform Support

| Platform | Status |
|----------|--------|
| Linux    | Supported |
| macOS    | Supported |
| Windows  | Supported |

## Roadmap

- [x] CLI skeleton + config system (PR #1)
- [x] Secret fence — environment variable filtering (PR #3)
- [x] SQLite event logging (PR #4)
- [x] Filesystem fence — LD_PRELOAD interception (PR #6)
- [x] Network fence — local proxy with domain allowlist (PR #7)
- [ ] Homebrew tap + CI (PR #8)

## Dashboard (Coming Soon)

Connect to [NockCC](https://nocktechnologies.io) for cloud monitoring:
- See fence events across all your machines
- Get Telegram/Slack alerts on blocked escape attempts
- Team visibility — know what every developer's agents are doing

## License

MIT
