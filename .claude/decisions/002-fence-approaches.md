# ADR-002: Fence Implementation Approaches

**Status:** Accepted
**Date:** 2026-04-05
**Author:** Mara (AI architect)

## Context
NockLock has three fence types. Each has multiple implementation approaches with different tradeoffs around isolation strength, platform support, and privilege requirements.

## Decisions

### Filesystem Fence: LD_PRELOAD / DYLD_INSERT_LIBRARIES
- Intercept syscalls (open, openat, stat, access, readlink) via shared library
- Check paths against allow/deny lists before passing to real syscall
- Blocked paths return ENOENT — agent doesn't know the fence exists
- Works on macOS and Linux; doesn't work on statically-linked binaries
- Claude Code (Node.js) is dynamically linked — this works

**Rejected alternatives:**
- Mount namespaces: strongest isolation, but Linux-only
- macOS sandbox profiles (`sandbox-exec`): macOS-only, limited docs, may be deprecated

### Network Fence: Local Proxy
- Start local HTTP/HTTPS proxy on random port
- Set HTTP_PROXY and HTTPS_PROXY for the agent process
- Proxy checks each request against domain allowlist
- Blocked requests return 403 or connection refused
- No root required. Cross-platform. Claude Code respects HTTP_PROXY.

**Rejected alternatives:**
- Packet filtering (pf/iptables): requires root/admin, platform-specific
- DNS interception: easy to bypass with IP addresses

### Secret Fence: Environment Variable Filtering
- Construct filtered environment when spawning child process
- Start with empty env, add only `pass` list vars, remove any `block` list matches
- Block takes precedence over pass
- Implemented via Go's `os/exec.Cmd.Env`

## Consequences
- MVP works without root/admin privileges
- Cross-platform from day one
- Can upgrade filesystem fence to mount namespaces on Linux later
- Can upgrade network fence to packet filtering later if proxy proves insufficient
