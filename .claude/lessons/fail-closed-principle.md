# Lesson: Fences Fail Closed

If a fence can't initialize, it must block everything — not silently pass through.

## Context
This is a security tool. The worst failure mode is one where the user thinks they're protected but the fence is actually not running. Every fence implementation must default to deny if initialization fails.

## Examples
- Config file has a typo → hard error, don't run the agent with no fences
- LD_PRELOAD fails to load → error out, don't run unprotected
- Proxy can't bind a port → error out, don't run without network fence
- Unknown TOML key → parse error, not silent ignore

## Application
- All new fence code must have an initialization check
- If init fails, return an error — never fall back to passthrough
- Tests should verify that broken initialization blocks execution
