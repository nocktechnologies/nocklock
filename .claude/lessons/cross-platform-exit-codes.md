# Lesson: Cross-Platform Exit Code Handling

## Context
PR #2 review caught that `syscall.WaitStatus` is Unix-only. NockLock must work on Windows.

## What Happened
Initial implementation used `syscall.WaitStatus` to extract signal-based exit codes (128+sig convention). This compiled on macOS/Linux but failed on Windows.

## Fix
- Use `exec.ExitError.ExitCode()` which is cross-platform
- Negative exit code (signal termination on Unix, abnormal exit elsewhere) falls back to exit code 1
- Removed direct syscall dependency

## Application
- Never use `syscall.WaitStatus` or other Unix-only syscall types
- Always check Go standard library for cross-platform alternatives first
- Test CI on all platforms before merging
