# Changelog

All notable changes to NockLock will be documented in this file.

## [Unreleased]

### Added
- Filesystem fence via LD_PRELOAD — intercepts file system calls on Linux, blocks access outside allowed directory tree (PR #6)
- C shared library (`libfence_fs.so`) intercepts 27 libc functions with symlink-safe path resolution
- Filesystem config: `root`, `mode` (read-write/read-only), `allow`, `deny` with tilde expansion
- Deny list takes priority over allow list; allow list is read-only
- Fence events reported over Unix domain socket and logged to SQLite
- Linux-only guard with clear macOS error message
- `build-fence-fs` and `build-all` Makefile targets
- Standardized repo with `.claude/` directory, Mermaid architecture diagrams, DESIGN.md, review pipeline
- ARCHITECTURE.md documenting package structure and data flow
- Architecture Decision Records (ADRs) in `.claude/decisions/`
- Lessons learned docs in `.claude/lessons/`
- Review pipeline (`.claude/review/PIPELINE.md`) — 7-phase process

## [0.1.0] — 2026-04-06

### Added
- CLI skeleton: `wrap`, `init`, `config`, `log`, `status`, `version` commands (PR #1, #2)
- TOML config parsing with strict validation (reject unknown keys)
- `nocklock init` creates `.nock/config.toml` with security-first defaults
- `nocklock wrap` passes through to child process (fences coming in PR #3-6)
- Cross-platform exit code handling (no Unix-only syscall dependencies)
- Makefile with build, test, lint targets
- Default config: deny `~/.ssh/`, `~/.aws/`, `~/.gnupg/`; block `AWS_*`, `*_SECRET*`, `*_TOKEN*`
