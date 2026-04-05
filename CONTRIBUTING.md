# Contributing to NockLock

Thanks for your interest in making AI agents safer. NockLock is open source under the MIT license and we welcome contributions.

## Quick Start

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/nocklock.git
cd nocklock

# Build
go build -o nocklock ./cmd/nocklock

# Run tests
go test ./...

# Try it
./nocklock wrap -- echo "hello from inside the fence"
```

## What We're Looking For

**High priority — we'd love help with:**
- Windows filesystem fence implementation (job objects, minifilter)
- Linux mount namespace fence as alternative to LD_PRELOAD
- Additional network proxy features (HTTPS inspection, WebSocket support)
- Performance benchmarks across different OS and hardware
- Integration testing with more AI agents (Cursor, Copilot, Windsurf, Codex)

**Always welcome:**
- Bug reports with reproduction steps
- Documentation improvements
- Test coverage improvements
- CI/CD improvements

**Please discuss first:**
- New fence types or major architectural changes — open an issue before building
- Changes to the config format — backwards compatibility matters
- Anything that adds external dependencies

## How to Contribute

1. **Fork** the repo and create a branch from `main`
2. **Write tests** for any new functionality
3. **Run the full test suite** — `go test ./...` must pass
4. **Follow the code style** — `go fmt` and `go vet` must pass clean
5. **Write a clear PR description** — what does it do, why, how to test it
6. **One PR per feature** — keep PRs focused and reviewable

## Code Standards

- Go 1.22+ required
- All exported functions need doc comments
- Error messages should be actionable ("failed to create proxy listener on port 8080: address already in use" not "proxy error")
- No external dependencies without discussion — the CLI should stay lightweight
- Config file changes must be backwards compatible
- Fence implementations must fail closed (if the fence can't initialize, block everything, don't allow everything)

## Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires sudo on Linux for mount namespace tests)
go test -tags=integration ./...

# Race detector
go test -race ./...

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Every PR must include tests. If you're fixing a bug, write a test that reproduces it first.

## Project Structure

```
nocklock/
├── cmd/nocklock/          # CLI entry point (cobra commands)
├── internal/
│   ├── config/            # TOML config parsing
│   ├── fence/
│   │   ├── filesystem/    # Filesystem fence implementations
│   │   ├── network/       # Network proxy fence
│   │   └── secrets/       # Environment variable filtering
│   ├── logging/           # SQLite event logging
│   └── cloud/             # Optional NockCC dashboard sync
├── pkg/                   # Public API (if any)
├── testdata/              # Test fixtures
├── .nock/                 # Example config
│   └── config.toml
├── CONTRIBUTING.md
├── LICENSE                # MIT
├── README.md
└── go.mod
```

## Commit Messages

Use conventional commits:

```
feat: add Windows job object filesystem fence
fix: proxy not closing connections on SIGTERM
docs: add macOS sandbox profile example
test: add integration tests for secret filtering
chore: update Go to 1.22.3
```

## Reporting Bugs

Open an issue with:
- OS and version (macOS 15.x, Ubuntu 24.04, Windows 11, etc.)
- Go version (`go version`)
- NockLock version (`nocklock version`)
- What you expected to happen
- What actually happened
- Steps to reproduce
- Config file (redact any secrets)

## Security Issues

If you find a security vulnerability in NockLock, **do not open a public issue.** Email security@nocktechnologies.com instead. We take security seriously — this is literally a security tool.

## Feature Requests

Open an issue tagged `enhancement`. Include:
- What problem does this solve?
- Who benefits from this?
- How should it work from the user's perspective?

We're more likely to accept features that align with the core philosophy: invisible fences that prevent escape, not guardrails that constrain behavior.

## Code of Conduct

Be respectful. Be constructive. We're all here to make AI agents safer. If you wouldn't say it in a code review with a colleague you respect, don't say it here.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- GitHub Discussions for general questions
- GitHub Issues for bugs and feature requests
- security@nocktechnologies.com for security issues

Thanks for helping make AI agents safer for everyone.

— Nock Technologies
