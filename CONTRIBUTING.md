# Contributing to NockLock

Thanks for your interest in making AI agents safer. NockLock is open source under the MIT license, and contributions are welcome.

## Quick start

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

## What we're looking for

The areas where help would matter most right now:

- Windows filesystem fence implementation (job objects, minifilter)
- Linux mount namespace fence as an alternative to LD_PRELOAD
- Additional network proxy features (HTTPS inspection, WebSocket support)
- Performance benchmarks across different OS and hardware
- Integration testing with more AI agents (Cursor, Copilot, Windsurf, Codex)

Bug reports with reproduction steps, documentation improvements, test coverage improvements, and CI/CD improvements are always welcome.

Some changes need a conversation first. Open an issue before building a new fence type or making a major architectural change. Changes to the config format need discussion because backwards compatibility matters, and so does anything that adds an external dependency.

## How to contribute

1. Fork the repo and create a branch from `main`.
2. Write tests for any new functionality.
3. Run the full test suite; `go test ./...` must pass.
4. Follow the code style; `go fmt` and `go vet` must pass clean.
5. Write a clear PR description: what it does, why, and how to test it.
6. Keep each PR to one feature, so it stays focused and reviewable.

## Code standards

Go 1.26 or newer is required. All exported functions need doc comments. Error messages should tell the reader what to do about them: "failed to create proxy listener on port 8080: address already in use" rather than "proxy error". Do not add external dependencies without discussion; the CLI should stay lightweight. Config file changes must be backwards compatible. Fence implementations must fail closed: if a fence cannot initialize, block everything rather than allow everything.

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

Every PR must include tests. If you are fixing a bug, write a test that reproduces it first.

## Project structure

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

## Commit messages

Use conventional commits:

```
feat: add Windows job object filesystem fence
fix: proxy not closing connections on SIGTERM
docs: add macOS sandbox profile example
test: add integration tests for secret filtering
chore: update Go to 1.22.3
```

## Reporting bugs

Open an issue with:

- OS and version (macOS 15.x, Ubuntu 24.04, Windows 11, etc.)
- Go version (`go version`)
- NockLock version (`nocklock version`)
- What you expected to happen
- What actually happened
- Steps to reproduce
- Config file (redact any secrets)

## Security issues

If you find a security vulnerability in NockLock, do not open a public issue. Email security@nocktechnologies.com instead.

## Feature requests

Open an issue tagged `enhancement`. Include:

- What problem does this solve?
- Who benefits from this?
- How should it work from the user's perspective?

The project is about fences that prevent escape. Features that fit that approach are the most likely to be accepted. Features that add guardrails to constrain the agent's behavior are a harder sell.

## Code of conduct

Be respectful and constructive. Everyone here wants to make AI agents safer.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions

- GitHub Discussions for general questions
- GitHub Issues for bugs and feature requests
- security@nocktechnologies.com for security issues

Thanks for helping make AI agents safer for everyone.

Nock Technologies
