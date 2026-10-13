# Contributing to NockLock

Thanks for your interest in making AI agents safer. NockLock is open source under the MIT license, and contributions are welcome.

## Quick start

Go 1.26 or newer is required. Linux also needs a C compiler for the filesystem interposer.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/nocklock.git
cd nocklock

# Build the CLI and, on Linux, libfence_fs.so
make build-all

# Run tests and static checks
go test ./...
go vet ./...
go fmt ./...
```

Before trying a wrapped command, complete the [source installation](docs/setup.md#1-install): install the CLI, and on Linux copy `libfence_fs.so` to its trusted path. The privileged egress helper is needed only for `--net-fence=netns`. A build alone is not a complete Linux installation.

In a scratch project outside this checkout:

```bash
cd ..
mkdir nocklock-demo
cd nocklock-demo
nocklock init
nocklock wrap -- /bin/echo "hello from inside the fence"
nocklock doctor
```

On Linux below Landlock ABI 9, `doctor` returns `PARTIAL` (exit 3) because other Unix sockets remain reachable. Read the reported boundaries; see [setup and verification](docs/setup.md#3-verify). For an agent that needs provider credentials, choose its runtime preset instead of plain `init` before creating the config.

## What we're looking for

The [roadmap to 1.0](docs/ROADMAP.md) tracks the current priorities:

- Real-kernel validation of the Linux Unix-socket rules, with red-team coverage and allowed-action controls
- Complete Linux packaging and clean-host installation verification
- A tested CLI, config and exit-code compatibility contract
- Integration testing with more AI agents and performance benchmarks across supported hosts

Bug reports with reproduction steps, documentation improvements, test coverage improvements, and CI/CD improvements are always welcome. Windows is a separate feasibility effort; read [the design](docs/design/windows-feasibility.md) before proposing a backend.

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

# Built-binary integration tests (requires the platform fence prerequisites)
go test -tags=integration ./...

# Race detector
go test -race ./...

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Behavior changes need tests with allowed-action controls for each expected denial. If you are fixing a bug, write a test that reproduces it first. For documentation-only changes, verify examples, links and claims against the code.

## Project structure

Start with the [repo map](docs/REPO-MAP.md) for every package and its tests, or [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow.

- `cmd/nocklock/`: CLI entry point
- `internal/cli/`: commands and fence composition
- `internal/config/`: strict TOML loading, defaults and runtime presets
- `internal/fence/`: `fs/` (Landlock, interposer, Seatbelt), `network/` (proxy and netns), `secrets/` and `syscallfence/`
- `internal/logging/`, `internal/anchorclient/`, `internal/forward/`: signed audit state, off-box anchors and optional Command delivery
- `pkg/receipt/`: public read-only per-session audit verifier
- `integration/`, `bench/redteam/`: integration tests and attack bench
- `.nock/config.toml.example`: example configuration; `init` creates the actual project config
- `docs/`: setup, feature boundaries, reference, runbooks and designs

## Commit messages

Use conventional commits:

```
feat: add Windows job object filesystem fence
fix: proxy not closing connections on SIGTERM
docs: add macOS sandbox profile example
test: add integration tests for secret filtering
chore: update Go toolchain
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

If you find a security vulnerability in NockLock, do not open a public issue. Follow [SECURITY.md](SECURITY.md) and email security@nocktechnologies.com instead.

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

- [GitHub Issues](https://github.com/nocktechnologies/nocklock/issues) for questions, bugs and feature requests
- security@nocktechnologies.com for security issues

Thanks for helping make AI agents safer for everyone.

Nock Technologies
