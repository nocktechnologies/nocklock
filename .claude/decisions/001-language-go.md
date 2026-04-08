# ADR-001: Use Go for NockLock

**Status:** Accepted
**Date:** 2026-04-05
**Author:** Mara (AI architect)

## Context
NockLock needs to be a cross-platform CLI that wraps AI coding agents with security fences. The language choice affects distribution, development speed, and ecosystem access.

## Decision
Go, not Rust.

## Rationale
- **Single binary distribution.** `go build` produces one static binary. No runtime dependencies. Drop it in PATH and it works.
- **Cross-compilation is trivial.** `GOOS=darwin GOARCH=arm64 go build` gives us all platforms from one CI pipeline.
- **Ecosystem fits.** Go has mature libraries for process management (os/exec), filesystem operations (os, filepath), network interception (net, syscall), and CLI tooling (cobra).
- **Kevin can read Go.** Closer to Python than Rust. He should be able to follow the code and explain the product.
- **Speed is sufficient.** The fence wraps a CLI command. Go vs Rust overhead is microseconds; agent sessions run minutes to hours.

## Tradeoffs
- Rust would be technically superior for the network interception layer (lower-level syscall access).
- If we need Rust for specific components later (network fence kernel), we can write that piece in Rust and call it from Go via CGO.

## Consequences
- All NockLock code is Go
- CI targets: macOS (ARM + Intel), Linux (AMD64 + ARM64), Windows (AMD64)
- Developers need Go 1.22+ to contribute
