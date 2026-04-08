# ADR-003: TOML for Configuration

**Status:** Accepted
**Date:** 2026-04-05
**Author:** Mara (AI architect)

## Context
NockLock needs a per-project config file (`.nock/config.toml`) that developers edit by hand.

## Decision
TOML with strict parsing (reject unknown keys).

## Rationale
- TOML is human-readable and writable, unlike JSON
- Less ambiguous than YAML (no boolean surprise, no indentation issues)
- BurntSushi/toml is the standard Go TOML library
- Rejecting unknown keys prevents typos from silently disabling fences
- A developer who types `[filesytem]` (typo) gets an error, not a wide-open fence

## Consequences
- Config file is `.nock/config.toml`
- `nocklock init` generates a default config with comments
- Unknown TOML keys are a hard error (fail closed)
- Config changes must remain backwards compatible
