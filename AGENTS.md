# AGENTS.md: NockLock

The contributor map lives in `CLAUDE.md`: build and test commands, invariants, and pointers into `docs/`. Read it first, then `docs/REPO-MAP.md`. This file is a pointer so the two never diverge.

Every rule the earlier AGENTS.md carried is in `CLAUDE.md`:

- Pre-push checklist (test, vet, fmt, self-review for secrets, path traversal, races, subprocess injection): `CLAUDE.md` "Pre-Push Checklist".
- Fences fail closed; actionable error messages; exported functions have doc comments; backward-compatible config: `CLAUDE.md` "Invariants".
- No new dependencies without discussion: `CLAUDE.md` "Commands" (Stack line).
- Session report for every session, docs-only included: `CLAUDE.md` "Session Closeout".

Quick commands: `go build ./cmd/nocklock`, `go test ./... -v`, `go fmt ./...`, `go vet ./...`.
