# Tamper-Evident Hash-Chain for the Audit Log + `nocklock verify`

> **For agentic workers:** use `superpowers:executing-plans` / TDD to implement task-by-task. Steps use `- [ ]`.

**Author:** Mira (NockLock lead) · **Date:** 2026-06-22 · **Status:** Ready to build

## Why (the moat)

NockLock's differentiator is **accountability** — agents you can *prove* were constrained. The sqlite event log (`internal/logging`) already records every fence action (secret/file/network block+pass, session). But the log is a plain table: anyone with write access to the `.db` can silently delete, alter, or reorder events, and nothing detects it. That is the gap a competitor already shipped against (hash-chain + verify). A tamper-evident, verifiable audit trail turns "we logged it" into "we can *prove* the log is intact" — the auditor-facing edge.

## What

1. Hash-chain every event so any alteration/deletion/reordering breaks the chain.
2. Add `nocklock verify` to walk the chain and report tampering (which event, what broke) with a non-zero exit on any break.

## Design — open questions ANSWERED

**Schema (migration):** add two columns to `events`:
```
prev_hash TEXT NOT NULL DEFAULT ''
hash      TEXT NOT NULL DEFAULT ''
```
On `NewLogger`, if the columns are absent, `ALTER TABLE ADD COLUMN` then **backfill the chain** over existing rows in `id` order (establishes an integrity baseline from the current log). New events continue the chain.

**Hash function:** `hash = hex(sha256(prev_hash + "\x1e" + timestamp + "\x1e" + event_type + "\x1e" + category + "\x1e" + detail + "\x1e" + strconv.FormatBool(blocked) + "\x1e" + session_id))`. Use `\x1e` (record separator) between fields so field contents can't be ambiguously concatenated. Genesis `prev_hash` = 64 zeros. The chain is **global** (a single tamper-evident log across sessions), ordered by `id`, not per-session.

**Write path (`Log` / `LogBatch`):** wrap each insert in a transaction: `SELECT hash FROM events ORDER BY id DESC LIMIT 1` → compute `hash` → `INSERT` with `prev_hash` + `hash`. **Add a `sync.Mutex` to `Logger`** (it currently has none) and hold it across the read-last-hash + insert so concurrent `Log` calls can't race the chain. `LogBatch` chains within the batch under one tx + the lock.

**`nocklock verify` (`internal/cli/verify.go`):** open the logger, walk events in `id` order, and for each assert: (a) recomputed hash == stored `hash`, and (b) stored `prev_hash` == the prior event's stored `hash` (genesis prev_hash == zeros). On the first failure, print `TAMPERING DETECTED at event id N (type=…, ts=…): <hash mismatch | broken chain link>` and exit 1. On success, print `verified N events; chain intact` and exit 0. Flags: `--db <path>` (default resolution as `log`), optional `--quiet`.

**Fail-closed nuance:** hashing is *additive integrity*, not a gate on logging. If the prev-hash read fails, still record the event (a dropped audit event is worse than an unverifiable one) — `verify` will surface any inconsistency. (This respects NockLock's fail-closed rule for the *fences* while not silently dropping *audit* records.)

## Tasks

- [ ] **T1 — Schema + migration.** Add `prev_hash`/`hash` columns; on open, detect-and-`ALTER` + backfill the chain over existing rows. Test: an old-schema DB opens, migrates, and verifies clean.
- [ ] **T2 — Hash in the write path.** Add `Logger.mu sync.Mutex`; compute + store the chain in `Log` and `LogBatch` (tx + lock). Test: hash is deterministic; consecutive events link (`event[n].prev_hash == event[n-1].hash`).
- [ ] **T3 — `VerifyChain` helper in `logging`.** `func (l *Logger) VerifyChain() (ok bool, firstBadID int64, reason string, count int)`. Tests: clean log → ok; mutate a row's `detail` → fail at that id; delete a middle row → fail (broken link).
- [ ] **T4 — `nocklock verify` command.** Wire `VerifyChain` to a cobra command with the exit-code + output contract above; register in `root.go`. Test: command exits 0 clean, 1 on tamper.
- [ ] **T5 — Concurrency + docs.** Test parallel `Log` produces a valid chain. Update `CHANGELOG.md` and the `log`/README docs to mention `verify`.

## Files
`internal/logging/logger.go`, `internal/logging/logger_test.go`, `internal/cli/verify.go`, `internal/cli/root.go`, `CHANGELOG.md`, README.

## Done = `go test ./...` green, `nocklock verify` exits 0 on a real session log and 1 after a manual row edit.
