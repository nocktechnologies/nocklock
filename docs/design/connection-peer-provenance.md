# Signed Linux connection-peer provenance

N11762 is a Tier 2 audit-path change, implemented on `next` for the next release.
It records connection provenance; it makes no new authorization or activity
recording claim.

## Capture and trust boundary

At the start of each accepted connection's goroutine, before parsing frames,
the collector reads `SO_PEERCRED` inside `UnixConn.SyscallConn().Control`. No raw descriptor escapes
that callback. Linux reports credentials in effect at connection time; reading
them after accept does not turn them into per-frame credentials. The collector
then makes a separate, best-effort `/proc/<pid>/exe` read. It captures one value
snapshot before starting the frame parser and reuses that snapshot on all frames.
A slow capture delays only that connection, not the shared accept loop; the
procfs read itself has no context deadline.

The child controls the report, including operation, path, reason and timestamp.
Private Go fields hold the collector snapshot outside the JSON decoding surface;
the parser attaches it after decoding. It cannot be replaced by similarly named
child JSON. Reports can still be fabricated, and a passed/inherited socket can
have another writer. PID/UID/GID are interpreted in the collector's namespaces;
no host-global identity is promised. Exec, process exit, PID reuse and namespace
or procfs restrictions can invalidate any inferred relationship between the
connection and the later executable path. No executable digest is computed.

Credential lookup failures keep the denial report and explicitly omit numeric
credentials. PID zero or an unavailable credential result never becomes an
apparent root identity. Legitimate UID/GID zero remain explicit. Executable
lookup failures omit the path rather than claiming an empty successful result.

## Signed detail format

Both existing event routes use `FenceEvent.Detail()` via `fileBlockedDetail`:
ordinary channel logging uses `Log`; synchronous look-back handling uses
`LogImmediate` before its ACK. Event type, blocked flag, look-back policy,
malformed-frame behavior and ACK ordering are unchanged.

```json
{"version":1,"report":{"type":"fs","action":"blocked","path":"/example","operation":"open","reason":"denied path","timestamp":"child claim"},"connection_peer":{"credentials_status":"captured","credentials":{"pid":123,"uid":1000,"gid":1000},"executable":{"status":"observed","path":"/usr/bin/example"}}}
```

When credential lookup fails, `credentials_status` is `unavailable`, the
`credentials` object is absent, and executable status is `credentials_unavailable`.
When only procfs lookup fails, credentials remain captured and executable status
is `unavailable` with no path. `observed` means only that a nonempty readlink
result was returned after accept; it is not authenticated executable identity.

This is JSON inside the existing signed detail string, not a row/signature
format migration. Existing rows are never rewritten, backfilled or re-signed.
Manually constructed events without a collector snapshot keep the old text
formatter. macOS kernel-denial and unrelated network detail formats are unchanged.

## Validation contract and limits

- Portable parser tests inject collector snapshots into real `net.Pipe` frame
  handling. Both dispatch paths reject child identity spoofing, preserve valid
  zero credentials and malformed-frame behavior, and still deliver reports when
  credentials are unavailable. These tests do not execute Linux `SO_PEERCRED`.
- Both routes append signed envelope rows after an old-format signed row. The
  mixed trail verifies, the old row hash/signature stay byte-identical, and
  changing collector identity in the stored detail fails verification.
- Linux-only ordinary tests use real Unix-stream connections without root or
  fences. They assert connector PID/UID/GID and pass the connection to a second
  process, proving repeated frames keep the connector snapshot rather than
  identifying the later writer. A closed socket exercises credential failure.
- The local macOS builder runs the portable tests, full native suite and focused
  race checks, plus Linux cross-vet/build. Cross-checking does not establish Linux
  runtime behavior; the normal hosted Linux test job must execute the real
  socket tests. No local root/kernel probe is needed for this change.
- A portable listener test holds the first connection's capture until a second
  connection is accepted, reported and acknowledged. It then releases the first
  connection and proves it still works; all I/O and cleanup waits are bounded.
- The red-team bench accepts legacy text and validated version 1 file reports,
  matching reason/operation rules against their named report fields and path
  matches against report.path. Collector fields never supply action proof, and
  receipts retain the original signed detail bytes. Malformed/unsupported
  envelopes and wrong-field spoof controls are rejected by the existing Python
  unittest entry point; final hosted acceptance must confirm all four file rows.

Security review focuses on the collector/report namespace boundary, fd lifetime,
failure statuses, signed-detail integrity, retained legacy signatures and bounded
test cleanup. A negative-control overlay bypasses the collector attachment with
child-supplied peer data and must fail the portable spoof test. The existing
recording and signature limits in the [audit guide](../how-it-works/audit-log.md)
remain in effect.
