# Optional public timestamp over the v2 snapshot digest

Status: design for Nock N11768. Nothing here changes runtime behavior and no code is added. The timestamp is opt-in. No calendar request is made unless the operator explicitly enables it.

## Problem

A NockLock v2 anchor proves a chain state to anyone who holds the signing public key, the expected `(agent_id, chain_id)` pair, and the remote store's history. It does not prove to an outside party that a given audit state existed at a given time. The remote store is operated by us or by a host we chose, so it is not an outside witness. Nothing outside our systems can currently show that a state existed before a later date.

This design adds one optional step: submit the existing v2 snapshot digest to a public timestamping service and keep the returned receipt next to the anchor. It does not add a Merkle tree, a new signature, a new anchor field, or a new record format. The stamped object is the digest that the code already computes and already verifies.

Related: [remote anchor chain identity](anchor-chain-identity.md) (the v2 record and pair rules) and [ADR-007](../decisions/007-audit-log-chain-signature-anchor.md) (the audit log chain and signature anchor).

## The digest being stamped

Source: `internal/logging/anchor_v2.go`.

- `AnchorV2SnapshotDigest(a, pub, expectedAgentID, expectedChainID)` first calls `VerifyAnchorV2`. It returns an error and no digest if the signature, the public key fingerprint, the canonical fields, or the expected pair fails. Only a verified record gets a digest.
- It then calls `anchorSnapshotDigest("nocklock-anchor-snapshot-v2\x00", cb, sig)`, where `cb` is `AnchorV2CanonicalBytes(a)` and `sig` is the 64 decoded Ed25519 signature bytes.
- `anchorSnapshotDigest` is `SHA-256(domain || cb || sig)` and returns 64 lowercase hex characters.

The exact input to SHA-256, in order:

1. The ASCII string `nocklock-anchor-snapshot-v2`, followed by one NUL byte (`0x00`).
2. The v2 canonical signed bytes: `0x06 || u32be(len(agent_id)) || agent_id || chain_id[32] || head_hash[32] || u64be(row_count) || u32be(len(created_at)) || created_at || legacy_anchor_digest[32]`.
3. The 64 decoded Ed25519 signature bytes (not the base64 text).

JSON whitespace, field order, and accepted base64 spelling do not change the digest. The v1 digest (`nocklock-anchor-snapshot-v1`, `LegacyAnchorSnapshotDigest`) is a separate function and is not used here.

## Exact bytes submitted

The stamped object is the 32 raw bytes of the SHA-256 output, not the 64-character hex text.

This is the only submitted object. Nothing else from the audit database, the anchor JSON, the key file, or the host is sent.

The reference client is the OpenTimestamps `ots` tool (opentimestamps-client, installed in a throwaway virtual environment). Its `ots stamp --help` lists only `FILE` arguments, calendar options, and timeout options. There is no digest option for `stamp`. The `-d DIGEST` option exists only for `ots verify`. In `otsclient/cmds.py` the stamp command hashes the file with SHA-256, adds a random 16-byte nonce, hashes again, and sends that value to the calendars.

So the client cannot stamp the 32 raw bytes as the leaf. The specified form is a file. Let `D` be the 32 raw digest bytes:

- File content equals `D`: the 32 raw bytes, no newline, no hex, no header.
- `ots stamp file` commits to `SHA-256(file)`, which equals `SHA-256(D)`. It does not commit to `D`. The receipt's file digest (the `File sha256 hash` line of `ots info`) is `SHA-256(D)`.
- This adds one hash layer. A verifier must compare the receipt's file digest with `SHA-256(D)`, never with `D`.

Relation for each form: file form (the form used in the example below), receipt digest = `SHA-256(D)`. Raw-digest form (not available, because the client has no way to stamp it), receipt digest would equal `D`.

## Three states

Each OpenTimestamps receipt (the reference service) is pending, upgraded, or verified. Each proves less than the next, and none proves that the audit state was valid.

**Pending.** A calendar server acknowledged the submission and will anchor it in Bitcoin later. A pending receipt (`PendingAttestation`) holds only the calendar URI. It has no signature and no time.

- Proves: nothing to a third party. It is a pointer that a later `ots upgrade` uses to fetch the Bitcoin proof from that calendar.
- Does not prove: when the submission happened, or that the calendar saw it. Only the operator's own submission log records when it was submitted. The receipt has no Bitcoin content.

**Upgraded.** The receipt now holds a Merkle path from `SHA-256(D)` to a Bitcoin block header. The `ots upgrade` step fetches this path from the calendar.

- Proves: `SHA-256(D)` existed no later than the timestamp of the Bitcoin block that commits to it. Block time is approximate, usually to within hours.
- Does not prove: the Merkle path is correct until the verifier checks it against a block header from a source it trusts. Until then the calendar is still in the trust chain.

**Verified.** The verifier checks the Merkle path against a Bitcoin block header from a source it trusts, such as its own node or a trusted header source.

- Proves: `SHA-256(D)` existed no later than that block. This removes the calendar from the trust chain for the existence claim.
- Does not prove: that the digest was a valid audit state, that the audit log was complete, or that the signing key was not compromised.

**Calendar acceptance is not Bitcoin confirmation.** Pending is not upgraded, and upgraded is not verified. Show the state in every report.

### What a timestamp does not do

Only an upgraded receipt proves that `SHA-256(D)` existed at a time. It does not prove that the audit state behind it was valid. A verifier must still:

1. Load the anchor record and its public key.
2. Run `AnchorV2SnapshotDigest` with the expected `(agent_id, chain_id)` pair. This checks the signature, the fingerprint, the canonical fields, and the pair.
3. Recompute `D`, the 32 digest bytes, and compute `SHA-256(D)`.
4. Check that the receipt's file digest equals `SHA-256(D)`. Comparing it with `D` fails by design, because of the extra hash layer.

Without steps 1 to 4 the timestamp binds nothing to a specific audit state.

## Opt-in and disclosure

Proposed control: an explicit flag on the anchor command, `--public-timestamp`. An environment variable (for example `NOCKLOCK_PUBLIC_TIMESTAMP=1`) is not enough by itself and must not be the only switch. Both the default and the absence of the flag mean off.

Requirements (design, not yet implemented):

- With the switch off, no command contacts a calendar. This includes `wrap` teardown, `anchor emit`, `anchor push`, and `verify`.
- With the switch on, the calendar request happens only in the command that asked for it. It is not a background retry, and a failed request is reported, not hidden.
- The receipt is written beside the anchor file, never inside the audit database.

What leaks when the switch is on:

- Only the 32-byte digest is in the request body.
- The calendar operator, and any network observer on the path, can see the client IP address, TLS metadata, the time of the request, and the client's user agent. Transport metadata is visible even though the body is only a digest.
- The digest is a deterministic function of the public anchor record. Anyone who holds that record can recompute the digest and link it to the stamp. The digest does not hide the record.

## Deferred: compact Merkle inclusion export

Not part of this design. A compact export of a Merkle inclusion proof for a single audit row would let a consumer check a row without calling the calendar. Defer it until a named consumer needs to verify a row without the calendar. Until then, the timestamp covers the digest only.

## Worked manual example

The example uses the synthetic fixture `valid_chain_a` in `internal/logging/testdata/anchor-v2/vectors.json`. That file holds public keys, records, signatures, and hashes only. It is a repo test vector. It is not an audit log, and nothing here comes from a real NockLock state.

### Step 1: compute and check the digest

Run from the repository root:

```
python3 -I -c 'import json,base64,hashlib,sys; d=json.load(open(sys.argv[1])); c=[x for x in d["cases"] if x["name"]=="valid_chain_a"][0]; cb=bytes.fromhex(c["canonical_hex"]); sig=base64.b64decode(c["anchor"]["sig"]); print(hashlib.sha256(b"nocklock-anchor-snapshot-v2\x00"+cb+sig).hexdigest(), "pinned", c["snapshot_digest"])' internal/logging/testdata/anchor-v2/vectors.json
```

Output observed when this document was written:

```
be1b3e04aef5b071f2f7ab6596253626ec6149cf22420d374576e5b5f5945d84 pinned be1b3e04aef5b071f2f7ab6596253626ec6149cf22420d374576e5b5f5945d84
```

The recomputed digest equals the pinned `snapshot_digest` in the fixture. The Go test `TestAnchorV2PublicVectors` in `internal/logging/anchor_v2_test.go` checks the same vectors through the Go code.

### Step 2: the file form to stamp

Write the 32 raw digest bytes to a file, with no newline:

```
python3 -I -c 'import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(sys.argv[1]))' be1b3e04aef5b071f2f7ab6596253626ec6149cf22420d374576e5b5f5945d84 > digest.bin
```

Check that it is 32 bytes: `wc -c digest.bin` should print `32 digest.bin`.

### Step 3: submit, then inspect

Submitted on 2026-10-17 at 05:46:51 UTC with `opentimestamps-client` and the client's default calendars. Only `digest.bin` (the 32 digest bytes of the public fixture) was given to the client.

```
$ ots -v stamp digest.bin
Doing 2-of-4 request, timeout is 5 seconds
Submitting to remote calendar https://a.pool.opentimestamps.org
Submitting to remote calendar https://b.pool.opentimestamps.org
Submitting to remote calendar https://a.pool.eternitywall.com
Submitting to remote calendar https://ots.btc.catallaxy.com
1.73 seconds elapsed
```

The command finished at 05:46:53 UTC and wrote `digest.bin.ots` (875 bytes). The receipt holds the leaf hash, the nonces and hash steps, and the calendar URLs. It holds no host data. A copy is at [examples/valid_chain_a.ots](examples/valid_chain_a.ots).

All four default calendars accepted the digest. The receipt carries four pending attestations (the four pool hostnames above resolve to these calendar servers):

```
$ ots info digest.bin.ots
File sha256 hash: 9d3fc018bdf5a33ad8e8278225003ec12f02198822a81e7965302dd85b4a5741
Timestamp:
...
    verify PendingAttestation('https://btc.calendar.catallaxy.com')
...
    verify PendingAttestation('https://bob.btc.calendar.opentimestamps.org')
...
    verify PendingAttestation('https://finney.calendar.eternitywall.com')
...
    verify PendingAttestation('https://alice.btc.calendar.opentimestamps.org')
```

Form used: the file form. The leaf is `SHA-256(D)`, not `D`. `sha256sum digest.bin` prints `9d3fc018bdf5a33ad8e8278225003ec12f02198822a81e7965302dd85b4a5741`, which equals the `File sha256 hash` line. The digest `D` itself (`be1b3e04...5d84`) does not appear as the receipt's file digest.

```
$ ots verify digest.bin.ots
Assuming target filename is 'digest.bin'
Calendar https://btc.calendar.catallaxy.com: Pending confirmation in Bitcoin blockchain
Calendar https://bob.btc.calendar.opentimestamps.org: Pending confirmation in Bitcoin blockchain
Calendar https://finney.calendar.eternitywall.com: Pending confirmation in Bitcoin blockchain
Calendar https://alice.btc.calendar.opentimestamps.org: Pending confirmation in Bitcoin blockchain
```

The exit code was 1, as expected for a receipt with no Bitcoin attestation.

**State: pending.** This is calendar acceptance, not Bitcoin confirmation. The receipt holds only the four calendar URIs. It proves nothing to a third party until it is upgraded. The submission time above comes from the operator's own log.

To upgrade later, run this in the directory that holds the receipt, once the calendars have committed to a Bitcoin block (usually some hours after submission):

```
ots upgrade digest.bin.ots    # replaces pending attestations with a Bitcoin block attestation
ots verify digest.bin.ots     # checks the path against a Bitcoin source you trust
```

An upgrade that reports no Bitcoin attestation means the calendar has not committed the digest yet, and the receipt stays pending. This repository stores the pending receipt only. When an upgraded receipt exists, record its state, the Bitcoin block height and hash, and the verifier's header source here.

Record for this example:

- Digest submitted (inside `digest.bin`): `be1b3e04aef5b071f2f7ab6596253626ec6149cf22420d374576e5b5f5945d84`
- Leaf in the receipt (`SHA-256(D)`): `9d3fc018bdf5a33ad8e8278225003ec12f02198822a81e7965302dd85b4a5741`
- Receipt: `docs/design/examples/valid_chain_a.ots`, pending

## Test plan (for the implementation PR, not this one)

- A Go test recomputes `AnchorV2SnapshotDigest` (or the domain-plus-bytes formula) for every successful case in `vectors.json` and compares it with `snapshot_digest`.
- A test confirms that a record failing `VerifyAnchorV2` produces no digest and no stamp.
- A test with the switch off asserts that no calendar client is constructed and no socket opens, including on `wrap` teardown.
- A round-trip test writes the 32-byte file and checks that the receipt's file digest equals `SHA-256(D)` and does not equal `D`.
