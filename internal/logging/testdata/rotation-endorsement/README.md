# Rotation endorsement public vectors

`vectors.json` uses envelope `nocklock-rotation-endorsement-test-vectors-1`,
following the anchor-v2 fixture envelope style. It contains public material only.
The format and trust limits are in
[the design](../../../../docs/design/rotation-endorsement.md).

Each `cases` entry has a `name`, `bundle`, trusted `expected` inputs and
`expected_result`. `canonical_hex`, `endorsement_digest` and
`acceptance_canonical_hex` pin the exact bytes and hashes when encoding permits.
They do not themselves imply validity. `transport_hex`, when present, supplies
raw JSON bytes instead of `bundle`, including malformed UTF-8 and duplicate
fields that cannot be represented in an ordinary JSON object. A null `bundle`
without transport, or whitespace-only transport, represents an absent
endorsement.

Results are `valid`, `root_mismatch`, `identity_mismatch`, `tail_mismatch`,
`replay`, `missing`, `unused`, `bad_signature` or `malformed`. Each reject's
`positive_control` names the entry that accepts when its single changed field
(or transport spelling) is restored. `valid_independent_root` has a first-key
root distinct from both retiring and successor fingerprints;
`valid_first_rotation` uses the retiring key's own fingerprint as the root.
Other accepts pin zero, 2^53 and maximum uint64 counts. Reject names enumerate each mutation.

The test-only signer generates ephemeral Ed25519 keys in memory and never emits
private material. To intentionally replace this fixture, run:

```
NOCKLOCK_GENERATE_ROTATION_VECTORS=1 go test ./internal/logging/...
```

Then run the same command without the environment flag to verify the new vectors.
Ordinary tests never rewrite fixtures. Do not regenerate anchor-v2 vectors.
