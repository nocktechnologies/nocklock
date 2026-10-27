#!/usr/bin/env bash
# Keyless-sign DIR/SHA256SUMS with this workflow's GitHub OIDC identity, then
# prove the bundle verifies only for that identity and only for those bytes.
# CI only: needs cosign and a job with id-token: write.
#
# Usage: sign-manifest.sh DIR IDENTITY [MANIFEST]
set -euo pipefail

dir="$1"
identity="$2"
manifest=${3:-SHA256SUMS}
[[ "$manifest" == SHA256SUMS || "$manifest" == INSTALLER.SHA256SUMS ]]
issuer=https://token.actions.githubusercontent.com
diagnostics="$(mktemp -d)"
trap 'rm -rf "$diagnostics"' EXIT
cd "$dir"
test -s "$manifest"
sha256sum --check --strict "$manifest"

cosign sign-blob --yes --bundle "$manifest.sigstore.json" "$manifest"
cosign verify-blob "$manifest" --bundle "$manifest.sigstore.json" \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"

# Each negative control must fail for its own reason, not any error.
if cosign verify-blob "$manifest" --bundle "$manifest.sigstore.json" \
  --certificate-identity 'https://github.com/nocktechnologies/nocklock/.github/workflows/not-this-workflow.yml@refs/tags/v0.0.0' \
  --certificate-oidc-issuer "$issuer" > "$diagnostics/wrong-identity.txt" 2>&1; then
  echo 'FAIL: manifest accepted for another workflow identity' >&2; exit 1
fi
cat "$diagnostics/wrong-identity.txt"
grep -Eq 'no matching CertificateIdentity found|none of the expected identities matched' \
  "$diagnostics/wrong-identity.txt" || { echo 'FAIL: wrong signer refused for another reason' >&2; exit 1; }

cp "$manifest" "$diagnostics/changed-manifest.txt"
echo changed >> "$diagnostics/changed-manifest.txt"
if cosign verify-blob "$diagnostics/changed-manifest.txt" --bundle "$manifest.sigstore.json" \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  > "$diagnostics/changed-manifest.log" 2>&1; then
  echo 'FAIL: changed manifest authenticated' >&2; exit 1
fi
cat "$diagnostics/changed-manifest.log"
grep -Eq 'failed to verify signature|could not verify message|invalid signature|artifact digest does not match|artifact does not match digest|does not match artifact' \
  "$diagnostics/changed-manifest.log" || { echo 'FAIL: changed manifest refused for another reason' >&2; exit 1; }
