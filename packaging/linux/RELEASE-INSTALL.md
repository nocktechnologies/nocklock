# Signed Linux installation

This installer targets **Ubuntu 24.04, amd64, glibc 2.39**. It installs the CLI
and matching filesystem interposer together. Python and Go are not installation
dependencies. Cosign v3.1.3 is required for verification; its Linux amd64 checksum
is pinned in the installer. Other distributions, arm64 and musl are not supported.

This implementation is prepared for v0.16.0; the release notes alone do not
make its assets available. v0.15.0 has no installer assets. Use the
[source installation](../../docs/setup.md) until a release publishes the six
files below and links successful release-install acceptance evidence. Tagged
production acceptance, signed cross-version upgrade/rollback evidence and the
broader network gates in the [packaging contract](../../docs/design/linux-packaging.md)
must be completed before asset publication.

## Obtain and authenticate the installer

Choose an explicit stable tag from the repository's Releases page. Download
these six assets from **that same release** into a new directory you own:

- `nocklock_vX.Y.Z_linux_amd64.tar.gz`
- `SHA256SUMS` and `SHA256SUMS.sigstore.json`
- `nocklock-install-linux-amd64`
- `INSTALLER.SHA256SUMS` and `INSTALLER.SHA256SUMS.sigstore.json`

Acquire `cosign-linux-amd64` for [Cosign v3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3).
The recipe below checks its pinned digest before executing it. Do not execute
the downloaded installer with sudo before verifying it. An installer cannot
authenticate itself after it has already started.

Install `sudo`, `iproute2` and `nftables` through Ubuntu's package manager if you
want the optional kernel network fence. The installer does not install system
packages. All installation parents, including `/usr/local/bin` and
`/usr/local/lib`, must already be real root-owned directories without group or
other write permission. Unsafe existing paths are refused, never repaired
automatically.

The following is a reviewed shell recipe, not a downloaded script. It copies
the installer and verifier into private root-owned staging and authenticates
those exact copies before executing anything from the download. It retains
that bootstrap directory for future upgrades and rollback. Set the three
absolute paths/tag first; there is no implicit `latest` selection.

```bash
: "${RELEASE_TAG:?Set the published stable tag vX.Y.Z}"
: "${DOWNLOADS:?Set the absolute asset directory}"
: "${COSIGN:?Set the absolute cosign-linux-amd64 path}"
sudo /bin/sh -s -- "$DOWNLOADS" "$COSIGN" "$RELEASE_TAG" <<'ROOT'
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
assets=$1 verifier=$2 tag=$3
case "$assets:$verifier" in /*:/*) ;; *) echo 'Use absolute paths' >&2; exit 1;; esac
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
test "$(uname -s):$(uname -m)" = Linux:x86_64
umask 077
stage=$(mktemp -d /root/nocklock-bootstrap.XXXXXX)
install -m 0600 "$verifier" "$stage/cosign"
for name in nocklock-install-linux-amd64 INSTALLER.SHA256SUMS INSTALLER.SHA256SUMS.sigstore.json; do
  install -m 0600 "$assets/$name" "$stage/$name"
done
cd "$stage"
printf '%s  cosign\n' 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 | sha256sum --check --strict
chmod 0700 cosign
./cosign verify-blob INSTALLER.SHA256SUMS \
  --bundle INSTALLER.SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/nocktechnologies/nocklock/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
test "$(wc -l < INSTALLER.SHA256SUMS)" -eq 1
grep -Eq '^[0-9a-f]{64}  nocklock-install-linux-amd64$' INSTALLER.SHA256SUMS
sha256sum --check --strict INSTALLER.SHA256SUMS
chmod 0700 nocklock-install-linux-amd64
./nocklock-install-linux-amd64 install --tag "$tag" --artifacts "$assets" --cosign "$stage/cosign"
printf 'Verified installer and verifier retained in %s\n' "$stage"
ROOT
```

The privileged installer copies the archive, release manifest and bundle into
its own root-owned staging and verifies them again. It accepts only the exact
tag-specific workflow identity above. CI candidate signatures, other workflows,
changed archives, unexpected archive members and unsupported payloads refuse
before activation. No script supplied by an archive runs as root.

## Optional kernel network helper

Use the retained, authenticated bootstrap directory printed above. Pass the
ordinary local account that runs wrapped agents; root is refused:

```bash
sudo "$BOOTSTRAP/nocklock-install-linux-amd64" install \
  --tag "$RELEASE_TAG" --artifacts "$DOWNLOADS" --cosign "$BOOTSTRAP/cosign" \
  --egress-user "$USER"
```

This explicitly grants that account only `check` and
`setup --request-file ...` on the fixed helper. The generated shim calls the
managed CLI; the sudoers policy is validated with `visudo` before an atomic
replacement. Passing a different account replaces the existing managed grant.
Source-installed or unrecognized helper/policy files are refused. A failed
post-install helper check reports **netns setup incomplete** and exits nonzero;
the CLI remains installed. No setuid bits, capabilities or broad sudo grant are
added. Omitting `--egress-user` preserves an existing managed grant.

## Upgrade, rollback and interruption

For an upgrade, download the newer release's assets and repeat authentication
and installation with its explicit tag. The installer retains the old directory
and activates the complete new pair through one atomic symlink replacement.
Every invocation from a versioned install holds a shared lock; install and
rollback require the exclusive lock. Stop NockLock commands and retry if busy.
An old executable loaded just before a switch refuses after it acquires the
lock, instead of mixing its CLI with another release's helper. The lock file is
permanent: never remove or replace it. Migration from source or candidate
installations is not supported by this installer. Use a fresh supported host
for managed installation, or keep an existing source installation on the
[source-install workflow](../../docs/setup.md).

This lock is readable by ordinary CLI users. Any local account can deliberately
hold it and deny service to commands or upgrades; it is a consistency mechanism,
not isolation against a hostile account on a shared host. An administrator must
stop the offending process, never replace the lock inode. Subprocess checks have
a two-minute deadline plus a two-second pipe-drain bound and cancel their process
group. A helper that deliberately detaches into another session can require
administrator cleanup; the installer still returns instead of hanging on its
output pipe. Neither case bypasses signature checks or permits mixed activation.

An ordinary install refuses a downgrade. To deliberately activate an older
**already-installed** release:

```bash
sudo "$BOOTSTRAP/nocklock-install-linux-amd64" rollback \
  --tag "$OLDER_RELEASE_TAG" --cosign "$BOOTSTRAP/cosign"
```

Rollback reauthenticates the retained archive and compares the installed CLI,
interposer and metadata byte-for-byte with it before switching. It is not a
blind symlink change. Rolling back may restore old security vulnerabilities;
select a known appropriate version. Rollback never rewrites audit state or
project config, so it cannot promise an older release understands newer state.

After an interruption, rerun the same command. A completely staged release can
be reused only if its bytes match; an incomplete staging directory is never an
activation target. Private `.stage-*` or switch directories left by SIGKILL are
inert and are not automatically removed by a later run. No command prunes old
releases, keys, logs, configs or namespace resources.

Finally, as your ordinary account, run `nocklock version`, `nocklock doctor`, a
wrapped allowed command and `nocklock verify --audit` in a scratch project.
Installing files does not prove kernel enforcement. Below Landlock ABI 9,
`CONFINED` still has the documented Unix-socket limitation and doctor reports
`PARTIAL`. Kernel-egress mode needs its separate helper and host prerequisites.
