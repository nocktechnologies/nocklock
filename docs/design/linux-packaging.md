# Installable Linux release and OS acceptance contract

Date: 2026-10-13

Status: **Proposed; design only, no installer or release assets added**

Nock: N11643

Baseline: `89c1bb6e` (v0.9.1); refreshed after the v0.8/v0.9 doctor and Unix-socket changes and the v0.9.1 signing-key fence and netns child thread lock.

## Decision

Ship one signed release tarball for **Linux amd64 on Ubuntu 24.04 with glibc**
first. It contains the CLI, the matching filesystem interposer, and the netns
helper installer. Keep Homebrew as the macOS installation path. Expand the Linux
matrix only after clean-machine acceptance on each added architecture and libc.
Do not describe this first artifact as a portable binary for every Linux system.

This decision is proposed for review. Signing introduces Cosign as release and
verification tooling; it adds no Go runtime dependency. Approve that tooling and
its pinned version before implementing the release workflow.

The first implementation should cover packaging and installation only. It must
not change fence policy, doctor semantics, init output, or signing-key format.
Coordinate its release against the separate onboarding and doctor work.

## Why this is needed

The v0.9.1 release exists (the Homebrew formula may still point at v0.9.0; confirm
before implementing), but the release has no attached binary assets at this
baseline. `make build-all` builds the Linux
CLI and C interposer; `make install` installs only the CLI. The egress helper has
its own installation step. A successful CLI download alone therefore does not
constitute a working Linux installation.

The interposer lookup in `internal/cli/wrap.go` accepts an executable-adjacent
library or the fixed `/usr/local/lib/nocklock` and `/usr/lib/nocklock` locations,
and rejects candidates inside the project. Packaging must preserve that trust
boundary. The helper script currently invokes `/usr/local/bin/nocklock`, so a
user-writable binary at that path would also become a privileged execution path.

## OS contract

| OS / first supported target | Installation | Required pieces | Privilege |
| --- | --- | --- | --- |
| Linux amd64, Ubuntu 24.04/glibc | Verified release tarball; system install | CLI, matching `libfence_fs.so`; `ip`, `nft`, `sudo`, `visudo`, `su`; netns helper for KERNEL mode | One explicit admin install; narrowly scoped passwordless helper at runtime |
| macOS on architectures exercised by release CI | Existing `nocktechnologies/tap/nocklock` formula | CLI and usable system `sandbox-exec`; no Linux `.so` or netns helper | Homebrew setup as documented by Homebrew; no NockLock root helper |
| Native Windows | No production installer in this slice | Existing feasibility/probe work is separate | No support claim |

Landlock, seccomp, namespace, routing and nftables capabilities must be checked
on the actual Linux host. A distro name or successful extraction cannot prove
they are usable. Containers with restricted capabilities are not substitutes
for the clean VM acceptance run. macOS acceptance is required on every claimed
OS/architecture pair; an unsupported/deprecated sandbox facility must produce a
clear refusal, not an installation success claim.

Linux Homebrew remains outside this first binary support matrix. `.deb` and
`.rpm` packages are good subsequent distribution channels, once the artifact,
privileged-helper contract, upgrades and acceptance tests are stable. Starting
with both package formats creates more lifecycle scripts before those contracts
are proven. A source-only recipe leaves users responsible for the mismatch this
work is meant to remove.

## Artifact and authenticity

Proposed asset name: `nocklock_vX.Y.Z_linux_amd64.tar.gz`. Its single top-level
directory contains:

```text
nocklock-vX.Y.Z-linux-amd64/
  nocklock
  libfence_fs.so
  install.sh
  install-egress-helper.sh
  INSTALL.md
  LICENSE
  build-info.json
```

Build both executables from one immutable commit in the pinned Ubuntu/glibc
builder. Record tag, full commit, Go version, C compiler, libc baseline, OS and
architecture in `build-info.json`. Set the CLI version from that tag. Check the
ELF architecture and required dynamic-library/symbol versions in CI. Do not
cross-compile only the Go binary and label the pair tested. No Alpine/musl or
arm64 compatibility claim follows from this build.

Publish `SHA256SUMS` and `SHA256SUMS.sigstore.json` next to the tarball.
`SHA256SUMS` names only the release assets. Cosign signs that manifest as a blob;
the bundle supplies the signing certificate and verification material. This
binds the checksums to a publisher, unlike a bare checksum on the same server.
See the official [blob-signing instructions](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/).

Use a tag-triggered, protected GitHub Actions release workflow with a pinned
Cosign toolchain. Restrict the expected certificate identity to the exact
repository, workflow path and release tag, with the GitHub Actions OIDC issuer.
The installer documentation must supply these expected values independently of
the downloaded checksum file. Do not accept a publisher identity supplied by the
archive being verified. Sigstore documents the
[GitHub workflow identity](https://docs.sigstore.dev/quickstart/quickstart-ci/)
and [blob verification options](https://docs.sigstore.dev/cosign/verifying/verify/).

Proposed verification recipe, after acquiring Cosign through a trusted channel
and downloading the three assets into an empty operator-owned directory:

```bash
set -euo pipefail
# Proposed workflow identity: this workflow does not exist at the baseline.
: "${RELEASE_TAG:?Set the reviewed release tag, for example v0.9.1}"
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
archive="nocklock_${RELEASE_TAG}_linux_amd64.tar.gz"
identity="https://github.com/nocktechnologies/nocklock/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}"
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Check only the selected asset, with exactly one matching manifest entry.
awk -v name="$archive" '$2 == name { print; n++ } END { if (n != 1) exit 1 }' \
  SHA256SUMS > selected-checksum.txt
sha256sum --check --strict selected-checksum.txt
```

The implementation must reject bad signatures, changed bytes, wrong identity,
wrong architecture, and invalid archive members before any privileged action.
Only regular files/directories from the documented manifest are valid; reject
absolute paths, `..` components, symlinks, hard links, devices and duplicate
members. Do not pipe a network response into a root shell. A tag or a matching
hash by itself is not the authenticity gate. Never replace released bytes under
an existing tag; issue a new version for a rebuilt artifact.

## Installation and helper privilege

Use a versioned directory such as
`/usr/local/lib/nocklock/releases/vX.Y.Z-linux-amd64/` for the CLI and its adjacent
library. All ancestors and executable/library files must be root-owned and
unwritable by group/other. `/usr/local/bin/nocklock` points to the installed CLI.
Confirm the real executable directory resolves correctly through that symlink
in acceptance. The fixed-library fallbacks must not silently select an old
interposer when the adjacent one is missing; packaging tests must detect this.

The proposed installer has two explicit entry points:

Before either entry point runs, use trusted system tools to copy the archive
and signature material into a new root-owned, non-writable staging directory,
repeat signature/hash checks there, and validate/extract the members there.
Execute the installers only from this verified root-controlled staging tree.
Checking a user-writable script and then running it with sudo leaves a race;
an installer cannot establish its own authenticity after it has started.

1. `sudo ./install.sh`: verify/stage the selected release in a root-controlled
   directory, validate its manifest there, set ownership/modes, then atomically
   switch the CLI link. The privileged phase must reverify the staged bytes;
   verification followed by copying from a user-writable path is a race. Reject
   unsafe pre-existing ancestors and unexpected file types. Execute only the
   reviewed installer; it must use fixed trusted tool paths and validated tag
   components, not arbitrary environment commands or shell interpolation.
2. `sudo ./install-egress-helper.sh --user "$USER"`: explicitly authorize one
   non-root operator account for the helper. The packaged script retains the
   existing narrow interface and adds the binary/ancestor ownership checks.
   It must refuse a user-writable or mismatched installed release before writing
   a sudo rule. Do not treat the current source helper script as having these
   new checks already.

The helper remains root-owned at `/usr/libexec/nocklock-egress-helper` and exposes
only `check` and `setup --request-file ...` through
`/etc/sudoers.d/nocklock-egress`. Its existing implementation validates the
request; installer ownership checks do not replace that validation. Validate a
staged sudoers file with `visudo`, install it atomically at mode `0440`, and run
the passwordless check as the target account. Never grant arbitrary
`sudo nocklock`, a shell, or `ALL`; do not add setuid bits or file capabilities.

Normal `nocklock wrap` runs as the operator. Netns mode uses the constrained
helper; failure of that helper must refuse the requested KERNEL mode. Installing
only the CLI/library can support the Linux CONFINED path when its actual probes
pass, but must not claim KERNEL enforcement.

For the first installer, refuse to replace an existing managed release while a
NockLock session is active; hold an installer lock across stage/switch/helper
validation. Establish a reliable session-liveness check before shipping that
rule. Pin a resolved release path for each invocation so a concurrent switch
cannot mix the parent CLI, helper and interposer. If this cannot be guaranteed
with the current helper interface, require a helper/version handshake as part
of the packaging implementation, not an undocumented compatibility assumption.
Retain prior release directories and support an explicit verified rollback.
Do not automatically prune binaries, audit databases, keys, project configs or
active namespace resources. A failed helper install leaves the CLI installed
but reports netns setup incomplete; it must never report full acceptance.

## Clean-machine acceptance scripts

These are a **proposed acceptance contract**, not evidence that release assets
already exist. Run as an ordinary user in disposable VMs with no repository
checkout, NockLock config, signing keys or prior installation. Preserve the VM
and logs on failure. VM teardown handles cleanup; the examples delete no files.
Require Bash and Python 3 as test tools (Python is not a product dependency).

Save this common body as `accept-installed.sh`. It uses a fresh directory under
the test user's home, outside the project, so `/tmp` runtime allowances do not
make the denial test meaningless. Use a dedicated test account with no real
credentials. The outside-directory positive control proves the host user could
write there without the fence. A timeout, missing executable or any other errno
fails the test instead of being counted as a successful denial.

```bash
#!/usr/bin/env bash
set -euo pipefail
: "${NOCKLOCK_BIN:?Absolute installed CLI path}"
: "${TEST_PYTHON:?Absolute system Python 3 path}"
: "${TEST_NET_MODE:?proxy or netns}"
: "${EXPECTED_EGRESS:?CONFINED, KERNEL or SEATBELT}"
test -x "$NOCKLOCK_BIN"
test -x "$TEST_PYTHON"
test "$(id -u)" -ne 0
case "$TEST_NET_MODE" in
  proxy) mode_args=() ;;
  netns) mode_args=(--net-fence=netns) ;;
  *) exit 2 ;;
esac
fixture=$(mktemp -d "$HOME/nocklock-accept.XXXXXX")
mkdir "$fixture/project" "$fixture/outside"
cd "$fixture/project"
"$NOCKLOCK_BIN" version | tee "$fixture/version.txt"
"$NOCKLOCK_BIN" init
doctor_exit=0
"$NOCKLOCK_BIN" doctor --json > "$fixture/doctor.json" || doctor_exit=$?
"$TEST_PYTHON" -I - "$fixture/doctor.json" "$doctor_exit" <<'PY'
import json, re, sys
report = json.load(open(sys.argv[1]))
code = int(sys.argv[2])
boundaries = {b["name"]: b["posture"] for b in report["boundaries"]}
for name in ("filesystem", "syscall", "network", "secrets"):
    assert boundaries[name] == "enforced", boundaries
if sys.platform == "darwin":
    assert report["egress_level"] == "SEATBELT", report
    assert code == 0 and report["verdict"] == "PROTECTED", report
else:
    assert sys.platform == "linux", sys.platform
    assert report["egress_level"] == "CONFINED", report
    if boundaries["unix-sockets"] == "enforced":
        assert code == 0 and report["verdict"] == "PROTECTED", report
    else:
        # v0.9 deliberately reports PARTIAL on pre-ABI-9 kernels. Accept
        # only that named limitation, never a generic degraded install.
        assert boundaries["unix-sockets"] == "unavailable", boundaries
        assert code == 3 and report["verdict"] == "PARTIAL", report
        check = next(c for c in report["checks"] if c["name"] == "unix-sockets")
        assert re.search(r"reason=landlock_abi_[1-8]_below_9\b", check["message"]), check
assert all(b["posture"] == "enforced" or
           (sys.platform == "linux" and b["name"] == "unix-sockets" and code == 3)
           for b in report["boundaries"]), boundaries
PY
cat > probe.py <<'PY'
import errno, pathlib, sys
pathlib.Path("allowed.txt").write_text("allowed\n")
assert pathlib.Path("allowed.txt").read_text() == "allowed\n"
try:
    pathlib.Path(sys.argv[1]).write_text("must be denied\n")
except OSError as exc:
    if exc.errno not in (errno.EACCES, errno.EPERM):
        raise
else:
    raise SystemExit("FAIL: outside write succeeded")
print("ALLOW_AND_DENY_PASS")
PY
"$TEST_PYTHON" -I - "$fixture/outside/control.txt" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text("host positive control\n")
PY
"$NOCKLOCK_BIN" wrap ${mode_args[@]+"${mode_args[@]}"} --require-enforced-egress -- \
  "$TEST_PYTHON" probe.py "$fixture/outside/forbidden.txt" \
  > "$fixture/wrap.txt" 2>&1
grep -qx ALLOW_AND_DENY_PASS "$fixture/wrap.txt"
test -f allowed.txt
test ! -e "$fixture/outside/forbidden.txt"
# Export includes an ed25519 prefix; v0.8+ accepts either form.
pub=$("$NOCKLOCK_BIN" verify --export-pubkey)
case "$pub" in 'ed25519 '*) pub=${pub#ed25519 } ;; esac
test -n "$pub"
"$NOCKLOCK_BIN" verify --audit --ed25519-pub "$pub" \
  > "$fixture/audit.txt"
grep -q '^AUDIT: AUTHENTIC' "$fixture/audit.txt"
"$NOCKLOCK_BIN" log --json > "$fixture/events.json"
"$TEST_PYTHON" -I - "$fixture/events.json" "$EXPECTED_EGRESS" <<'PY'
import json, sys
events = json.load(open(sys.argv[1]))
starts = [e for e in events if e["EventType"] == "session_start"]
assert len(starts) == 1, "expected one session in a fresh project"
assert starts[0]["egress_level"] == sys.argv[2], starts[0]
PY
printf 'ACCEPTED; evidence: %s\n' "$fixture"
```

Linux acceptance has two separate roles. The provision step runs once on the
clean Ubuntu 24.04 VM as root (`sudo bash provision.sh`, from an admin account).
It is the only place with privileged installs. The acceptance driver then runs
as the dedicated test user and makes no privileged installs at all. Both are
proposed, as are the two install scripts they call, and both follow
signature/checksum/archive validation above and extraction into a fresh
staging directory.

Provision step (root, admin account):

```bash
#!/usr/bin/env bash
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test "$(id -u)" -eq 0
: "${VERIFIED_PACKAGE_DIR:?Root-controlled verified extracted release directory}"
: "${TEST_USER:?Name of the new dedicated unprivileged test user}"
# Prerequisites on the clean VM; use its signed package repository.
apt-get update
apt-get install -y iproute2 nftables sudo python3
# Resolve once; every later use takes ONLY the resolved path $pkg. Fail closed
# unless the directory and every parent up to / are owned by root and not
# group- or other-writable, and each script run below is a regular file (not a
# symlink) with the same ownership and mode. Check-then-use is safe only because
# the whole path is root-owned end to end, so no non-root user can swap a
# component between the check and the run. Remaining limit: a root-writable
# parent (or a root process) could still race it; the VM has no such writer.
pkg=$(realpath -e -- "$VERIFIED_PACKAGE_DIR")
d=$pkg
while :; do
  read -r owner mode < <(stat -c '%u %a' -- "$d")
  test "$owner" = 0 && test $((8#$mode & 8#022)) -eq 0 \
    || { echo "untrusted package path component: $d" >&2; exit 1; }
  test "$d" = / && break
  d=$(dirname -- "$d")
done
for f in install.sh install-egress-helper.sh; do
  test -f "$pkg/$f" && test ! -L "$pkg/$f" \
    || { echo "not a regular file: $pkg/$f" >&2; exit 1; }
  read -r owner mode < <(stat -c '%u %a' -- "$pkg/$f")
  test "$owner" = 0 && test $((8#$mode & 8#022)) -eq 0 \
    || { echo "untrusted script: $pkg/$f" >&2; exit 1; }
done
# The test user must be new, so it cannot inherit a blanket grant from a stock
# cloud-image rule or from the sudo or admin groups. Refuse an existing name.
if id -u -- "$TEST_USER" >/dev/null 2>&1; then
  echo "test user already exists: $TEST_USER" >&2; exit 1
fi
useradd --create-home --shell /bin/bash -- "$TEST_USER"
"$pkg/install.sh"
"$pkg/install-egress-helper.sh" --user "$TEST_USER"
# Fail closed unless the helper drop-in is the user's only sudo grant.
listing=$(sudo -l -U "$TEST_USER")
if printf '%s\n' "$listing" | grep -Eq '\(ALL( : ALL)?\) +(NOPASSWD: *)?ALL([[:space:]]|$)'; then
  echo "blanket sudo grant for $TEST_USER" >&2; exit 1
fi
printf 'Provisioned %s; run the acceptance driver as that user.\n' "$TEST_USER"
```

Acceptance driver (run as the test user, no privileged installs):

```bash
#!/usr/bin/env bash
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test "$(id -u)" -ne 0
# Evidence directory comes first, before anything else runs.
: "${EVIDENCE_DIR:?Absolute path for the evidence directory}"
: "${ACCEPT_SCRIPT:?Absolute path to the common acceptance body}"
mkdir -p -- "$EVIDENCE_DIR"
# Drop any cached sudo ticket, then record what this user may run.
sudo -k
sudo -n -l > "$EVIDENCE_DIR/sudo-l.txt"
# sudo -l joins commands with commas. Split them one per line, then fail closed
# unless every listed command is under the egress helper and both helper
# entries exist.
entries=$(sed -n '/may run the following commands/,$p' "$EVIDENCE_DIR/sudo-l.txt" \
  | tail -n +2 \
  | sed -E 's/^[[:space:]]*(\([^)]*\)[[:space:]]*)?(NOPASSWD:[[:space:]]*)?//' \
  | sed -E 's|, (/)|\n\1|g' | grep -v '^$')
printf '%s\n' "$entries" > "$EVIDENCE_DIR/sudo-entries.txt"
grep -qx '/usr/libexec/nocklock-egress-helper check' "$EVIDENCE_DIR/sudo-entries.txt"
grep -q '^/usr/libexec/nocklock-egress-helper setup --request-file ' \
  "$EVIDENCE_DIR/sudo-entries.txt"
if grep -v '^/usr/libexec/nocklock-egress-helper ' "$EVIDENCE_DIR/sudo-entries.txt" | grep -q .; then
  echo "foreign sudo entry present" >&2; exit 1
fi
# Negative control: an unrelated command must be refused without a password.
if sudo -n /usr/bin/true 2>/dev/null; then
  echo "negative control failed: sudo -n /usr/bin/true succeeded" >&2; exit 1
fi
# Functional check, after the proof, with no cached ticket.
sudo -n /usr/libexec/nocklock-egress-helper check
NOCKLOCK_BIN=/usr/local/bin/nocklock TEST_PYTHON=/usr/bin/python3 \
  TEST_NET_MODE=proxy EXPECTED_EGRESS=CONFINED bash "$ACCEPT_SCRIPT"
NOCKLOCK_BIN=/usr/local/bin/nocklock TEST_PYTHON=/usr/bin/python3 \
  TEST_NET_MODE=netns EXPECTED_EGRESS=KERNEL bash "$ACCEPT_SCRIPT"
```

The test dependency list must be kept consistent with installer preflight;
`su` and `visudo` must also be present. The helper `check` verb is the one the
sudoers rule names, and the installer preflight runs it as the target user for
the same reason. The `sudo -l` listing plus the failed `/usr/bin/true` control
prove the rule is narrow; a blanket grant would pass `check` alone. The common body asserts the
effective signed session level is CONFINED for proxy mode and KERNEL for netns.
Doctor is run before each test. On Linux below Landlock ABI 9, v0.9.x returns
PARTIAL (exit 3); the script accepts only the Unix-socket unavailability with
its explicit below-9 reason and requires every other boundary to be enforced.
This is installation acceptance with a recorded limitation, not a claim of
Unix-socket isolation. The ABI-9 branch still needs real-kernel validation.
Doctor's config-based result alone cannot certify the later
`--net-fence=netns` override. `log --json` decodes the signed session-start
detail envelope; its egress-level assertion follows authenticity verification.

macOS driver, on a clean supported machine with Homebrew installed using its
official instructions and Python 3 provisioned as a test dependency:

```bash
#!/usr/bin/env bash
set -euo pipefail
test "$(uname -s)" = Darwin
test "$(id -u)" -ne 0
: "${ACCEPT_SCRIPT:?Absolute path to the common acceptance body}"
: "${TEST_PYTHON:?Absolute Python 3 path under a permitted runtime prefix}"
brew tap nocktechnologies/tap
brew install nocklock
installed_cli="$(brew --prefix nocklock)/bin/nocklock"
NOCKLOCK_BIN="$installed_cli" TEST_NET_MODE=proxy EXPECTED_EGRESS=SEATBELT \
  TEST_PYTHON="$TEST_PYTHON" bash "$ACCEPT_SCRIPT"
```

Record the exact formula revision, OS, architecture and installed CLI version;
the published formula must point to the intended release. Its existing source
SHA check is distinct from the proposed Sigstore authentication of Linux assets.
Require SEATBELT in the signed session-start row on macOS. If a Python runtime
is denied, diagnose the setup rather than weakening fence rules to pass.

`AUTHENTIC` authenticates the stored audit chain with the specified key. This
local export checks install/signing integration; it is not an independent
off-machine key-distribution or rollback-resistance test. Keep the exported
public key and verifier output with acceptance evidence; never upload the
private key.

## Additional release gates and implementation order

1. Build and inspect the paired Linux artifact; verify version and glibc baseline.
2. Exercise signature and archive rejection cases before testing the installer.
3. Exercise clean install, repeated install, interrupted install, unsafe existing
   symlinks/owners, missing interposer, helper preflight failure and rollback.
4. Run both OS acceptance drivers. Inspect the signed session level and any
   unexpected skips. The common script proves file operations and receipt
   authenticity; it does not prove network reachability policy by itself.
5. Run existing Linux netns integration scenarios on a real VM: controlled
   reachable server, allowed HTTP(S) through the proxy, denied domain through
   the proxy, direct TCP/UDP denial, and no fallback after helper failure. A
   negative network test needs an unfenced reachability control and a kernel
   counter/packet observation; a timeout alone is inconclusive. Keep test-only
   private-address allowances local to that fixture, never in shipped defaults.
6. Run corresponding macOS allowed-proxy/direct-egress probes; prove the test
   destination is reachable outside the fence. Existing kernel-denial telemetry
   limitations do not imply permission to advertise a complete denial history.
7. Only then publish the immutable assets, install guide and support matrix.

Record artifact hashes, signing identity, full source head and VM evidence in
the release. Ship additional package managers and architectures as separate
slices using this same contract. This note changes no installed behavior.
