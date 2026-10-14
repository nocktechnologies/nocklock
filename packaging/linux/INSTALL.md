# Linux CI candidate — not a release

This archive pairs NockLock and `libfence_fs.so` from the commit recorded in
`build-info.json`. The build targets **Ubuntu 24.04, Linux amd64, glibc 2.39**.
It makes no arm64, musl, other distribution, or production support claim.

There is intentionally no public `install.sh` in this first slice. Installation
is exercised only by the reviewed `packaging/linux/provision-ci.py` harness on
a disposable GitHub-hosted VM. That harness refuses any existing installation,
stages and verifies bytes under root ownership, and installs the paired files
together. It is not an upgrade, rollback, or general-purpose installer. Do not
run it on a workstation or agent host. Never run the included helper script
directly from an untrusted download with sudo.

The disposable-host workflow first checks that `/usr/local` and its `bin` and
`lib` children are real directories, then makes only those three directories
root-owned and removes group/other write permission. Hosted runner images can
otherwise leave them writable by the runner. Before/after owners and modes are
retained in the acceptance artifact; the installer still rejects any untrusted
path component. This VM preparation is not a public installation procedure.

`SHA256SUMS` and its Sigstore bundle accompany the archive in the CI artifact.
The workflow signs a **candidate manifest**, not a release. Verification must
pin the GitHub Actions OIDC issuer and the exact candidate workflow identity
and ref recorded in the workflow run. An identity from this archive is not a
trust root. Successful candidate verification does not authorize publication.

The CI receipt records filesystem allow/deny controls, the explicit doctor
boundary (including PARTIAL for Landlock ABI below 9), and AUTHENTIC audit logs
whose signed session-start records report CONFINED and KERNEL. It proves only
the checks recorded in that run. The broader network, upgrade, rollback and
production signing gates in `docs/design/linux-packaging.md` remain outstanding.

No private signing key is included. Use the existing documented source build
until an approved, signed production installer and release are published.
