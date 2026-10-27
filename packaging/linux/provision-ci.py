#!/usr/bin/env python3
"""Fresh-install acceptance harness for disposable GitHub-hosted VMs ONLY.

The reviewed workflow/checkout is the harness trust root. This is deliberately
not shipped as an installer: public bootstrap, upgrades and rollback are absent.
"""

import argparse
import fcntl
import grp
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

from artifact import digest, names, validate

COSIGN_SHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"  # v3.1.3 linux-amd64
TEST_USER = "nocklock-candidate"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C"}


def trusted(path):
    """Reject symlinks and non-root/writable components, all the way to /."""
    path = Path(path)
    for component in [path, *path.parents]:
        info = component.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError(f"untrusted root path: {component}")


def run(*args):
    subprocess.run(args, check=True, env=ENV)


def stage_file(source, destination, limit):
    # Inputs may be runner-owned. Copy without executing; then authenticate ONLY
    # this root-owned copy. A concurrent source modification cannot bypass that.
    with source.open("rb") as src, destination.open("xb") as dst:
        data = src.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"oversized input: {source.name}")
        dst.write(data)
    destination.chmod(0o600)


def require_private_group(name):
    """Require name's primary group to be named name with no other members."""
    account = pwd.getpwnam(name)
    group = grp.getgrgid(account.pw_gid)
    sharers = [p.pw_name for p in pwd.getpwall() if p.pw_gid == account.pw_gid and p.pw_name != name]
    if group.gr_name != name or set(group.gr_mem) - {name} or sharers:
        raise ValueError(f"{name} does not have a private primary group")


def make_traversable_dir(path):
    """Create a directory 0755; mkdir alone honors the private 077 umask."""
    path.mkdir()
    path.chmod(0o755)


def provision(args):
    if (os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64"
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("CI-only: require root on a disposable GitHub-hosted Linux amd64 VM")
    os.umask(0o077)
    identity_prefix = "https://github.com/nocktechnologies/nocklock/.github/workflows/linux-candidate.yml@"
    if not re.fullmatch(re.escape(identity_prefix) + r"refs/(heads/[A-Za-z0-9_./-]+|pull/[0-9]+/merge)", args.identity):
        raise ValueError("require exact candidate workflow/ref identity; release tags are not supported")
    root, filename = names(args.commit)
    for parent in ("/usr/local/bin", "/usr/local/lib", "/usr/lib", "/etc/sudoers.d", "/opt", "/run"):
        trusted(parent)
    lock_path = "/run/nocklock-candidate-install.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        trusted(lock_path)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # No replacement, even of a broken symlink or an interrupted install.
        for path in ("/usr/local/bin/nocklock", "/usr/local/lib/nocklock", "/usr/lib/nocklock",
                     "/usr/libexec/nocklock-egress-helper", "/etc/sudoers.d/nocklock-egress"):
            if os.path.lexists(path):
                raise ValueError(f"refusing pre-existing installation: {path}; use a fresh VM")
        try:
            pwd.getpwnam(TEST_USER)
        except KeyError:
            pass
        else:
            raise ValueError("acceptance account already exists; use a fresh VM")
        stage = Path(tempfile.mkdtemp(prefix="nocklock-candidate-", dir="/opt"))
        print(f"Root-controlled evidence/staging retained at {stage}", flush=True)
        stage_file(args.cosign, stage / "cosign", 200 * 1024 * 1024)
        if digest((stage / "cosign").read_bytes()) != COSIGN_SHA256:
            raise ValueError("Cosign v3.1.3 binary checksum mismatch")
        (stage / "cosign").chmod(0o700)
        for name, limit in ((filename, 128 * 1024 * 1024), ("SHA256SUMS", 4096), ("SHA256SUMS.sigstore.json", 2 * 1024 * 1024)):
            stage_file(args.artifacts / name, stage / name, limit)
        trusted(stage / "cosign")
        run(str(stage / "cosign"), "verify-blob", str(stage / "SHA256SUMS"),
            "--bundle", str(stage / "SHA256SUMS.sigstore.json"),
            "--certificate-identity", args.identity,
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
        records = validate(stage / filename, stage / "SHA256SUMS", args.commit)
        extracted = stage / root
        extracted.mkdir(mode=0o700)
        for name, data in records.items():
            path = extracted / name
            path.write_bytes(data)
            path.chmod(0o755 if name in {"nocklock", "libfence_fs.so", "install-egress-helper.sh"} else 0o644)
            trusted(path)
        # The immutable pair is installed adjacent; no fixed .so fallback exists.
        release = Path("/usr/local/lib/nocklock/releases") / root
        release.mkdir(parents=True, mode=0o755)
        # mkdir's intermediates honor the private umask; make only these new,
        # operator-created ancestors traversable by the dedicated account.
        for path in (release.parent.parent, release.parent, release):
            path.chmod(0o755)
            trusted(path)
        for name in ("nocklock", "libfence_fs.so", "build-info.json"):
            shutil.copyfile(extracted / name, release / name)
            (release / name).chmod(0o644 if name.endswith(".json") else 0o755)
            trusted(release / name)
        os.symlink(release / "nocklock", "/usr/local/bin/nocklock")
        # Versioned CLIs share this permanent inode with the lifecycle installer.
        lease = release.parent.parent / "install.lock"
        lease.touch(mode=0o644, exist_ok=False)
        lease.chmod(0o644)
        if Path("/usr/local/bin/nocklock").resolve(strict=True) != release / "nocklock":
            raise ValueError("installed CLI symlink does not resolve to candidate")
        if not Path("/usr/libexec").exists():
            make_traversable_dir(Path("/usr/libexec"))
        trusted("/usr/libexec")
        # Stock Ubuntu account shape: a private group named after the user.
        run("/usr/sbin/useradd", "--create-home", "--user-group", "--shell", "/bin/bash", TEST_USER)
        require_private_group(TEST_USER)
        # Preflight all executable ancestors before the packaged helper script
        # writes its constrained sudoers grant. Its fixed CLI link cannot change
        # during this fresh-only install, and this harness never upgrades it.
        trusted(release / "nocklock")
        run("/bin/sh", str(extracted / "install-egress-helper.sh"), "--user", TEST_USER)
        trusted("/usr/libexec/nocklock-egress-helper")
        trusted("/etc/sudoers.d/nocklock-egress")
        print(f"Fresh candidate installed for {TEST_USER}; acceptance has not run yet", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("cosign", type=Path)
    parser.add_argument("commit")
    parser.add_argument("identity")
    provision(parser.parse_args())
