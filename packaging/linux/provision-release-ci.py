#!/usr/bin/env python3
"""CI-only authentication of the standalone installer before granting it root."""

import argparse
import importlib.util
import os
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location("candidate_ci", Path(__file__).with_name("provision-ci.py"))
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def provision(args):
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("require root on a disposable GitHub-hosted VM")
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag):
        raise ValueError("require stable release tag")
    ci.trusted("/opt")
    os.umask(0o077)
    stage = Path(tempfile.mkdtemp(prefix="nocklock-release-bootstrap-", dir="/opt"))
    for name, limit in {"nocklock-install-linux-amd64": 64 << 20,
                        "INSTALLER.SHA256SUMS": 4096,
                        "INSTALLER.SHA256SUMS.sigstore.json": 2 << 20}.items():
        ci.stage_file(args.artifacts / name, stage / name, limit)
    ci.stage_file(args.cosign, stage / "cosign", 200 << 20)
    if ci.digest((stage / "cosign").read_bytes()) != ci.COSIGN_SHA256:
        raise ValueError("wrong pinned verifier")
    (stage / "cosign").chmod(0o700)
    identity = "https://github.com/nocktechnologies/nocklock/.github/workflows/release.yml@refs/tags/" + args.tag
    ci.run(str(stage / "cosign"), "verify-blob", str(stage / "INSTALLER.SHA256SUMS"),
           "--bundle", str(stage / "INSTALLER.SHA256SUMS.sigstore.json"),
           "--certificate-identity", identity,
           "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
    expected = ci.digest((stage / "nocklock-install-linux-amd64").read_bytes()) + "  nocklock-install-linux-amd64\n"
    if (stage / "INSTALLER.SHA256SUMS").read_text() != expected:
        raise ValueError("standalone installer checksum mismatch")
    installer = stage / "nocklock-install-linux-amd64"
    installer.chmod(0o700)
    ci.run("/usr/sbin/useradd", "--create-home", "--user-group", "--shell", "/bin/bash", ci.TEST_USER)
    ci.require_private_group(ci.TEST_USER)
    ci.run(str(installer), "install", "--tag", args.tag, "--artifacts", str(args.artifacts),
           "--cosign", str(stage / "cosign"), "--egress-user", ci.TEST_USER)
    # Retry and explicit rollback reverify stored bytes through the production path.
    ci.run(str(installer), "install", "--tag", args.tag, "--artifacts", str(args.artifacts),
           "--cosign", str(stage / "cosign"))
    ci.run(str(installer), "rollback", "--tag", args.tag, "--cosign", str(stage / "cosign"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("cosign", type=Path)
    parser.add_argument("tag")
    provision(parser.parse_args())
