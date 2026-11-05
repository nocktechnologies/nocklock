#!/usr/bin/env python3
"""Assemble release evidence after the Linux and ABI 9 jobs both pass."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("expected exact release commit")
    if args.dry_run:
        if args.assets is not None or args.tag is not None:
            raise ValueError("branch dry run must not package release assets")
    elif (args.assets is None or args.tag is None or
          not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag)):
        raise ValueError("release requires a stable tag and Linux assets")

    receipt = args.receipt / "landlock-abi9-receipt.json"
    bundle = args.receipt / "landlock-abi9-receipt.json.sigstore.json"
    report = json.loads(receipt.read_text())
    claims = report.get("claims", [])
    if (report.get("commit") != args.commit or report.get("verdict") != "PASS" or
            report.get("landlock_abi", 0) < 9 or len(claims) != 5 or
            any(c.get("actual") != c.get("expected") for c in claims) or
            not bundle.is_file() or not bundle.stat().st_size):
        raise ValueError("ABI 9 receipt is incomplete, failed or from another commit")
    acceptance = args.acceptance / "linux-release-acceptance.json"
    accepted = json.loads(acceptance.read_text())
    if accepted.get("commit") != args.commit:
        raise ValueError("Linux acceptance is from another commit")
    if args.dry_run:
        if accepted.get("kind") != "branch-dry-run-placeholder":
            raise ValueError("dry run must identify placeholder acceptance")
    elif (accepted.get("kind") != "release-install-acceptance" or
          accepted.get("tag") != args.tag or
          accepted.get("modes") != ["proxy", "netns"]):
        raise ValueError("Linux release acceptance is incomplete")

    args.output.mkdir(parents=True, exist_ok=False)
    if args.assets is not None:
        archive = f"nocklock_{args.tag}_linux_amd64.tar.gz"
        for name in (archive, "nocklock-install-linux-amd64", "INSTALLER.SHA256SUMS",
                     "INSTALLER.SHA256SUMS.sigstore.json"):
            shutil.copyfile(args.assets / name, args.output / name)
        original = (args.assets / "SHA256SUMS").read_text()
        if original != f"{digest(args.output / archive)}  {archive}\n":
            raise ValueError("Linux archive checksum mismatch")
    else:
        original = ""
    for source in (receipt, bundle, acceptance):
        shutil.copyfile(source, args.output / source.name)
    hashes = {name: digest(args.output / name) for name in
              ("linux-release-acceptance.json", "landlock-abi9-receipt.json")}
    (args.output / "SHA256SUMS").write_text(
        original + "".join(f"{hashes[name]}  {name}\n" for name in hashes))
    (args.output / "release-evidence.json").write_text(json.dumps({
        "schema": 1, "kind": "branch-dry-run" if args.dry_run else "release",
        "commit": args.commit, "tag": args.tag, "sha256": hashes,
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--dry-run", action="store_true")
    assemble(parser.parse_args())
