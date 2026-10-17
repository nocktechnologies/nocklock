#!/usr/bin/env python3
"""Validate candidate bytes before extraction. This is CI tooling, not an installer."""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

PAYLOAD = {"nocklock", "libfence_fs.so", "install-egress-helper.sh", "INSTALL.md", "LICENSE"}
FILES = PAYLOAD | {"build-info.json"}
MAX_BYTES = 128 * 1024 * 1024


def names(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected a full lowercase source commit")
    root = f"nocklock-candidate-{commit}-linux-amd64"
    return root, root + ".tar.gz"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf_amd64(data):
    # ELF64, little endian, current ELF version, x86-64, executable or shared object.
    return (len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
            and int.from_bytes(data[16:18], "little") in (2, 3)
            and int.from_bytes(data[18:20], "little") == 62)


def validate(archive, manifest, commit):
    """Return validated file bytes; never extract a tar member via its supplied path."""
    root, filename = names(commit)
    if archive.name != filename or archive.stat().st_size > MAX_BYTES:
        raise ValueError("wrong candidate filename or oversized archive")
    expected_manifest = f"{digest(archive.read_bytes())}  {filename}\n"
    if manifest.read_text(encoding="ascii") != expected_manifest:
        raise ValueError("manifest must contain exactly this candidate's SHA-256 entry")
    records = {}
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        seen = set()
        for member in tar:
            if member.name in seen:
                raise ValueError("duplicate archive member")
            seen.add(member.name)
            if member.name == root:
                if not member.isdir() or member.mode != 0o755 or member.uid != 0 or member.gid != 0:
                    raise ValueError("invalid top-level directory")
                continue
            if not member.name.startswith(root + "/"):
                raise ValueError("archive member outside candidate directory")
            name = member.name[len(root) + 1:]
            if name not in FILES or not member.isfile() or member.issparse():
                raise ValueError("unexpected path, link, special or sparse archive member")
            mode = 0o755 if name in {"nocklock", "libfence_fs.so", "install-egress-helper.sh"} else 0o644
            if member.mode != mode or member.uid != 0 or member.gid != 0:
                raise ValueError("unexpected candidate ownership or mode")
            total += member.size
            if member.size < 0 or total > MAX_BYTES:
                raise ValueError("candidate exceeds size limit")
            records[name] = tar.extractfile(member).read()
    if seen != {root} | {root + "/" + name for name in FILES}:
        raise ValueError("candidate must contain exactly the documented files")
    info = json.loads(records["build-info.json"], object_pairs_hook=unique_object)
    for key, value in {"schema": 1, "kind": "ci-candidate-not-release", "commit": commit,
                       "os": "linux", "arch": "amd64", "distribution": "ubuntu-24.04",
                       "libc_baseline": "glibc-2.39",
                       "version": "0.0.0-candidate." + commit}.items():
        if info.get(key) != value:
            raise ValueError(f"unexpected build-info {key}")
    if info.get("files") != {name: digest(records[name]) for name in PAYLOAD}:
        raise ValueError("build-info payload hashes do not match")
    for name in ("nocklock", "libfence_fs.so"):
        if not elf_amd64(records[name]):
            raise ValueError(f"{name} is not a Linux amd64 ELF64 candidate")
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("commit")
    args = parser.parse_args()
    validate(args.archive, args.manifest, args.commit)
    print("Candidate manifest, archive members, payload hashes and ELF architecture verified")
