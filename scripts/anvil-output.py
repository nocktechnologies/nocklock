#!/usr/bin/env python3
"""Validate Anvil verdicts and retain redacted runner-side review output."""

import os
from pathlib import Path
import re
import stat
import sys
import tempfile


FINDING = re.compile(r"^- \[P[0-3]\] .+ - .+:[0-9]+$", re.MULTILINE)
REVIEW_NAME = re.compile(r"[0-9]+-[0-9a-f]{40}\.txt\Z")


def verdict(output_path):
    """Classify the final review output using Anvil's fail-closed contract."""
    try:
        output = Path(output_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "unparseable"
    if output in ("ANVIL_NO_FINDINGS", "ANVIL_NO_FINDINGS\n"):
        return "clean"
    if FINDING.search(output):
        return "findings"
    return "unparseable"


def private_directory(path):
    """Create or validate a runner-owned directory with mode 0700."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError(f"Unsafe Anvil review directory: {path}")
    path.chmod(0o700)


def store(output_path, repository, run_id, head_sha):
    """Store already-redacted output privately and retain the newest 50 files."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("Invalid repository name")
    if not re.fullmatch(r"[0-9]+", run_id):
        raise RuntimeError("Invalid workflow run ID")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise RuntimeError("Invalid pull request head SHA")

    home = Path.home()
    if not home.is_absolute():
        raise RuntimeError("HOME must be an absolute path")
    top = home / "anvil-reviews"
    private_directory(top)
    review_directory = top / repository.replace("/", "__")
    private_directory(review_directory)
    review_root = review_directory.resolve()
    for excluded in (os.environ.get("RUNNER_TEMP"), os.environ.get("GITHUB_WORKSPACE")):
        if excluded:
            excluded_root = Path(excluded).resolve()
            if os.path.commonpath((review_root, excluded_root)) == str(excluded_root):
                raise RuntimeError("Anvil review output must stay outside runner temp and checkout")

    destination = review_directory / f"{run_id}-{head_sha}.txt"
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError(f"Unsafe existing Anvil review file: {destination}")

    temporary_fd, temporary_name = tempfile.mkstemp(prefix=".anvil-review.", dir=review_directory)
    try:
        os.fchmod(temporary_fd, 0o600)
        with os.fdopen(temporary_fd, "wb") as target, open(output_path, "rb") as source:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_name, destination)
        destination.chmod(0o600)
    except BaseException:
        try:
            os.close(temporary_fd)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    reviews = []
    for candidate in review_directory.iterdir():
        if not REVIEW_NAME.fullmatch(candidate.name):
            continue
        info = candidate.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid():
            reviews.append((info.st_mtime_ns, candidate))
    reviews.sort(key=lambda item: (item[0], item[1].name), reverse=True)
    for _, old_review in reviews[50:]:
        old_review.unlink()

    print(destination)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "verdict":
        print(verdict(sys.argv[2]))
    elif len(sys.argv) == 6 and sys.argv[1] == "store":
        try:
            store(*sys.argv[2:])
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Anvil review storage failed: {error}", file=sys.stderr)
            raise SystemExit(1)
    else:
        raise SystemExit("Usage: anvil-output.py verdict FILE | store OUTPUT REPOSITORY RUN_ID HEAD_SHA")
