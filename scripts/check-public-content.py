#!/usr/bin/env python3
"""Reject previously exposed internal identifiers in tracked public files."""

import pathlib
import re
import subprocess
import sys


# Keep fragments separate so this guard does not itself contain the identifiers.
FORBIDDEN = tuple(
    part_a + part_b
    for part_a, part_b in (
        ("kk", "wil"),
        ("Kevins", "-Desktop"),
        ("/Users/", "kevin"),
        ("kevin", "linux"),
        ("Nock", "CC"),
        ("Kevin ", "sleeping"),
    )
)
PERSONAL_NAMES = tuple(part_a + part_b for part_a, part_b in (("Mi", "ra"), ("Ma", "ra")))
NAME_PATTERN = re.compile(r"(?<![a-z])(?:" + "|".join(PERSONAL_NAMES) + r")(?![a-z])", re.I)


def contains_forbidden(content):
    """Report whether text contains one of the retired public identifiers."""
    folded = content.casefold()
    return any(term.casefold() in folded for term in FORBIDDEN) or bool(NAME_PATTERN.search(content))


def main():
    """Check the classifier and scan tracked files, except release history."""
    assert all(contains_forbidden("prefix " + term + " suffix") for term in FORBIDDEN)
    assert all(contains_forbidden("prefix " + name + " suffix") for name in PERSONAL_NAMES)
    assert not contains_forbidden("host=<host> user=<user> home=<home>")
    assert not contains_forbidden("mar" + "athon and ad" + "mi" + "ration are ordinary words")

    tracked = subprocess.check_output(("git", "ls-files", "-z")).split(b"\0")
    violations = []
    for raw_path in filter(None, tracked):
        path = pathlib.Path(raw_path.decode())
        if path.as_posix() == "CHANGELOG.md":
            continue
        if path.is_symlink():
            content = str(path.readlink()).encode()
        elif path.is_file():
            content = path.read_bytes()
        else:
            continue
        if b"\0" not in content and contains_forbidden(content.decode("utf-8", errors="replace")):
            violations.append(path.as_posix())
    if violations:
        print("Public content contains retired identifiers:", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("Public content check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
