#!/usr/bin/env python3
"""Reject previously exposed internal identifiers in tracked public files."""

import difflib
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
    """Check the classifier and scan tracked files, except unchanged release history on next."""
    if not all(contains_forbidden("prefix " + term + " suffix") for term in FORBIDDEN + PERSONAL_NAMES):
        raise SystemExit("public-content control failed: retired identifier accepted")
    if contains_forbidden("host=<host> user=<user> home=<home>") or contains_forbidden("mar" + "athon and ad" + "mi" + "ration are ordinary words"):
        raise SystemExit("public-content control failed: allowed text rejected")

    root = pathlib.Path(subprocess.check_output(("git", "rev-parse", "--show-toplevel"), text=True).strip())
    tracked = subprocess.check_output(("git", "ls-files", "-z"), cwd=root).split(b"\0")
    history = subprocess.check_output(("git", "show", "origin/next:CHANGELOG.md"), cwd=root).decode("utf-8", errors="replace").splitlines()
    violations = []
    for raw_path in filter(None, tracked):
        relative = pathlib.Path(raw_path.decode())
        path = root / relative
        if path.is_symlink():
            content = str(path.readlink()).encode()
        elif path.is_file():
            content = path.read_bytes()
        else:
            continue
        if b"\0" in content:
            print(f"Public content: {relative.as_posix()}: NUL bytes present; scanning decoded content")
        lines = content.decode("utf-8", errors="replace").splitlines()
        exempt = set()
        if relative.as_posix() == "CHANGELOG.md" and not path.is_symlink():
            for block in difflib.SequenceMatcher(None, history, lines, autojunk=False).get_matching_blocks():
                exempt.update(range(block.b, block.b + block.size))
        for number, line in enumerate(lines):
            if number not in exempt and contains_forbidden(line):
                violations.append(f"{relative.as_posix()}:{number + 1}")
    if violations:
        print("Public content contains retired identifiers:", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("Public content check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
