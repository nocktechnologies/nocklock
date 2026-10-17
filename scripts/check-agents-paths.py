#!/usr/bin/env python3
"""Fail when AGENTS.md names a repository path that git does not track."""

import pathlib
import re
import subprocess
import sys

# A backtick span with no whitespace is a path when it contains "/" or ends in a
# lowercase file extension with a letter in it (so `v0.12.0` is not a path).
# Multi-word spans are commands (`go test ./...`) and spans with a <placeholder>
# or a glob are patterns; both are skipped. A link target may be wrapped in <>
# and followed by a "title"; only the target is checked.
SPAN = re.compile(r"`([^`\s]+)`")
LINK = re.compile(r"\]\(\s*(?:<([^>]*)>|([^)\s]+))")
EXTENSION = re.compile(r"\.[0-9]*[a-z][a-z0-9]{0,4}$")
PATTERN = re.compile(r"[<>*?\[\]]")


def named_paths(text):
    """Return the repo paths text names in backtick spans and link targets."""
    spans = [s for s in SPAN.findall(text) if ("/" in s or EXTENSION.search(s)) and not PATTERN.search(s)]
    links = [t.split("#", 1)[0] for t in map("".join, LINK.findall(text)) if ":" not in t]
    return spans + [t for t in links if t]


def bad_paths(text, root, tracked):
    """Return the paths text names that are outside root or not in tracked (files and their directories)."""
    bad = []
    for path in named_paths(text):
        target = (root / path).resolve()
        if not target.is_relative_to(root) or target.relative_to(root).as_posix() not in tracked:
            bad.append(path)
    return list(dict.fromkeys(bad))


def main():
    """Check the classifier, then every path AGENTS.md names."""
    root = pathlib.Path(subprocess.check_output(("git", "rev-parse", "--show-toplevel"), text=True).strip()).resolve()
    files = filter(None, subprocess.check_output(("git", "ls-files", "-z"), cwd=root, text=True).split("\0"))
    tracked = {str(p) for f in files for p in (pathlib.PurePosixPath(f), *pathlib.PurePosixPath(f).parents)}

    allowed = "`scripts/` `AGENTS.md` `go test ./... -v` `<home>/x` `docs/*.md` `t.TempDir()` `v0.12.0` [a](AGENTS.md#x) [b](https://example.com/a) [c](<AGENTS.md> \"t\")"
    if bad_paths(allowed, root, tracked):
        raise SystemExit("agents-paths control failed: tracked path, command or pattern rejected")
    planted = ["docs/no-such-file.md", "../AGENTS.md", "/tmp", ".git/HEAD", "docs/missing.md", "docs/titled.md", "docs/angled.md"]
    names = '`docs/no-such-file.md` `../AGENTS.md` `/tmp` `.git/HEAD` [c](docs/missing.md) [d](docs/titled.md "t") [e](<docs/angled.md>)'
    if bad_paths(names, root, tracked) != planted:
        raise SystemExit("agents-paths control failed: missing, escaping or untracked path accepted")

    bad = bad_paths((root / "AGENTS.md").read_text(encoding="utf-8"), root, tracked)
    if bad:
        print("AGENTS.md names paths that are missing, untracked or outside the repo:", file=sys.stderr)
        print("\n".join(bad), file=sys.stderr)
        return 1
    print("AGENTS.md path check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
