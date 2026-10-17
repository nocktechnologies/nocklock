#!/usr/bin/env python3
"""Fail when AGENTS.md names a repository path that does not exist."""

import pathlib
import re
import subprocess
import sys

# A backtick span with no whitespace that contains "/" is a path. Multi-word
# spans are commands (`go test ./...`) and bare file names are prose; both are skipped.
SPAN = re.compile(r"`([^`\s]*/[^`\s]*)`")


def missing_paths(text, root):
    """Return the paths named in text that do not exist under root."""
    return [path for path in SPAN.findall(text) if not (root / path).exists()]


def main():
    """Check the classifier, then every path AGENTS.md names."""
    root = pathlib.Path(subprocess.check_output(("git", "rev-parse", "--show-toplevel"), text=True).strip())
    if missing_paths("`scripts/` `AGENTS.md` `go test ./... -v`", root):
        raise SystemExit("agents-paths control failed: existing path or command rejected")
    if missing_paths("`docs/no-such-file.md`", root) != ["docs/no-such-file.md"]:
        raise SystemExit("agents-paths control failed: missing path accepted")

    missing = missing_paths((root / "AGENTS.md").read_text(encoding="utf-8"), root)
    if missing:
        print("AGENTS.md names paths that do not exist:", file=sys.stderr)
        print("\n".join(missing), file=sys.stderr)
        return 1
    print("AGENTS.md path check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
