#!/usr/bin/env python3
"""Acceptance report checks, shared by disposable-host CI and fixture tests."""

import json
import re
import sys


def check_doctor(report, code):
    boundaries = {b["name"]: b["posture"] for b in report["boundaries"]}
    for name in ("filesystem", "syscall", "network", "secrets", "signing-key"):
        assert boundaries[name] == "enforced", boundaries
    assert report["egress_level"] == "CONFINED", report
    if boundaries["unix-sockets"] == "enforced":
        assert code == 0 and report["verdict"] == "PROTECTED", report
    else:
        # doctor distinguishes the running advisory boundary from the backend
        # check's "unavailable" status. Accept only the named ABI 1..8 limit.
        assert boundaries["unix-sockets"] == "advisory", boundaries
        assert code == 3 and report["verdict"] == "PARTIAL", report
        check = next(c for c in report["checks"] if c["name"] == "unix-sockets")
        assert check["status"] == "unavailable", check
        assert re.search(r"reason=landlock_abi_[1-8]_below_9\b", check["message"]), check
    assert all(value == "enforced" or (name == "unix-sockets" and code == 3)
               for name, value in boundaries.items()), boundaries


if __name__ == "__main__":
    check_doctor(json.load(open(sys.argv[1])), int(sys.argv[2]))
