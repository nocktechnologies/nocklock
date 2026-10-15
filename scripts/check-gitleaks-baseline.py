#!/usr/bin/env python3
"""Fail CI when the secret scan finds a fingerprint outside the historical set."""

import json
import pathlib
import sys


def unexpected_findings(baseline, report):
    """Return findings whose exact scan fingerprint is not in the baseline."""
    known = [entry["Fingerprint"] for entry in baseline]
    if len(known) != len(set(known)):
        raise ValueError("duplicate fingerprint in secret-scan baseline")
    return [entry for entry in report if entry["Fingerprint"] not in known]


def main():
    """Check the comparison controls, then compare the current scan report."""
    assert not unexpected_findings([{"Fingerprint": "old"}], [{"Fingerprint": "old"}])
    assert unexpected_findings([{"Fingerprint": "old"}], [{"Fingerprint": "new"}])
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-gitleaks-baseline.py <scan-report.json>")
    baseline = json.loads(pathlib.Path(".gitleaks-baseline.json").read_text())
    report = json.loads(pathlib.Path(sys.argv[1]).read_text())
    unexpected = unexpected_findings(baseline, report)
    if unexpected:
        for finding in unexpected:
            print("New secret-scan finding:", finding["Fingerprint"], file=sys.stderr)
        return 1
    print(f"Secret scan: PASS ({len(report)} historical findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
