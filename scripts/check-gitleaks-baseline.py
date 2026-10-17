#!/usr/bin/env python3
"""Fail CI when the secret scan finds a fingerprint outside the historical set."""

import json
import pathlib
import sys


def load_findings(path):
    """Load a JSON finding list, rejecting incomplete scanner output."""
    findings = json.loads(path.read_text())
    if not isinstance(findings, list):
        raise ValueError(f"{path}: expected a JSON list")
    for entry in findings:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("Fingerprint"), str)
            or not entry["Fingerprint"].strip()
        ):
            raise ValueError(f"{path}: finding has no nonempty Fingerprint")
    return findings


def unexpected_findings(baseline, report):
    """Return findings whose exact scan fingerprint is not in the baseline."""
    known = [entry["Fingerprint"] for entry in baseline]
    if len(known) != len(set(known)):
        raise ValueError("duplicate fingerprint in secret-scan baseline")
    known = set(known)
    return [entry for entry in report if entry["Fingerprint"] not in known]


def main():
    """Check the comparison controls, then compare the current scan report."""
    if unexpected_findings([{"Fingerprint": "old"}], [{"Fingerprint": "old"}]):
        raise SystemExit("secret-scan control failed: historical finding rejected")
    if not unexpected_findings([{"Fingerprint": "old"}], [{"Fingerprint": "new"}]):
        raise SystemExit("secret-scan control failed: new finding accepted")
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-gitleaks-baseline.py <scan-report.json>")
    try:
        baseline = load_findings(pathlib.Path(".gitleaks-baseline.json"))
        report = load_findings(pathlib.Path(sys.argv[1]))
        unexpected = unexpected_findings(baseline, report)
    except (OSError, ValueError) as error:
        print(f"Secret scan: FAIL: {error}", file=sys.stderr)
        return 1
    if unexpected:
        for finding in unexpected:
            print("New secret-scan finding:", finding["Fingerprint"], file=sys.stderr)
        return 1
    print(f"Secret scan: PASS ({len(report)} historical findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
