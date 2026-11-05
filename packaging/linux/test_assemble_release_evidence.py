"""Release evidence assembly rejects mixed commits and incomplete proofs."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location(
    "assemble_release_evidence", Path(__file__).with_name("assemble-release-evidence.py"))
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)

COMMIT = "a" * 40
TAG = "v1.2.3"
CLAIMS = [
    {"claim": "a-pathname-socket-outside-root", "expected": "DENIED", "actual": "DENIED"},
    {"claim": "b-abstract-socket", "expected": "DENIED", "actual": "DENIED"},
    {"claim": "c-allowed-proxy-socket", "expected": "CONNECTED", "actual": "CONNECTED"},
    {"claim": "c-allowed-event-socket", "expected": "CONNECTED", "actual": "CONNECTED"},
    {"claim": "d-io-uring-setup-denied", "expected": "PASS", "actual": "PASS"},
]


class AssembleReleaseEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.receipt = root / "receipt"
        self.acceptance = root / "acceptance"
        self.assets = root / "assets"
        for path in (self.receipt, self.acceptance, self.assets):
            path.mkdir()
        self.output = root / "output"
        self.report = {"commit": COMMIT, "verdict": "PASS", "landlock_abi": 9,
                       "claims": [claim.copy() for claim in CLAIMS]}
        self.accepted = {"kind": "release-install-acceptance", "commit": COMMIT,
                         "tag": TAG, "modes": ["proxy", "netns"]}
        (self.receipt / "landlock-abi9-receipt.json.sigstore.json").write_text("signed")
        archive = self.assets / f"nocklock_{TAG}_linux_amd64.tar.gz"
        archive.write_bytes(b"archive")
        (self.assets / "SHA256SUMS").write_text(f"{assembly.digest(archive)}  {archive.name}\n")
        for name in ("nocklock-install-linux-amd64", "INSTALLER.SHA256SUMS",
                     "INSTALLER.SHA256SUMS.sigstore.json"):
            (self.assets / name).write_text("signed")

    def assemble(self):
        (self.receipt / "landlock-abi9-receipt.json").write_text(json.dumps(self.report))
        (self.acceptance / "linux-release-acceptance.json").write_text(json.dumps(self.accepted))
        assembly.assemble(SimpleNamespace(receipt=self.receipt, acceptance=self.acceptance,
                                          assets=self.assets, output=self.output,
                                          commit=COMMIT, tag=TAG, dry_run=False))

    def test_release_hashes_both_evidence_files(self):
        self.assemble()
        manifest = (self.output / "SHA256SUMS").read_text()
        evidence = json.loads((self.output / "release-evidence.json").read_text())
        for name in ("linux-release-acceptance.json", "landlock-abi9-receipt.json"):
            expected = assembly.digest(self.output / name)
            self.assertIn(f"{expected}  {name}\n", manifest)
            self.assertEqual(evidence["sha256"][name], expected)
        self.assertTrue((self.output / "landlock-abi9-receipt.json.sigstore.json").is_file())

    def test_refuses_failed_or_mixed_commit_evidence(self):
        for change in (lambda: self.report.update(verdict="FAIL"),
                       lambda: self.report.update(landlock_abi=8),
                       lambda: self.report.update(commit="b" * 40),
                       lambda: self.accepted.update(commit="b" * 40),
                       lambda: self.accepted.update(modes=["proxy"])):
            with self.subTest(change=change):
                old_report, old_accepted = self.report.copy(), self.accepted.copy()
                change()
                with self.assertRaises(ValueError):
                    self.assemble()
                self.report, self.accepted = old_report, old_accepted

    def test_refuses_wrong_archive_hash(self):
        (self.assets / "SHA256SUMS").write_text("0" * 64 + "  wrong.tar.gz\n")
        with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
            self.assemble()

    def test_refuses_missing_duplicate_or_mismatched_claims(self):
        for claims in (
            [dict(claim) for claim in CLAIMS[:-1]] + [{"claim": "other", "expected": "PASS", "actual": "PASS"}],
            [dict(claim) for claim in CLAIMS[:-1]] + [dict(CLAIMS[0])],
            [dict(claim) for claim in CLAIMS[:-1]] + ["not a claim"],
            [dict(claim) for claim in CLAIMS[:-1]] + [{"claim": CLAIMS[-1]["claim"], "expected": "DENIED", "actual": "DENIED"}],
            [dict(claim) for claim in CLAIMS[:-1]] + [{"claim": CLAIMS[-1]["claim"], "expected": "PASS", "actual": "FAIL"}],
        ):
            with self.subTest(claims=claims):
                self.report["claims"] = claims
                with self.assertRaisesRegex(ValueError, "ABI 9 receipt is incomplete"):
                    self.assemble()

    def test_branch_dry_run_is_explicit_and_cannot_replace_release_acceptance(self):
        self.accepted = {"kind": "branch-dry-run-placeholder", "commit": COMMIT}
        with self.assertRaisesRegex(ValueError, "acceptance is incomplete"):
            self.assemble()
        self.output = Path(self.temp.name) / "dry-run"
        (self.receipt / "landlock-abi9-receipt.json").write_text(json.dumps(self.report))
        (self.acceptance / "linux-release-acceptance.json").write_text(json.dumps(self.accepted))
        assembly.assemble(SimpleNamespace(receipt=self.receipt, acceptance=self.acceptance,
                                          assets=None, output=self.output,
                                          commit=COMMIT, tag=None, dry_run=True))
        self.assertEqual(json.loads((self.output / "release-evidence.json").read_text())["kind"],
                         "branch-dry-run")


if __name__ == "__main__":
    unittest.main()
