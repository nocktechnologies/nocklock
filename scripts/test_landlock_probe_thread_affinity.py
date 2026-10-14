"""Pure controls for classifying the hosted old-helper negative receipt."""

import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "thread_affinity", Path(__file__).with_name("test-landlock-probe-thread-affinity.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.name = "TestLandlockChildCanMutateRootButNotRelocatedAudit"
        self.receipt = "\n".join(json.dumps(event) for event in [
            {"Action": "output", "Test": self.name,
             "Output": "write audit database error = <nil>, want EACCES or EPERM\n"},
            {"Action": "fail", "Test": self.name},
            {"Action": "fail", "Package": "landlock"},
        ])

    def test_expected_failure(self):
        self.assertTrue(harness.is_expected_failure(1, self.receipt))

    def test_timeout_panic_or_fatal_after_expected_marker(self):
        for diagnostic in ("panic: test timed out after 2m30s", "panic: unexpected panic",
                           "fatal error: all goroutines are asleep"):
            with self.subTest(diagnostic=diagnostic):
                extra = json.dumps({"Action": "output", "Output": diagnostic})
                self.assertFalse(harness.is_expected_failure(1, self.receipt + "\n" + extra))

    def test_unrelated_named_failure(self):
        extra = json.dumps({"Action": "fail", "Test": "TestUnrelated"})
        self.assertFalse(harness.is_expected_failure(1, self.receipt + "\n" + extra))

    def test_wrong_exit_or_signal(self):
        for code in (0, 2, -9, 124, 137):
            with self.subTest(code=code):
                self.assertFalse(harness.is_expected_failure(code, self.receipt))

    def test_incomplete_or_wrong_test_receipt(self):
        for receipt in ("compile error", self.receipt.replace("<nil>", "EIO"),
                        self.receipt.replace('"Action": "fail"', '"Action": "pass"'),
                        self.receipt.replace(self.name, "TestUnrelated")):
            with self.subTest(receipt=receipt):
                self.assertFalse(harness.is_expected_failure(1, receipt))


if __name__ == "__main__":
    unittest.main()
