"""Pure controls for classifying the hosted old-helper negative receipt."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_every_audit_operation_escape(self):
        for operation in ("truncate audit database", "unlink audit database", "rename audit database",
                          "create file in audit directory", "remove audit directory"):
            with self.subTest(operation=operation):
                receipt = self.receipt.replace("write audit database", operation)
                self.assertTrue(harness.is_expected_failure(1, receipt))

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


class ProcessCleanupTests(unittest.TestCase):
    def test_group_cleanup_on_every_exit_path(self):
        for outcome in (0, 1, subprocess.TimeoutExpired("go", 180), KeyboardInterrupt()):
            with self.subTest(outcome=repr(outcome)), tempfile.TemporaryDirectory() as scratch:
                proc = Mock(pid=12345, returncode=1)
                proc.wait.side_effect = [outcome, 1]
                log = Path(scratch) / "receipt"
                printed = io.StringIO()
                with patch.object(harness.subprocess, "Popen", return_value=proc), \
                     patch.object(harness.os, "killpg") as kill, contextlib.redirect_stdout(printed):
                    if isinstance(outcome, subprocess.TimeoutExpired):
                        with self.assertRaises(SystemExit):
                            harness.run_control(["go"], scratch, {}, log, "CONTROL")
                    elif isinstance(outcome, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            harness.run_control(["go"], scratch, {}, log, "CONTROL")
                    else:
                        code, _ = harness.run_control(["go"], scratch, {}, log, "CONTROL")
                        self.assertEqual(code, outcome)
                    kill.assert_called_once_with(proc.pid, signal.SIGKILL)
                    self.assertEqual(proc.wait.call_count, 2)
                    self.assertIn("CONTROL exit=", printed.getvalue())

    def test_receipt_survives_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as scratch:
            proc = Mock(pid=12345, returncode=None)
            proc.wait.side_effect = [1, subprocess.TimeoutExpired("go", 5)]
            printed = io.StringIO()
            with patch.object(harness.subprocess, "Popen", return_value=proc), \
                 patch.object(harness.os, "killpg"), contextlib.redirect_stdout(printed):
                with self.assertRaises(subprocess.TimeoutExpired):
                    harness.run_control(["go"], scratch, {}, Path(scratch) / "receipt", "CONTROL")
            self.assertIn("CONTROL exit=", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
