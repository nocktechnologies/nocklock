"""Mocked process-lifecycle controls; these never run the enforcement proof."""

import importlib.util
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import Mock, call, patch

spec = importlib.util.spec_from_file_location(
    "credential_proof", Path(__file__).with_name("test-credential-denies.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class ProcessCleanupTests(unittest.TestCase):
    def test_isolated_session_cleanup_on_every_exit_path(self):
        outcomes = [0, 73, subprocess.TimeoutExpired("proof", 30),
                    KeyboardInterrupt(), SystemExit(2), RuntimeError("read failed")]
        for outcome in outcomes:
            with self.subTest(outcome=repr(outcome)):
                process = Mock(pid=12345, returncode=outcome if isinstance(outcome, int) else None)
                process.communicate.side_effect = [
                    ("stdout", "stderr") if isinstance(outcome, int) else outcome,
                    ("", "")]
                with patch.object(harness.subprocess, "Popen", return_value=process) as popen, \
                     patch.object(harness.subprocess, "check_output", return_value="200 201\n300 301\n"), \
                     patch.object(harness.os, "getsid", side_effect=[process.pid, 99999]), \
                     patch.object(harness.os, "killpg") as kill:
                    if isinstance(outcome, BaseException):
                        with self.assertRaises(type(outcome)) as raised:
                            harness.run(["proof"], ".", {})
                        self.assertIs(raised.exception, outcome)
                    else:
                        result = harness.run(["proof"], ".", {})
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                                         (outcome, "stdout", "stderr"))
                    self.assertTrue(popen.call_args.kwargs["start_new_session"])
                    # A reaped launcher's pid may be reused: only signal it unreaped.
                    launcher = [] if isinstance(outcome, int) else [call(process.pid, signal.SIGKILL)]
                    self.assertEqual(kill.call_args_list, launcher + [call(201, signal.SIGKILL)])
                    self.assertEqual(process.communicate.call_args_list,
                                     [call(timeout=30), call(timeout=5)])

    def test_enumeration_failure_preserves_original_error_and_reaps(self):
        for error in [OSError("ps unavailable"), subprocess.CalledProcessError(1, "ps"),
                      subprocess.TimeoutExpired("ps", 5), ValueError("bad ps row")]:
            with self.subTest(error=repr(error)):
                original = KeyboardInterrupt()
                process = Mock(pid=12345, returncode=None)
                process.communicate.side_effect = [original, ("", "")]
                order = Mock()
                with patch.object(harness.subprocess, "Popen", return_value=process), \
                     patch.object(harness.subprocess, "check_output", side_effect=error) as ps, \
                     patch.object(harness.os, "killpg") as kill:
                    order.attach_mock(kill, "kill")
                    order.attach_mock(ps, "ps")
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        harness.run(["proof"], ".", {})
                    self.assertIs(raised.exception, original)
                    self.assertIn("process enumeration failed", original.__notes__[0])
                    self.assertEqual(order.mock_calls[0], call.kill(process.pid, signal.SIGKILL))
                    self.assertEqual(process.communicate.call_count, 2)

    def test_enumeration_failure_after_reap_signals_nothing(self):
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = ("", "")
        with patch.object(harness.subprocess, "Popen", return_value=process), \
             patch.object(harness.subprocess, "check_output", side_effect=OSError("ps unavailable")), \
             patch.object(harness.os, "killpg") as kill:
            with self.assertRaisesRegex(
                    RuntimeError, "process enumeration failed; descendants of this proof "
                                  "may still be running: ps unavailable"):
                harness.run(["proof"], ".", {})
            # The reaped launcher's pid may be reused: no survivor is verified,
            # so nothing is signalled and the error is the report.
            kill.assert_not_called()

    def test_enumeration_failure_tolerates_exited_launcher_group(self):
        original = subprocess.TimeoutExpired("proof", 30)
        process = Mock(pid=12345, returncode=None)
        process.communicate.side_effect = [original, ("", "")]
        with patch.object(harness.subprocess, "Popen", return_value=process), \
             patch.object(harness.subprocess, "check_output", side_effect=ValueError("bad ps row")), \
             patch.object(harness.os, "killpg", side_effect=ProcessLookupError()) as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.run(["proof"], ".", {})
            note, = original.__notes__
            self.assertRegex(note, "process enumeration failed.*bad ps row")
            self.assertNotIn("No such process", note)
            self.assertEqual(kill.call_args_list, [call(process.pid, signal.SIGKILL)])

    def test_cleanup_error_does_not_turn_success_into_pass(self):
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = ("", "")
        with patch.object(harness.subprocess, "Popen", return_value=process), \
             patch.object(harness.subprocess, "check_output", side_effect=OSError("ps unavailable")), \
             patch.object(harness.os, "killpg"):
            with self.assertRaisesRegex(RuntimeError, "ps unavailable"):
                harness.run(["proof"], ".", {})
            self.assertEqual(process.communicate.call_count, 2)

    def test_inaccessible_or_exited_processes_do_not_interrupt_cleanup(self):
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = ("", "")
        with patch.object(harness.subprocess, "Popen", return_value=process), \
             patch.object(harness.subprocess, "check_output", return_value="200 201\n300 301\n"), \
             patch.object(harness.os, "getsid", side_effect=[PermissionError(), process.pid]), \
             patch.object(harness.os, "killpg", side_effect=[ProcessLookupError()]) as kill:
            self.assertEqual(harness.run(["proof"], ".", {}).returncode, 0)
            self.assertEqual(kill.call_args_list, [call(301, signal.SIGKILL)])

    def test_pipe_timeout_closes_readers_and_bounds_launcher_reap(self):
        original = subprocess.TimeoutExpired("proof", 30)
        process = Mock(pid=12345, returncode=None)
        process.communicate.side_effect = [original, subprocess.TimeoutExpired("proof", 5)]
        with patch.object(harness.subprocess, "Popen", return_value=process), \
             patch.object(harness.subprocess, "check_output", return_value=""), \
             patch.object(harness.os, "killpg"):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                harness.run(["proof"], ".", {})
            self.assertIs(raised.exception, original)
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
