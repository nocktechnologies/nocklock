import contextlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest import TestCase, main as unittest_main, mock

import kernel_cases


class KernelReceiptTest(TestCase):
    def setUp(self):
        kernel_cases._termination_requested = None
        self.addCleanup(setattr, kernel_cases, "_termination_requested", None)

    def test_timeout_is_failure_even_after_pass_and_zero_leader_exit(self):
        # A real fake-go process emits valid passing test JSON, then leaves a
        # descendant holding output. The leader exits 0: returncode cannot be
        # used to decide whether the harness deadline succeeded.
        for leader_waits in (False, True):
            with self.subTest(leader_waits=leader_waits), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                test = kernel_cases.CASES[1][2]
                stub = root / "go"
                stub.write_text(f"#!{sys.executable}\n" +
                                "import json, os, time\n" +
                                f"print(json.dumps(dict(Test={test!r}, Action='pass')), flush=True)\n" +
                                "if os.fork() == 0:\n    time.sleep(30)\n    os._exit(0)\n" +
                                ("time.sleep(30)\n" if leader_waits else "os._exit(0)\n"))
                stub.chmod(0o700)
                start = time.monotonic()
                with mock.patch.dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]), \
                     mock.patch("kernel_cases.CASE_TIMEOUT_SECONDS", 0.3), \
                     mock.patch("kernel_cases.CLEANUP_TIMEOUT_SECONDS", 0.3):
                    with self.assertRaisesRegex(ValueError, "Harness timeout"):
                        kernel_cases.run_case(root, root, *kernel_cases.CASES[1])
                self.assertLess(time.monotonic() - start, 2)
                self.assertIn('"Action": "pass"', (root / "abi9.jsonl").read_text())
                self.assertIn("Harness timeout", (root / "abi9.stderr.txt").read_text())

    def test_postkill_output_drain_has_a_deadline(self):
        # The escaped child holds both pipes even after killpg. This is a real
        # process, not a mocked communicate; cleanup removes only our own child.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / "escaped-pid"
            stub = root / "go"
            stub.write_text(f"#!{sys.executable}\n" +
                            "import os, pathlib, time\n" +
                            "print('partial receipt', flush=True)\n" +
                            "if os.fork() == 0:\n    os.setsid()\n" +
                            f"    pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))\n" +
                            "    time.sleep(3)\n    os._exit(0)\n" +
                            "time.sleep(30)\n")
            stub.chmod(0o700)
            try:
                start = time.monotonic()
                with mock.patch.dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]), \
                     mock.patch("kernel_cases.CASE_TIMEOUT_SECONDS", 0.3), \
                     mock.patch("kernel_cases.CLEANUP_TIMEOUT_SECONDS", 0.3):
                    with self.assertRaisesRegex(ValueError, "output drain exceeded"):
                        kernel_cases.run_case(root, root, *kernel_cases.CASES[1])
                self.assertLess(time.monotonic() - start, 2)
                self.assertIn("partial receipt", (root / "abi9.jsonl").read_text())
                self.assertIn("output drain exceeded", (root / "abi9.stderr.txt").read_text())
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_interrupt_kills_the_owned_process_group(self):
        # The stub and its child share the session Popen created and ignore
        # SIGTERM, so the SIGKILL fallback is exercised too. A real SIGINT
        # arrives while communicate() waits.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / "leader-pid"
            stub = root / "go"
            stub.write_text(f"#!{sys.executable}\n" +
                            "import os, pathlib, signal, time\n" +
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" +
                            "if os.fork() == 0:\n    time.sleep(30)\n    os._exit(0)\n" +
                            f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))\n" +
                            "time.sleep(30)\n")
            stub.chmod(0o700)

            def interrupt_when_ready():
                deadline = time.monotonic() + 10
                while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
                    time.sleep(0.02)
                os.kill(os.getpid(), signal.SIGINT)

            old = signal.signal(signal.SIGINT, signal.default_int_handler)
            threading.Thread(target=interrupt_when_ready, daemon=True).start()
            try:
                with mock.patch.dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]), \
                     mock.patch("kernel_cases.SIGTERM_GRACE_SECONDS", 0.2), \
                     mock.patch("kernel_cases.CLEANUP_TIMEOUT_SECONDS", 1):
                    with self.assertRaises(KeyboardInterrupt):
                        kernel_cases.run_case(root, root, *kernel_cases.CASES[1])
                pgid = int(pidfile.read_text())
                gone = False
                for _ in range(100):
                    try:
                        os.killpg(pgid, 0)
                    except ProcessLookupError:
                        gone = True
                        break
                    time.sleep(0.05)
                self.assertTrue(gone, "process group survived the interrupt")
            finally:
                signal.signal(signal.SIGINT, old)
                if pidfile.exists() and pidfile.read_text():
                    try:
                        os.killpg(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_second_interrupt_during_grace_wait_still_kills_the_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pidfile = root / "leader-pid"
            stub = root / "go"
            stub.write_text(f"#!{sys.executable}\n" +
                            "import os, pathlib, signal, time\n" +
                            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" +
                            "if os.fork() == 0:\n    time.sleep(30)\n    os._exit(0)\n" +
                            f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))\n" +
                            "time.sleep(30)\n")
            stub.chmod(0o700)

            def interrupt_twice():
                deadline = time.monotonic() + 10
                while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
                    time.sleep(0.02)
                os.kill(os.getpid(), signal.SIGINT)  # enters cleanup
                time.sleep(0.3)                      # inside the 1s grace wait
                os.kill(os.getpid(), signal.SIGINT)

            old = signal.signal(signal.SIGINT, signal.default_int_handler)
            threading.Thread(target=interrupt_twice, daemon=True).start()
            try:
                with mock.patch.dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]), \
                     mock.patch("kernel_cases.SIGTERM_GRACE_SECONDS", 1), \
                     mock.patch("kernel_cases.CLEANUP_TIMEOUT_SECONDS", 1):
                    with self.assertRaises(KeyboardInterrupt):
                        kernel_cases.run_case(root, root, *kernel_cases.CASES[1])
                self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
                pgid = int(pidfile.read_text())
                gone = False
                for _ in range(100):
                    try:
                        os.killpg(pgid, 0)
                    except ProcessLookupError:
                        gone = True
                        break
                    time.sleep(0.05)
                self.assertTrue(gone, "process group survived the second interrupt")
            finally:
                signal.signal(signal.SIGINT, old)
                if pidfile.exists() and pidfile.read_text():
                    try:
                        os.killpg(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_sigterm_during_timeout_cleanup_stops_the_harness(self):
        # The first case times out; its cleanup drain is held open by an escaped
        # child. SIGTERM arrives during that drain. It must be recorded, not
        # dropped: main exits 143 and never starts the second case.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "starts"
            escaped = root / "escaped"
            stub = root / "go"
            stub.write_text(f"#!{sys.executable}\n" +
                            "import os, pathlib, time\n" +
                            f"open({str(log)!r}, 'a').write(str(os.getpid()) + '\\n')\n" +
                            "if os.fork() == 0:\n    os.setsid()\n" +
                            f"    open({str(escaped)!r}, 'a').write(str(os.getpid()) + '\\n')\n" +
                            "    time.sleep(4)\n    os._exit(0)\n" +
                            "time.sleep(30)\n")
            stub.chmod(0o700)
            cases = (("a", "pkg", kernel_cases.CASES[1][2]), ("b", "pkg", kernel_cases.CASES[1][2]))
            old = signal.getsignal(signal.SIGTERM)
            timer = threading.Timer(0.6, os.kill, (os.getpid(), signal.SIGTERM))
            timer.start()
            try:
                with mock.patch.dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"]), \
                     mock.patch("kernel_cases.CASES", cases), \
                     mock.patch("kernel_cases.CASE_TIMEOUT_SECONDS", 0.3), \
                     mock.patch("kernel_cases.CLEANUP_TIMEOUT_SECONDS", 1.5), \
                     mock.patch("sys.argv", ["kernel_cases.py", "--out", str(root / "out")]):
                    with self.assertRaises(SystemExit) as raised:
                        kernel_cases.main()
                self.assertEqual(raised.exception.code, 143)
                starts = log.read_text().split()
                self.assertEqual(len(starts), 1, "a second case started after SIGTERM")
                for _ in range(100):
                    try:
                        os.killpg(int(starts[0]), 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("process group survived")
            finally:
                timer.cancel()
                signal.signal(signal.SIGTERM, old)
                for pid in (escaped.read_text().split() if escaped.exists() else []):
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_git_head_failure_yields_unknown_and_report_is_written(self):
        import subprocess
        saved = signal.getsignal(signal.SIGTERM)
        # main() installs its own SIGTERM handler and never restores it.
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            row = dict(case="x", verdict="PASS", reason="stub")
            with mock.patch("kernel_cases.platform.system", return_value="Linux"), \
                 mock.patch("kernel_cases.run_case", return_value=row), \
                 mock.patch("kernel_cases.subprocess.check_output",
                            side_effect=subprocess.CalledProcessError(128, "git")), \
                 mock.patch("sys.argv", ["kernel_cases.py", "--out", str(out)]):
                self.assertEqual(kernel_cases.main(), 0)
            self.assertEqual(json.loads((out / "report.json").read_text())["commit"], "unknown")
            self.assertTrue((out / "REPORT.md").exists())

    def test_git_head_test_restores_the_sigterm_handler(self):
        name = "test_kernel_cases.KernelReceiptTest.test_git_head_failure_yields_unknown_and_report_is_written"
        # Start from a known handler so earlier tests cannot mask a leak.
        self.addCleanup(signal.signal, signal.SIGTERM, signal.getsignal(signal.SIGTERM))
        signal.signal(signal.SIGTERM, lambda signum, frame: None)
        before = signal.getsignal(signal.SIGTERM)
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromName(name).run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_cleanup_fault_after_interrupt_reaches_stderr(self):
        # communicate() is interrupted. The SIGKILL in cleanup then fails with
        # PermissionError. The fault must be reported and the interrupt kept.
        process = mock.Mock(pid=4242)
        process.communicate.side_effect = [KeyboardInterrupt, ("", "")]
        process.wait.return_value = 0

        def killpg(pgid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError("denied")

        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("kernel_cases.subprocess.Popen", return_value=process), \
             mock.patch("kernel_cases.os.killpg", side_effect=killpg), \
             contextlib.redirect_stderr(stderr):
            root = Path(directory)
            with self.assertRaises(KeyboardInterrupt):
                kernel_cases.run_case(root, root, *kernel_cases.CASES[1])
        self.assertIn("kernel_cases: cleanup after interrupt", stderr.getvalue())
        self.assertIn("process-group kill failed: denied", stderr.getvalue())

    def test_broken_stderr_cannot_replace_the_interrupt(self):
        process = mock.Mock(pid=4242)
        process.communicate.side_effect = [KeyboardInterrupt, ("", "")]
        process.wait.return_value = 0

        class BrokenStderr:
            def write(self, text):
                raise BrokenPipeError("closed")

            def flush(self):
                pass

        def killpg(pgid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError("denied")

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("kernel_cases.subprocess.Popen", return_value=process), \
             mock.patch("kernel_cases.os.killpg", side_effect=killpg), \
             mock.patch("sys.stderr", BrokenStderr()):
            root = Path(directory)
            with self.assertRaises(KeyboardInterrupt):
                kernel_cases.run_case(root, root, *kernel_cases.CASES[1])

    def test_missing_failed_and_malformed_cannot_pass(self):
        test = kernel_cases.CASES[1][2]
        for raw, code in (("", 0), ("not json", 0), (json.dumps(dict(Test=test, Action="fail")), 1),
                          (json.dumps(dict(Test=test, Action="pass")), 1)):
            with self.subTest(raw=raw, code=code):
                with self.assertRaises(ValueError): kernel_cases.parse_result(raw, test, code)

    def test_abi9_skip_is_gap_not_pass(self):
        test = kernel_cases.CASES[1][2]
        raw = "\n".join(json.dumps(e) for e in [dict(Test=test, Action="output", Output="ABI9_COVERAGE_GAP: real kernel ABI 6 < 9"), dict(Test=test, Action="skip")])
        row = kernel_cases.classify("abi9", *kernel_cases.parse_result(raw, test, 0))
        self.assertEqual(row["verdict"], "SKIP")
        self.assertEqual(kernel_cases.classify("abi9", {test: "pass"}, "")["verdict"], "PASS")

    def test_unavailable_io_uring_is_not_a_block(self):
        test = kernel_cases.CASES[2][2]
        row = kernel_cases.classify("io-uring", {test: "skip"}, "ambient io_uring control is unavailable (probe exit 10)")
        self.assertEqual(row["verdict"], "SKIP")
        with self.assertRaises(ValueError): kernel_cases.classify("io-uring", {test: "skip"}, "C compiler unavailable")

    def test_reachable_unix_sockets_are_known_limit(self):
        test = kernel_cases.CASES[0][2]
        actions = {test: "pass", test + "/default_below_ABI_9_runs_and_records_reachability": "pass",
                   test + "/strict_config_refuses_below_ABI_9": "pass",
                   test + "/Landlock_ABI_9_enforcement_with_filesystem_rules": "skip",
                   test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied": "skip"}
        self.assertEqual(kernel_cases.classify("unix-wrap", actions, "")["verdict"], "KNOWN-LIMIT")
        actions[test + "/Landlock_ABI_9_enforcement_with_filesystem_rules"] = "pass"
        with self.assertRaises(ValueError): kernel_cases.classify("unix-wrap", actions, "")

    def test_abi9_wrap_requires_both_enforcement_paths(self):
        test = kernel_cases.CASES[0][2]
        actions = {test: "pass", test + "/default_below_ABI_9_runs_and_records_reachability": "skip",
                   test + "/strict_config_refuses_below_ABI_9": "skip",
                   test + "/Landlock_ABI_9_enforcement_with_filesystem_rules": "pass",
                   test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied": "pass"}
        self.assertEqual(kernel_cases.classify("unix-wrap", actions, "")["verdict"], "PASS")
        del actions[test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied"]
        with self.assertRaises(ValueError): kernel_cases.classify("unix-wrap", actions, "")


if __name__ == "__main__":
    unittest_main()
