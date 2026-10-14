import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

from kernel_cases import CASES, classify, parse_result, run_case


class KernelReceiptTest(unittest.TestCase):
    def test_timeout_is_failure_even_after_pass_and_zero_leader_exit(self):
        # A real fake-go process emits valid passing test JSON, then leaves a
        # descendant holding output. The leader exits 0: returncode cannot be
        # used to decide whether the harness deadline succeeded.
        for leader_waits in (False, True):
            with self.subTest(leader_waits=leader_waits), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                test = CASES[1][2]
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
                        run_case(root, root, *CASES[1])
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
                        run_case(root, root, *CASES[1])
                self.assertLess(time.monotonic() - start, 2)
                self.assertIn("partial receipt", (root / "abi9.jsonl").read_text())
                self.assertIn("output drain exceeded", (root / "abi9.stderr.txt").read_text())
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_missing_failed_and_malformed_cannot_pass(self):
        test = CASES[1][2]
        for raw, code in (("", 0), ("not json", 0), (json.dumps(dict(Test=test, Action="fail")), 1),
                          (json.dumps(dict(Test=test, Action="pass")), 1)):
            with self.subTest(raw=raw, code=code):
                with self.assertRaises(ValueError): parse_result(raw, test, code)

    def test_abi9_skip_is_gap_not_pass(self):
        test = CASES[1][2]
        raw = "\n".join(json.dumps(e) for e in [dict(Test=test, Action="output", Output="ABI9_COVERAGE_GAP: real kernel ABI 6 < 9"), dict(Test=test, Action="skip")])
        row = classify("abi9", *parse_result(raw, test, 0))
        self.assertEqual(row["verdict"], "SKIP")
        self.assertEqual(classify("abi9", {test: "pass"}, "")["verdict"], "PASS")

    def test_unavailable_io_uring_is_not_a_block(self):
        test = CASES[2][2]
        row = classify("io-uring", {test: "skip"}, "ambient io_uring control is unavailable (probe exit 10)")
        self.assertEqual(row["verdict"], "SKIP")
        with self.assertRaises(ValueError): classify("io-uring", {test: "skip"}, "C compiler unavailable")

    def test_reachable_unix_sockets_are_known_limit(self):
        test = CASES[0][2]
        actions = {test: "pass", test + "/default_below_ABI_9_runs_and_records_reachability": "pass",
                   test + "/strict_config_refuses_below_ABI_9": "pass",
                   test + "/Landlock_ABI_9_enforcement_with_filesystem_rules": "skip",
                   test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied": "skip"}
        self.assertEqual(classify("unix-wrap", actions, "")["verdict"], "KNOWN-LIMIT")
        actions[test + "/Landlock_ABI_9_enforcement_with_filesystem_rules"] = "pass"
        with self.assertRaises(ValueError): classify("unix-wrap", actions, "")

    def test_abi9_wrap_requires_both_enforcement_paths(self):
        test = CASES[0][2]
        actions = {test: "pass", test + "/default_below_ABI_9_runs_and_records_reachability": "skip",
                   test + "/strict_config_refuses_below_ABI_9": "skip",
                   test + "/Landlock_ABI_9_enforcement_with_filesystem_rules": "pass",
                   test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied": "pass"}
        self.assertEqual(classify("unix-wrap", actions, "")["verdict"], "PASS")
        del actions[test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied"]
        with self.assertRaises(ValueError): classify("unix-wrap", actions, "")


if __name__ == "__main__":
    unittest.main()
