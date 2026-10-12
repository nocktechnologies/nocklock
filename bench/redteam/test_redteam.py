"""Tests for the red-team driver's process handling. Run: python3 -m unittest bench/redteam/test_redteam.py"""
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import redteam  # noqa: E402


class RunTest(unittest.TestCase):
    def run_sh(self, cmd, budget):
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            rc, out = redteam.run(["/bin/sh", "-c", cmd], d, os.environ.copy(), Path(d) / "log", start + budget)
            return rc, out, time.monotonic() - start

    def test_descendant_holding_stdout_cannot_stall_the_bench(self):
        # The attack exits at once but leaves a child running that holds its stdout/stderr.
        rc, out, took = self.run_sh("echo started; sleep 60 & exit 0", 10)
        self.assertEqual(rc, 0)
        self.assertIn("started", out)
        self.assertLess(took, 8)

    def test_hung_attack_is_killed_at_its_deadline_and_recorded(self):
        # The attack never exits and its child holds stdout; the group is SIGKILLed at the deadline.
        rc, out, took = self.run_sh("echo started; sleep 60 & sleep 60", 1)
        self.assertEqual(rc, 124)
        self.assertIn("timed out", out)
        self.assertIn("started", out)
        self.assertLess(took, 6)

    def test_sink_drain_stops_at_the_deadline(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(0.2)
        start = time.monotonic()
        self.assertEqual(redteam.sink_hits(s, start - 1), 0)  # already expired: drains nothing
        self.assertLess(time.monotonic() - start, 0.1)
        s.close()


class RunFaultTest(unittest.TestCase):
    def test_wrap_that_cannot_launch_is_a_fault_row_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = redteam.run(["/nonexistent/nocklock"], d, {}, Path(d) / "log", time.monotonic() + 5)
        self.assertIsNone(rc)
        self.assertIn("HARNESS-FAULT", out)

    def test_killpg_permission_error_is_recorded_and_the_run_continues(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("os.killpg", side_effect=PermissionError("root-owned")):
            rc, out = redteam.run(["/bin/sh", "-c", "echo done"], d, os.environ.copy(), Path(d) / "log", time.monotonic() + 5)
        self.assertEqual(rc, 0)
        self.assertIn("done", out)
        self.assertIn("killpg", out)


class SetupCheckTest(unittest.TestCase):
    def config(self, d, allow):
        (Path(d) / "root/.nock").mkdir(parents=True)
        cfg = Path(d) / "root/.nock/config.toml"
        cfg.write_text('[filesystem]\nroot = "."\nallow = %s\nallow_rw = []\n' % allow)
        return cfg

    def test_evidence_under_a_grant_is_a_setup_fault(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self.config(d, '["%s/"]' % d)
            with self.assertRaises(redteam.SetupFault) as cm:
                redteam.check_setup(cfg, {"nockguard key": Path(d) / "home/key"})
            self.assertIn("nockguard key", str(cm.exception))

    def test_evidence_beside_the_grants_passes(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self.config(d, '["%s/granted/"]' % d)
            redteam.check_setup(cfg, {"nockguard key": Path(d) / "home/key"})
            with self.assertRaises(redteam.SetupFault):
                redteam.check_setup(cfg, {"x": Path(d) / "granted/x"})


class ClassifyTest(unittest.TestCase):
    mcp = {"evidence": "nockguard"}

    def test_mcp_client_exit_codes(self):
        self.assertEqual(redteam.classify(0, self.mcp), (True, False))
        self.assertEqual(redteam.classify(1, self.mcp), (False, False))
        self.assertEqual(redteam.classify(5, self.mcp), (True, True))  # breach survives a shutdown fault
        self.assertEqual(redteam.classify(4, self.mcp), (False, True))  # a fault is never BLOCKED
        self.assertEqual(redteam.classify(3, self.mcp), (False, True))

    def test_child_output_cannot_declare_a_fault(self):
        self.assertEqual(redteam.classify(1, {"evidence": "nocklock"}), (False, False))


class McpClientTest(unittest.TestCase):
    """The client decides the verdict when the reply arrives; a hung shutdown cannot undo it."""
    def run_client(self, reply_text, hang=False):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "proxy.py"
            fake.write_text(
                "import json, sys, time\n"
                "for line in sys.stdin:\n"
                "    mid = json.loads(line)['id']\n"
                "    print(json.dumps({'jsonrpc': '2.0', 'id': mid, 'result': {'content': %r}}), flush=True)\n"
                "    if mid == 2 and %r:\n"
                "        time.sleep(30)  # ignores stdin EOF: the client's shutdown must time out\n" % (reply_text, hang))
            p = subprocess.run([sys.executable, str(Path(redteam.__file__).parent / "mcp_client.py"), "t", "1",
                                "--", sys.executable, str(fake)], capture_output=True, text=True, timeout=30)
            return p.returncode, p.stdout

    def test_executed_reply_exits_zero(self):
        self.assertEqual(self.run_client("UPSTREAM-EXECUTED:t")[0], 0)

    def test_stopped_reply_exits_one(self):
        rc, out = self.run_client("denied")
        self.assertEqual(rc, 1)
        self.assertIn("STOPPED", out)

    def test_executed_reply_is_a_breach_even_when_shutdown_hangs(self):
        rc, out = self.run_client("UPSTREAM-EXECUTED:t", hang=True)
        self.assertEqual(rc, 5)
        self.assertIn("EXECUTED", out)
        self.assertIn("HARNESS-FAULT", out)

    def test_stopped_reply_with_hung_shutdown_is_a_fault_not_a_block(self):
        rc, out = self.run_client("denied", hang=True)
        self.assertEqual(rc, 4)
        self.assertIn("STOPPED", out)


class LogSymlinkTest(unittest.TestCase):
    def test_a_symlinked_log_path_is_refused_and_its_target_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "victim"
            target.write_text("keep")
            log = Path(d) / "a.log"
            log.symlink_to(target)
            rc, out = redteam.run(["/bin/true"], d, {}, log, time.monotonic() + 5)
            self.assertIsNone(rc)
            self.assertIn("HARNESS-FAULT", out)
            self.assertEqual(target.read_text(), "keep")


class ControlTest(unittest.TestCase):
    def test_sink_packet_counts_as_reached_even_on_nonzero_exit(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(0.2)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.sendto(b"x", s.getsockname())
        c.close()
        hits = redteam.sink_hits(s, time.monotonic() + 2)
        s.close()
        self.assertEqual(hits, 1)
        self.assertTrue(redteam.control_result(1, hits)["reached"])

    def test_no_packet_and_failed_exit_is_not_reached(self):
        self.assertFalse(redteam.control_result(1, 0)["reached"])


if __name__ == "__main__":
    unittest.main()
