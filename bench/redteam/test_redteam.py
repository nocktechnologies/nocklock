"""Tests for the red-team driver's process handling. Run: python3 -m unittest bench/redteam/test_redteam.py"""
import os
import socket
import sys
import tempfile
import time
import unittest
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


if __name__ == "__main__":
    unittest.main()
