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


def run_in(d, argv, env, until, name="log", plant=None):
    """redteam.run with the log dir fd opened as bench() does; `plant` creates a file at the log path first."""
    if plant:
        plant(Path(d) / name)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return redteam.run(argv, d, env, fd, name, until)
    finally:
        os.close(fd)


class RunTest(unittest.TestCase):
    def run_sh(self, cmd, budget):
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            rc, out = run_in(d, ["/bin/sh", "-c", cmd], os.environ.copy(), start + budget)
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

    def sink(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.settimeout(0.2)
        self.addCleanup(s.close)
        return s

    def send(self, s, n):
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(n):
            c.sendto(b"x", s.getsockname())
        c.close()

    def test_sink_drain_waits_for_nothing_after_the_deadline(self):
        s = self.sink()
        start = time.monotonic()
        self.assertEqual(redteam.sink_hits(s, start - 1), 0)  # expired and empty: returns at once
        self.assertLess(time.monotonic() - start, 0.1)

    def test_datagrams_queued_at_the_deadline_still_count(self):
        s = self.sink()
        self.send(s, 3)
        self.assertEqual(redteam.sink_hits(s, time.monotonic() - 1), 3)


class RunFaultTest(unittest.TestCase):
    def test_wrap_that_cannot_launch_is_a_fault_row_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = run_in(d, ["/nonexistent/nocklock"], {}, time.monotonic() + 5)
        self.assertIsNone(rc)
        self.assertIn("HARNESS-FAULT", out)

    def test_failed_process_group_cleanup_is_a_harness_fault(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("os.killpg", side_effect=PermissionError("root-owned")):
            rc, out = run_in(d, ["/bin/sh", "-c", "echo done"], os.environ.copy(), time.monotonic() + 5)
        self.assertEqual(rc, 0)
        self.assertIsInstance(rc, redteam.FaultExit)
        self.assertIn("killpg", out)

    def test_breach_survives_a_failed_cleanup_as_allowed_plus_fault(self):
        atk = {"evidence": "nocklock", "expect": "blocked", "blocked_exit": [1]}
        executed, fault = redteam.classify(redteam.FaultExit(0), atk)
        self.assertTrue(executed)
        self.assertTrue(fault)

    def test_interrupt_kills_the_attack_process_group(self):
        orig, calls = subprocess.Popen.wait, []
        with tempfile.TemporaryDirectory() as d:
            pidfile = Path(d) / "pid"

            def wait(proc, *args, **kw):
                if not calls:  # first wait is the interrupt, raised once the attack has really started
                    calls.append(1)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not pidfile.exists():
                        time.sleep(0.01)
                    raise KeyboardInterrupt
                return orig(proc, *args, **kw)

            with mock.patch.object(subprocess.Popen, "wait", autospec=True, side_effect=wait):
                with self.assertRaises(KeyboardInterrupt):
                    run_in(d, ["/bin/sh", "-c", f"echo $$ > {pidfile}.tmp; mv {pidfile}.tmp {pidfile}; sleep 60"],
                           os.environ.copy(), time.monotonic() + 30)
            pid = int(pidfile.read_text())  # fails loudly if the attack never started
            time.sleep(0.2)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


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
    mcp = {"evidence": "nockguard", "expect": "blocked", "blocked_exit": [1]}

    def test_mcp_client_exit_codes(self):
        self.assertEqual(redteam.classify(0, self.mcp), (True, False))
        self.assertEqual(redteam.classify(1, self.mcp), (False, False))
        self.assertEqual(redteam.classify(5, self.mcp), (True, True))  # breach survives a shutdown fault
        self.assertEqual(redteam.classify(4, self.mcp), (False, True))  # a fault is never BLOCKED
        self.assertEqual(redteam.classify(3, self.mcp), (False, True))

    def test_child_output_cannot_declare_a_fault(self):
        self.assertEqual(redteam.classify(1, {"evidence": "nocklock", "expect": "blocked", "blocked_exit": [1]}), (False, False))

    def test_only_declared_exits_are_a_block(self):
        atk = {"evidence": "nocklock", "expect": "blocked", "blocked_exit": [35]}
        self.assertEqual(redteam.classify(35, atk), (False, False))
        self.assertEqual(redteam.classify(1, atk), (False, True))  # a crashed client's own exit
        self.assertEqual(redteam.classify(127, atk), (False, True))
        self.assertEqual(redteam.classify(0, atk), (True, False))
        self.assertEqual(redteam.classify(None, atk), (False, True))
        self.assertEqual(redteam.classify(1, {**atk, "blocked_exit": []}), (False, True))  # undeclared: no silent pass


class McpClientTest(unittest.TestCase):
    """The client decides the verdict when the reply arrives; a hung shutdown cannot undo it."""
    def run_client(self, reply_text, hang=False, exit_code=0):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "proxy.py"
            fake.write_text(
                "import json, sys, time\n"
                "for line in sys.stdin:\n"
                "    mid = json.loads(line)['id']\n"
                "    print(json.dumps({'jsonrpc': '2.0', 'id': mid, 'result': {'content': %r}}), flush=True)\n"
                "    if mid == 2 and %r:\n"
                "        time.sleep(30)  # ignores stdin EOF: the client's shutdown must time out\n"
                "sys.exit(%d)\n" % (reply_text, hang, exit_code))
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

    def test_nonzero_proxy_exit_is_a_fault_whatever_the_reply(self):
        rc, out = self.run_client("denied", exit_code=3)
        self.assertEqual(rc, 4)
        self.assertIn("HARNESS-FAULT", out)
        self.assertEqual(self.run_client("UPSTREAM-EXECUTED:t", exit_code=3)[0], 5)

    def test_stopped_reply_with_hung_shutdown_is_a_fault_not_a_block(self):
        rc, out = self.run_client("denied", hang=True)
        self.assertEqual(rc, 4)
        self.assertIn("STOPPED", out)


class LogPlantTest(unittest.TestCase):
    """The harness writes only regular files it created itself; a planted path is a fault, within the deadline."""
    def check(self, plant, after=None):
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            rc, out = run_in(d, ["/bin/true"], {}, start + 5, plant=plant)
            self.assertLess(time.monotonic() - start, 3)
            self.assertIsNone(rc)
            self.assertIn("HARNESS-FAULT", out)
            if after:
                after(Path(d))

    def test_a_symlinked_log_path_is_refused_and_its_target_untouched(self):
        def plant(log):
            (log.parent / "victim").write_text("keep")
            log.symlink_to(log.parent / "victim")
        self.check(plant, lambda d: self.assertEqual((d / "victim").read_text(), "keep"))

    def test_a_fifo_at_the_log_path_is_refused_without_blocking(self):
        self.check(lambda log: os.mkfifo(log))

    def test_a_dangling_symlink_is_refused(self):
        self.check(lambda log: log.symlink_to(log.parent / "nowhere"))


class VerdictTest(unittest.TestCase):
    def verdict(self, exit_code, expect="blocked", evidence="nockguard", control=None):
        atk = {"expect": expect, "evidence": evidence, "blocked_exit": [1]}
        executed, fault = redteam.classify(exit_code, atk)
        res = {"exit": exit_code, "ran": True, "planted": False, "fault": fault, "control": control}
        return redteam.verdict(res, atk, executed)

    def test_a_timed_out_attack_is_inconclusive_never_blocked(self):
        for evidence in ("nockguard", "nocklock"):
            self.assertEqual(self.verdict(124, evidence=evidence), ("INCONCLUSIVE", False))

    def test_a_timed_out_negative_control_is_inconclusive(self):
        self.assertEqual(self.verdict(124, expect="allowed"), ("INCONCLUSIVE", False))

    def test_a_timed_out_unfenced_control_is_inconclusive(self):
        self.assertEqual(self.verdict(1, control={"exit": 124, "reached": True}), ("INCONCLUSIVE", False))

    def test_clean_block_still_passes(self):
        self.assertEqual(self.verdict(1), ("BLOCKED", True))

    def test_a_datagram_at_the_dns_receiver_fails_the_attack_whatever_its_exit(self):
        atk = {"expect": "blocked", "evidence": "nocklock", "blocked_exit": [1]}
        res = {"exit": 1, "ran": True, "planted": True, "fault": False, "control": None}
        self.assertEqual(redteam.verdict(res, atk, False)[1], False)

    def test_an_undeclared_exit_is_a_harness_fault_not_a_block(self):
        for evidence in ("nockguard", "nocklock"):
            self.assertEqual(self.verdict(2, evidence=evidence), ("HARNESS-FAULT", False))


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
