"""Timeout regression for the confined Unix-socket probe."""

import contextlib
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


class ProbeTimeoutTest(unittest.TestCase):
    def run_case(self, parent_exits: bool, kill_group: bool):
        script_path = pathlib.Path(__file__).with_name("run-probe.py")
        spec = importlib.util.spec_from_file_location("run_probe", script_path)
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)

        with tempfile.TemporaryDirectory() as scratch:
            work = pathlib.Path(scratch) / "probe"
            work.mkdir()
            sentinel = pathlib.Path(scratch) / "descendant-survived"

            real_run_bounded = probe.run_bounded

            def fake_run(args, cwd, timeout):
                if args[0] == "go":
                    child_code = (
                        "import pathlib, time; time.sleep(1); "
                        f"pathlib.Path({str(sentinel)!r}).write_text('survived')"
                    )
                    pathlib.Path(args[3]).write_text(
                        "#!/usr/bin/env python3\n"
                        "import subprocess, sys, time\n"
                        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
                        "print('wrap-started', flush=True)\n"
                        + ("" if parent_exits else "time.sleep(2)\n")
                    )
                    os.chmod(args[3], 0o700)
                    return subprocess.CompletedProcess(args, 0, "", ""), False
                if args[1] == "init":
                    return subprocess.CompletedProcess(args, 0, "", ""), False
                return real_run_bounded(args, cwd, timeout)

            class Listener:
                def bind(self, _address):
                    pass

                def listen(self, _backlog):
                    pass

                def settimeout(self, _seconds):
                    pass

                def accept(self):
                    raise TimeoutError

                def close(self):
                    pass

            output = io.StringIO()
            with (
                mock.patch.object(probe.tempfile, "mkdtemp", return_value=str(work)),
                mock.patch.object(probe.subprocess, "check_output", return_value="testhead\n"),
                mock.patch.object(probe, "run_bounded", side_effect=fake_run),
                mock.patch.object(probe.socket, "socket", return_value=Listener()),
                mock.patch.object(probe, "WRAP_TIMEOUT_SECONDS", 0.2),
                (contextlib.nullcontext() if kill_group else mock.patch.object(probe.os, "killpg")),
                contextlib.redirect_stdout(output),
            ):
                result = probe.main()

            time.sleep(1.1)
            return result, output.getvalue(), sentinel.exists()

    def test_timeout_kills_wrapped_descendant_and_reports_output(self):
        for parent_exits in (False, True):
            with self.subTest(parent_exits=parent_exits):
                result, output, survived = self.run_case(parent_exits, kill_group=True)
                self.assertEqual(result, 124, output)
                self.assertIn("wrap-started", output)
                self.assertIn("wrap_timeout=0.2", output)
                self.assertIn("server_accepts=[]", output)
                self.assertFalse(survived, "wrapped descendant survived the timeout")

    def test_negative_control_without_group_kill_survives(self):
        result, output, survived = self.run_case(False, kill_group=False)
        self.assertEqual(result, 124, output)
        self.assertTrue(survived, "negative control did not expose the descendant")

    def test_setup_runner_timeout_kills_descendant(self):
        with tempfile.TemporaryDirectory() as scratch:
            sentinel = pathlib.Path(scratch) / "setup-descendant-survived"
            child_code = (
                "import pathlib, time; time.sleep(1); "
                f"pathlib.Path({str(sentinel)!r}).write_text('survived')"
            )
            parent_code = (
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "print('setup-started', flush=True); time.sleep(2)"
            )
            script_path = pathlib.Path(__file__).with_name("run-probe.py")
            spec = importlib.util.spec_from_file_location("run_probe_setup", script_path)
            probe = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(probe)
            result, timed_out = probe.run_bounded(
                [sys.executable, "-c", parent_code], pathlib.Path(scratch), 0.2,
            )
            time.sleep(1.1)
            self.assertTrue(timed_out)
            self.assertEqual(result.returncode, 124)
            self.assertIn("setup-started", result.stdout)
            self.assertFalse(sentinel.exists())

    def test_observations_are_required_for_success(self):
        script_path = pathlib.Path(__file__).with_name("run-probe.py")
        spec = importlib.util.spec_from_file_location("run_probe_observations", script_path)
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)

        class Listener:
            def __init__(self, deliver):
                self.deliver = deliver

            def bind(self, _address):
                pass

            def listen(self, _backlog):
                pass

            def settimeout(self, _seconds):
                pass

            def accept(self):
                if not self.deliver:
                    raise TimeoutError
                return self, None

            def recv(self, _size):
                return b"probe"

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

        banner = "CONFINED (syscall fence; proxy bridge only)"
        connected = "path=CONNECTED\nabstract=CONNECTED\n"
        cases = (
            (
                "valid",
                connected + "inet_datagram=DENIED errno=1 Operation not permitted\n",
                (True, True), 0,
            ),
            ("ip_allowed", connected + "inet_datagram=UNEXPECTED_ALLOWED\n", (True, True), 1),
            (
                "missing_accept",
                connected + "inet_datagram=DENIED errno=1 Operation not permitted\n",
                (True, False), 1,
            ),
        )
        with tempfile.TemporaryDirectory() as scratch:
            for name, stdout, deliveries, expected in cases:
                with self.subTest(name=name):
                    work = pathlib.Path(scratch) / name
                    work.mkdir()

                    def fake_run(args, _cwd, _timeout):
                        if args[0] == "go" or args[1] == "init":
                            return subprocess.CompletedProcess(args, 0, "", ""), False
                        return subprocess.CompletedProcess(args, 0, stdout, banner), False

                    output = io.StringIO()
                    with (
                        mock.patch.object(probe.tempfile, "mkdtemp", return_value=str(work)),
                        mock.patch.object(probe.subprocess, "check_output", return_value="testhead\n"),
                        mock.patch.object(probe, "run_bounded", side_effect=fake_run),
                        mock.patch.object(
                            probe.socket, "socket", side_effect=[Listener(d) for d in deliveries]
                        ),
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        result = probe.main()
                    self.assertEqual(result, expected, output.getvalue())


if __name__ == "__main__":
    unittest.main()
