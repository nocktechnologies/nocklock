"""Offline refusal controls; live/root enforcement belongs exclusively in CI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fetcher = module("fetch-release-ci")
network = module("network-acceptance")


class ReleaseSelection(unittest.TestCase):
    def test_only_successful_exact_production_tag(self):
        good = dict(path=".github/workflows/release.yml", head_branch="v0.16.0",
                    head_sha="a" * 40, status="completed", conclusion="success",
                    event="push", html_url="https://github.com/nocktechnologies/nocklock/actions/runs/1")
        mutations = [{}, dict(path=".github/workflows/linux-candidate.yml"),
                     dict(head_branch="next"), dict(head_sha="b" * 40),
                     dict(status="in_progress"), dict(conclusion="failure"), dict(event="pull_request")]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                run = {**good, **mutation}
                with patch.object(fetcher.subprocess, "check_output", side_effect=[json.dumps(run), json.dumps(dict(sha="a" * 40))]), patch.object(fetcher.subprocess, "run") as download:
                    if mutation:
                        with self.assertRaises(ValueError):
                            fetcher.fetch("v0.16.0", "1", Path(root) / "assets")
                        download.assert_not_called()
                    else:
                        fetcher.fetch("v0.16.0", "1", Path(root) / "assets")
                        download.assert_called_once()
                        self.assertEqual(json.loads((Path(root) / "v0.16.0-source.json").read_text())["commit"], "a" * 40)

    def test_untrusted_inputs_refused_before_api(self):
        for tag, run in [("next", "1"), ("v0.16.0;id", "1"), ("v0.16.0", "1/../../")]:
            with self.subTest(tag=tag, run=run), patch.object(fetcher.subprocess, "check_output") as api:
                with self.assertRaises(ValueError):
                    fetcher.fetch(tag, run, Path("unused"))
                api.assert_not_called()

    def test_teardown_signals_group_after_leader_exit_or_timeout(self):
        for timeout in (False, True):
            process = Mock(pid=123)
            if timeout:
                process.wait.side_effect = [subprocess.TimeoutExpired("probe", 15), 0]
            with self.subTest(timeout=timeout), patch.object(network.os, "killpg") as kill:
                network.stop_process_group(process)
                self.assertEqual([c.args for c in kill.call_args_list],
                                 [(123, network.signal.SIGTERM), (123, network.signal.SIGKILL)])
                self.assertEqual(process.wait.call_count, 2)

    def test_timeout_stops_group_without_unbounded_pipe_drain(self):
        process = Mock(pid=123)
        process.communicate.side_effect = subprocess.TimeoutExpired("probe", 1)
        with patch.object(network.subprocess, "Popen", return_value=process) as popen, patch.object(network, "stop_process_group") as stop:
            with self.assertRaises(subprocess.TimeoutExpired):
                network.run("probe", timeout=1)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            stop.assert_called_once_with(process)
            process.communicate.assert_called_once_with(timeout=1)
            process.stdout.close.assert_called_once()

    def test_optimization_cannot_emit_acceptance(self):
        for name in ("network-acceptance.py", "cross-version-ci.py"):
            result = subprocess.run([sys.executable, "-O", str(Path(__file__).with_name(name)), "--help"],
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("acceptance requires assertions", result.stderr)

    def test_network_driver_refuses_resident_host(self):
        with patch.object(network.os, "geteuid", return_value=0), patch.dict(network.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "disposable"):
                network.accept(None)


if __name__ == "__main__":
    unittest.main()
