"""Offline refusal controls; live/root enforcement belongs exclusively in CI."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


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

    def test_network_driver_refuses_resident_host(self):
        with patch.object(network.os, "geteuid", return_value=0), patch.dict(network.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "disposable"):
                network.accept(None)


if __name__ == "__main__":
    unittest.main()
