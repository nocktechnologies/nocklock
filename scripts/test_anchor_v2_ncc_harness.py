#!/usr/bin/env python3
"""Lower-level safety/receipt controls; these are not real-NCC matrix rows."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("anchor_ncc", Path(__file__).with_name("test-anchor-v2-ncc.py"))
harness_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness_module)
Harness = harness_module.Harness


class HarnessSafetyTests(unittest.TestCase):
    def bare(self, root):
        h = Harness.__new__(Harness)
        h.scratch = root
        h.args = SimpleNamespace(out=root / "out", server_smoke=True, ncc_checkout=root, nocklock_bin=None)
        h.args.out.mkdir()
        h.rows, h.commands = [], []
        h.secret_values = {"token-secret", "fernet-secret", "django-secret", "webhook-secret"}
        h.ready = {"django": "fixture"}
        return h

    def test_bootstrap_cleanup_including_interrupt_and_fixed_path(self):
        real_popen = subprocess.Popen
        for failure in (KeyboardInterrupt, RuntimeError, None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scratch = root / "scratch"
                scratch.mkdir()
                out = root / "out"
                out.mkdir()
                args = SimpleNamespace(out=out, ncc_python=Path(sys.executable), ncc_checkout=root)
                h = Harness.__new__(Harness)
                children = []

                def spawn(*unused, **kwargs):
                    self.assertEqual(kwargs["env"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
                    child = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
                    children.append(child)
                    return child

                def ready(instance, path, **unused):
                    text = " ".join(instance.secret_values) + " public diagnostic"
                    instance.server_log.write(text)
                    instance.server_log.flush()
                    if failure:
                        raise failure(text)
                    path.write_text(json.dumps({"url": "http://127.0.0.1:1", "django": "fixture"}))

                try:
                    with patch.object(harness_module.os, "defpath", ".:untrusted"), \
                            patch.object(harness_module.subprocess, "Popen", side_effect=spawn), \
                            patch.object(Harness, "wait_file", ready):
                        if failure:
                            with self.assertRaises(failure) as caught:
                                h.__init__(args, scratch)
                            if failure is RuntimeError:
                                for secret in h.secret_values:
                                    self.assertNotIn(secret, str(caught.exception))
                            receipt = (out / "bootstrap-error.log").read_text()
                            for secret in h.secret_values:
                                self.assertNotIn(secret, receipt)
                            self.assertIn("public diagnostic", receipt)
                            self.assertTrue(h.server_log.closed)
                            self.assertIsNotNone(children[0].poll(), "bootstrap left its child alive")
                        else:
                            h.__init__(args, scratch)
                            self.assertEqual(h.cli_env["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
                finally:
                    # Test containment even when a removed-cleanup mutant fails.
                    if hasattr(h, "server_log"):
                        h.close()
                    for child in children:
                        if child.poll() is None:
                            child.kill()
                        child.wait(timeout=5)

    def test_wait_tail_case_exception_and_report_redact_all_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            h = self.bare(Path(temporary))
            text = " ".join(sorted(h.secret_values)) + " public diagnostic"
            (h.scratch / "server.log").write_text(text)
            h.server = SimpleNamespace(poll=lambda: 1)
            with self.assertRaises(RuntimeError) as caught:
                h.wait_file(h.scratch / "never-ready")
            for secret in h.secret_values:
                self.assertNotIn(secret, str(caught.exception))

            def fail():
                raise RuntimeError(text)

            with self.assertRaises(RuntimeError) as caught:
                h.case("error-redaction", fail)
            for secret in h.secret_values:
                self.assertNotIn(secret, str(caught.exception))
            # Also exercise the final serializer with a raw nested exception:
            # it must sanitize even if a future caller misses earlier filtering.
            h.rows.append(dict(case="outer-exception", verdict="FAIL", detail={"exception": text}))
            with patch.object(harness_module.subprocess, "check_output", side_effect=lambda args, **kw: "fixture" if "rev-parse" in args else b""):
                h.evidence()
            for name in ("report.json", "server.log", "commands.json"):
                content = (h.args.out / name).read_text()
                for secret in h.secret_values:
                    self.assertNotIn(secret, content)
            self.assertIn("public diagnostic", (h.args.out / "report.json").read_text())

    def test_case_request_slice_labels_and_current_rate_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            h = self.bare(Path(temporary))
            requests = [{"status": 429, "code": "prior-case"}]
            h.requests = lambda: list(requests)
            h.case("scoped", lambda: requests.append({"status": 200}) or {"invariant": True})
            self.assertEqual(h.rows[-1]["request_range"], [1, 2])
            self.assertEqual(h.rows[-1]["detail_type"], "asserted")
            with self.assertRaisesRegex(RuntimeError, "HTTP 429"):
                h.case("current-rate-limit", lambda: requests.append({"status": 429}))
            self.assertEqual(h.rows[-1]["verdict"], "FAIL")

    def test_exact_diagnostic_rejects_substrings_and_help_text(self):
        expected = "Error: refusing prune: retained request"
        harness_module.require_diagnostic(expected + "\nUsage: harmless help", expected)
        for output in ("other failure\n" + expected, expected + " lookalike", "help mentions " + expected):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                harness_module.require_diagnostic(output, expected)


if __name__ == "__main__":
    unittest.main()
