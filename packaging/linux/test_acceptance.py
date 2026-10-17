import copy
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from acceptance import check_doctor

TESTDATA = Path(__file__).resolve().parent / "testdata"


def load(name):
    return json.loads((TESTDATA / name).read_text())


class DoctorReceiptTest(unittest.TestCase):
    def setUp(self):
        # Captured from `nocklock doctor --json` (exit 3) on a Landlock ABI 8
        # host in a fresh `nocklock init` project; home paths are rewritten.
        self.report = load("doctor-partial-abi8.json")

    def boundary(self, report, name):
        return next(b for b in report["boundaries"] if b["name"] == name)

    def check(self, report, name):
        return next(c for c in report["checks"] if c["name"] == name)

    def test_real_below_9_posture(self):
        check_doctor(self.report, 3)

    def test_abi_9_enforced_control(self):
        self.boundary(self.report, "unix-sockets")["posture"] = "enforced"
        self.report["verdict"] = "PROTECTED"
        check_doctor(self.report, 0)

    def test_config_refused_names_the_cause(self):
        # Captured from hosted CI: a 0775 project directory made doctor refuse
        # the config, so boundaries and egress_level were absent.
        report = load("doctor-config-refused.json")
        with self.assertRaisesRegex(AssertionError, "config did not load"):
            check_doctor(report, 3)

    def test_generic_degradation_is_not_acceptance(self):
        cases = ("other_boundary", "unknown_abi", "wrong_exit", "wrong_posture", "wrong_status",
                 "no_boundaries", "wrong_egress")
        for case in cases:
            with self.subTest(case=case):
                report = copy.deepcopy(self.report)
                code = 3
                if case == "other_boundary": self.boundary(report, "filesystem")["posture"] = "advisory"
                elif case == "unknown_abi": self.check(report, "unix-sockets")["message"] = "reason=landlock_abi_unknown"
                elif case == "wrong_exit": code = 0
                elif case == "wrong_posture": self.boundary(report, "unix-sockets")["posture"] = "unavailable"
                elif case == "wrong_status": self.check(report, "unix-sockets")["status"] = "will-refuse"
                elif case == "no_boundaries": del report["boundaries"]
                elif case == "wrong_egress": report["egress_level"] = "OPEN"
                with self.assertRaises((AssertionError, KeyError)): check_doctor(report, code)


def load_provision():
    spec = importlib.util.spec_from_file_location(
        "provision_ci", Path(__file__).resolve().parent / "provision-ci.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivateGroupTest(unittest.TestCase):
    def check(self, group_name, members=(), sharers=()):
        module = load_provision()
        user = SimpleNamespace(pw_name="cand", pw_gid=2000)
        others = [SimpleNamespace(pw_name=n, pw_gid=2000) for n in sharers]
        module.pwd = SimpleNamespace(getpwnam=lambda name: user, getpwall=lambda: [user, *others])
        module.grp = SimpleNamespace(getgrgid=lambda gid: SimpleNamespace(gr_name=group_name, gr_mem=list(members)))
        module.require_private_group("cand")

    def test_private_group_accepted(self):
        self.check("cand", members=["cand"])

    def test_shared_groups_refused(self):
        for case in (dict(group_name="users"), dict(group_name="cand", members=["other"]),
                     dict(group_name="cand", sharers=["other"])):
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.check(**case)


class ProvisionDirectoryTest(unittest.TestCase):
    def test_libexec_fallback_is_traversable_under_private_umask(self):
        module = load_provision()
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "libexec"
            previous = os.umask(0o077)
            try:
                module.make_traversable_dir(target)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
