import copy
import unittest

from acceptance import check_doctor


class DoctorReceiptTest(unittest.TestCase):
    def setUp(self):
        # Matches doctorBoundaries' actual JSON contract: advisory posture,
        # unavailable check status (not an unavailable boundary posture).
        self.report = dict(verdict="PARTIAL", egress_level="CONFINED",
                           boundaries=[dict(name=name, posture="enforced") for name in
                                       ("filesystem", "syscall", "network", "secrets", "signing-key")]
                           + [dict(name="unix-sockets", posture="advisory")],
                           checks=[dict(name="unix-sockets", status="unavailable",
                                        message="reason=landlock_abi_6_below_9")])

    def test_real_below_9_posture(self):
        check_doctor(self.report, 3)

    def test_abi_9_enforced_control(self):
        self.report["boundaries"][-1]["posture"] = "enforced"
        self.report["verdict"] = "PROTECTED"
        check_doctor(self.report, 0)

    def test_generic_degradation_is_not_acceptance(self):
        for case in ("other_boundary", "unknown_abi", "wrong_exit", "wrong_posture", "wrong_status"):
            with self.subTest(case=case):
                report = copy.deepcopy(self.report)
                code = 3
                if case == "other_boundary": report["boundaries"][0]["posture"] = "advisory"
                elif case == "unknown_abi": report["checks"][0]["message"] = "reason=landlock_abi_unknown"
                elif case == "wrong_exit": code = 0
                elif case == "wrong_posture": report["boundaries"][-1]["posture"] = "unavailable"
                elif case == "wrong_status": report["checks"][0]["status"] = "will-refuse"
                with self.assertRaises(AssertionError): check_doctor(report, code)


if __name__ == "__main__":
    unittest.main()
