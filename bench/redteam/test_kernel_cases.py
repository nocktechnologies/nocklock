import json
import unittest

from kernel_cases import CASES, classify, parse_result


class KernelReceiptTest(unittest.TestCase):
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
