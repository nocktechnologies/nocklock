#!/usr/bin/env python3
"""Controls for the schema cache in check-ocsf-schema.py.

Needs the jsonschema package, which the checker imports; CI runs it in the
same environment as the schema check.
"""

import hashlib
import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check_ocsf_schema", os.path.join(HERE, "check-ocsf-schema.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

GOOD = b'{"type": "object"}'
DIGEST = hashlib.sha256(GOOD).hexdigest()
URL = "https://schema.invalid/class"


class VerifiedSchemaTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "class.json")

    def tearDown(self):
        self.dir.cleanup()

    def cache(self, body):
        with open(self.path, "wb") as f:
            f.write(body)

    def test_cached_match_does_not_download(self):
        self.cache(GOOD)
        with patch.object(checker, "fetch") as fetch:
            self.assertEqual(checker.verified_schema(self.path, URL, DIGEST), GOOD)
        fetch.assert_not_called()

    def test_cached_mismatch_is_replaced_by_one_fresh_download(self):
        self.cache(b"stale")
        with patch.object(checker, "fetch", return_value=GOOD) as fetch:
            self.assertEqual(checker.verified_schema(self.path, URL, DIGEST), GOOD)
        fetch.assert_called_once_with(URL)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), GOOD)

    def test_cached_mismatch_then_fresh_mismatch_fails(self):
        self.cache(b"stale")
        with patch.object(checker, "fetch", return_value=b"changed") as fetch:
            with self.assertRaises(SystemExit) as cm:
                checker.verified_schema(self.path, URL, DIGEST)
        fetch.assert_called_once_with(URL)
        self.assertIn("does not match the pinned", str(cm.exception))
        self.assertFalse(os.path.exists(self.path))

    def test_missing_then_fresh_mismatch_fails_without_retry(self):
        with patch.object(checker, "fetch", return_value=b"changed") as fetch:
            with self.assertRaises(SystemExit) as cm:
                checker.verified_schema(self.path, URL, DIGEST)
        fetch.assert_called_once_with(URL)
        self.assertIn("does not match the pinned", str(cm.exception))
        self.assertFalse(os.path.exists(self.path))

    def test_missing_then_fresh_match(self):
        with patch.object(checker, "fetch", return_value=GOOD) as fetch:
            self.assertEqual(checker.verified_schema(self.path, URL, DIGEST), GOOD)
        fetch.assert_called_once_with(URL)


if __name__ == "__main__":
    unittest.main()
