"""Subprocess regression controls for the public-repository gates."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent


class PublicChecksTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def run_check(self, name, *args, cwd=None):
        return subprocess.run([sys.executable, '-O', str(SCRIPTS / name), *args],
                              cwd=cwd or self.root, capture_output=True, text=True)

    def test_baseline_gate(self):
        (self.root / '.gitleaks-baseline.json').write_text('[{"Fingerprint":"old"}]')
        report = self.root / 'report.json'
        self.assertEqual(self.run_check('check-gitleaks-baseline.py', str(report)).returncode, 1)
        for content in ('', '{', '{}', '[{}]', '[{"Fingerprint":null}]', '[{"Fingerprint":""}]'):
            with self.subTest(content=content):
                report.write_text(content)
                result = self.run_check('check-gitleaks-baseline.py', str(report))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('FAIL', result.stderr)
        for finding, expected in (('new', 1), ('old', 0)):
            report.write_text(json.dumps([{'Fingerprint': finding}]))
            self.assertEqual(self.run_check('check-gitleaks-baseline.py', str(report)).returncode, expected)
        report.write_text('[]')
        self.assertEqual(self.run_check('check-gitleaks-baseline.py', str(report)).returncode, 0)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, stderr=subprocess.DEVNULL)

    def test_content_gate_from_subdirectory(self):
        self.git('init')
        retired = 'kk' + 'wil'
        changelog = self.root / 'CHANGELOG.md'
        changelog.write_text('History: ' + retired + '\n')
        (self.root / 'sub').mkdir()
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
        self.git('update-ref', 'refs/remotes/origin/next', 'HEAD')
        def check(expected):
            result = self.run_check('check-public-content.py', cwd=self.root / 'sub')
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            return result
        check(0)
        changelog.write_text('History: ' + retired + '\nNew: ' + retired + '\n')
        self.assertIn('CHANGELOG.md:2', check(1).stderr)
        changelog.write_text('History: ' + retired + '\n')
        binary = self.root / 'binary.dat'
        binary.write_bytes(b'ordinary\0bytes')
        self.git('add', 'binary.dat')
        self.assertIn('NUL bytes', check(0).stdout)
        binary.write_bytes(b'prefix\0' + retired.encode())
        check(1)
        binary.write_text('safe text')
        check(0)
        binary.write_text(retired)
        self.assertIn('binary.dat:1', check(1).stderr)


if __name__ == '__main__':
    unittest.main()
