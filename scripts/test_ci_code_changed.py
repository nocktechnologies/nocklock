"""Subprocess controls for scripts/ci-code-changed.sh, the CI docs-only detector."""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / 'ci-code-changed.sh'


class CodeChangedTest(unittest.TestCase):
    def setUp(self):
        self.fresh_repo()

    def fresh_repo(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.git('init', '-q', '-b', 'base')
        self.write('main.go', 'package main\n')
        self.commit('base')

    def git(self, *args):
        env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t',
               'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t'}
        subprocess.run(['git', *args], cwd=self.root, env=env, check=True, capture_output=True)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '--allow-empty', '-m', message)

    def merge_pr(self, paths):
        """Mirror the PR merge ref: HEAD^1 is the base tip, HEAD^2 the PR head."""
        self.git('checkout', '-q', '-b', 'pr')
        for path in paths:
            self.write(path, 'changed\n')
        self.commit('pr')
        self.git('checkout', '-q', 'base')
        self.git('merge', '-q', '--no-ff', '-m', 'merge', 'pr')

    def run_script(self, event='pull_request'):
        output = self.root / 'github_output'
        output.write_text('')
        env = {**os.environ, 'GITHUB_EVENT_NAME': event, 'GITHUB_OUTPUT': str(output)}
        result = subprocess.run(['bash', str(SCRIPT)], cwd=self.root, env=env,
                                capture_output=True, text=True)
        return result, output.read_text()

    def test_classification(self):
        cases = (
            (['README.md'], 'false'),
            (['docs/setup.md', 'AGENTS.md', 'CLAUDE.md', 'bench/redteam/README.md'], 'false'),
            (['docs/probes/n1/output.txt'], 'false'),
            (['internal/cli/wrap.go'], 'true'),
            (['README.md', 'internal/cli/wrap.go'], 'true'),
            (['.github/workflows/test.yml'], 'true'),
            (['CHANGELOG.md', 'scripts/ci-code-changed.sh'], 'true'),
            (['README.md.go'], 'true'),
            (['notdocs/x.txt'], 'true'),
            ([], 'true'),
        )
        for paths, want in cases:
            with self.subTest(paths=paths):
                self.fresh_repo()
                self.merge_pr(paths)
                result, output = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, f'code={want}\n')

    def test_non_pr_events_always_run(self):
        self.merge_pr(['README.md'])
        for event in ('push', 'workflow_dispatch', ''):
            with self.subTest(event=event):
                result, output = self.run_script(event)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, 'code=true\n')

    def test_missing_base_fails_closed(self):
        # A single-commit checkout has no HEAD^1: the step must fail, not skip.
        result, output = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output, '')


if __name__ == '__main__':
    unittest.main()
