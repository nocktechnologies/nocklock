#!/usr/bin/env python3
"""Guard Anvil's base-branch workflow and pinned checkout against regression."""

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/anvil.yml"


def violations(source):
    errors = []
    trigger = re.search(r"(?ms)^on:\s*\n(.*?)(?=^[^\s#][^\n]*:|\Z)", source)
    events = trigger.group(1) if trigger else ""
    if not re.search(r"(?m)^  pull_request_target:\s*$", events):
        errors.append("Anvil must use pull_request_target so the base branch supplies the workflow")
    if re.search(r"(?m)^  pull_request:\s*$", events):
        errors.append("Anvil must not execute a pull_request workflow from the PR ref")

    job = re.search(r"(?ms)^  anvil-review:\s*\n(.*?)(?=^  [\w-]+:\s*$|\Z)", source)
    job_body = job.group(1) if job else ""
    condition = re.search(r"(?ms)^    if: >-\n(.*?)(?=^    [\w-]+:|\Z)", job_body)
    gate = condition.group(1) if condition else ""
    if "github.event.pull_request.head.repo.full_name == github.repository" not in gate:
        errors.append("Anvil must require a same-repository PR head")
    if "github.event.pull_request.user.login == 'nock-fleet[bot]'" not in gate:
        errors.append("Anvil must keep the exact fleet login check")

    runs_on = re.search(r"(?ms)^    runs-on:\s*\n(.*?)(?=^    [\w-]+:|\Z)", job_body)
    runner = runs_on.group(1) if runs_on else ""
    if not re.search(r"(?m)^      group: nocklock-anvil\s*$", runner):
        errors.append("Anvil must request only the dedicated runner group")

    checkout = re.search(
        r"(?ms)^      - uses: actions/checkout@[^\n]+\n(.*?)(?=^      - (?:name|uses):|\Z)",
        job_body,
    )
    checkout_options = checkout.group(1) if checkout else ""
    if len(re.findall(r"(?m)^      - uses: actions/checkout@", job_body)) != 1:
        errors.append("Anvil must have exactly one checkout step")
    if not re.search(
        r"(?m)^          ref: \$\{\{ github\.event\.pull_request\.base\.sha \}\}\s*$",
        checkout_options,
    ):
        errors.append("Anvil checkout must pin the event's base SHA, never the PR head")

    if 'git fetch --no-tags origin "refs/pull/${PR_NUMBER}/head"' not in source:
        errors.append("Anvil must fetch the PR head as data for the diff")
    if '"$(git rev-parse FETCH_HEAD)" != "${PR_HEAD_SHA}"' not in source:
        errors.append("Anvil must reject a PR head that moved since the event")
    if 'git diff "${PR_BASE_SHA}...${PR_HEAD_SHA}"' not in source:
        errors.append("Anvil must diff the two event-pinned commits")
    if "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}" not in source:
        errors.append("Anvil must use the event base SHA")
    if "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}" not in source:
        errors.append("Anvil must use the event head SHA")
    return errors


class AnvilTrustGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()

    def test_workflow_has_protected_trigger_and_pinned_diff(self):
        self.assertEqual([], violations(self.source))

    def test_negative_controls_reject_pr_trigger_and_head_checkout(self):
        source = self.source.replace("  pull_request_target:", "  pull_request:", 1)
        self.assertTrue(any("pull_request_target" in error for error in violations(source)))

        source = self.source.replace(
            "ref: ${{ github.event.pull_request.base.sha }}",
            "ref: ${{ github.event.pull_request.head.sha }}",
            1,
        )
        self.assertTrue(any("base SHA" in error for error in violations(source)))

    def test_negative_controls_reject_unpinned_head_and_bypassed_gate(self):
        source = self.source.replace(
            '"$(git rev-parse FETCH_HEAD)" != "${PR_HEAD_SHA}"',
            '"$(git rev-parse FETCH_HEAD)" != "ignored"',
            1,
        )
        self.assertTrue(any("moved" in error for error in violations(source)))

        source = self.source.replace(
            "github.event.pull_request.head.repo.full_name == github.repository &&", "true &&", 1
        )
        source += "\n# github.event.pull_request.head.repo.full_name == github.repository\n"
        self.assertTrue(any("same-repository" in error for error in violations(source)))

        source = self.source.replace("      group: nocklock-anvil", "      group: Default", 1)
        self.assertTrue(any("runner group" in error for error in violations(source)))


if __name__ == "__main__":
    unittest.main()
