#!/usr/bin/env python3
"""Fetch only successful production tagged workflow artifacts, never candidates."""
import argparse
import json
from pathlib import Path
import re
import subprocess

REPO = "nocktechnologies/nocklock"


def fetch(tag, run_id, destination):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("require stable tag")
    if not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("require workflow run ID")
    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", "repos/" + REPO + "/" + path], text=True))
    run = api("actions/runs/" + run_id)
    commit = api("commits/" + tag)["sha"]
    if not (run["path"] == ".github/workflows/release.yml" and run["head_branch"] == tag
            and run["head_sha"] == commit and run["status"] == "completed"
            and run["conclusion"] == "success" and run["event"] in ("push", "workflow_dispatch")):
        raise ValueError("not a successful production workflow for the exact tag commit")
    destination.mkdir(parents=True)
    subprocess.run(["gh", "run", "download", run_id, "--repo", REPO,
                    "--name", "linux-amd64-release-assets", "--dir", str(destination)], check=True)
    (destination.parent / (tag + "-source.json")).write_text(json.dumps(dict(
        tag=tag, commit=commit, run_id=run_id, url=run["html_url"]), indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("run_id")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    fetch(args.tag, args.run_id, args.destination)
