#!/usr/bin/env python3
"""Build a test-only policy-removal mutant in an isolated CI source copy."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Mutation build is CI-only")
output = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="nocklock-mutant-", dir=os.environ["RUNNER_TEMP"]) as tmp:
    source = Path(tmp) / "source"
    shutil.copytree(Path.cwd(), source, ignore=shutil.ignore_patterns(".git", "credential-proof-*", "nocklock", "*.so"))
    path = source / "internal/fence/fs/builtins.go"
    text = path.read_text()
    signature = 'func ProcessEffectiveConfig(cfg *config.Config, goos string) (*FenceConfig, error) {'
    assert text.count(signature) == 1
    # Leave the original code type-checked below the unconditional return;
    # production has no environment variable or flag that disables this policy.
    path.write_text(text.replace(signature, signature + '\n return ProcessConfig(cfg.Filesystem)', 1))
    subprocess.run(["go", "build", "-o", str(output), "./cmd/nocklock"], cwd=source, check=True)
