#!/usr/bin/env python3
"""Authenticate two real tagged releases and exercise the managed lifecycle."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("release_ci", Path(__file__).with_name("provision-release-ci.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
ci = release.ci


def snapshot(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file()}


def main(args):
    assert args.older != args.newer, "two distinct immutable tags required"
    assert tuple(map(int, args.older[1:].split('.'))) < tuple(map(int, args.newer[1:].split('.')))
    args.evidence.mkdir(parents=True)
    # The workflow has already installed and tested the older signed release.
    assert Path("/usr/local/bin/nocklock").resolve().parent.name == args.older + "-linux-amd64"
    newer = SimpleNamespace(tag=args.newer, artifacts=args.new_assets, cosign=args.cosign)
    installer, cosign = release.authenticate(newer)
    home = Path("/home") / ci.TEST_USER
    # Establish actual signed state using the old release, then require every
    # byte of config and audit state to survive activation and rollback.
    ci.run("/usr/bin/sudo", "-u", ci.TEST_USER, "env", "-i", "HOME=" + str(home),
           "PATH=/usr/bin:/bin", "/bin/bash", "-c",
           'cd "$HOME"; mkdir lifecycle-project; cd lifecycle-project; '
           '/usr/local/bin/nocklock init; /usr/local/bin/nocklock wrap -- /bin/echo LIFECYCLE')
    project = home / "lifecycle-project"
    config_before = snapshot(project)
    state_before = snapshot(home / ".local/state/nocklock")
    assert state_before, "missing real audit state"
    link = Path("/usr/local/bin/nocklock")
    old_path = link.resolve()
    old_tree = snapshot(old_path.parent)
    def activate(action, tag, artifacts=None, refusal=None):
        command = [str(installer), action, "--tag", tag, "--cosign", str(cosign)]
        if artifacts:
            command += ["--artifacts", str(artifacts)]
        result = subprocess.run(command, text=True, capture_output=True, timeout=180)
        with (args.evidence / "lifecycle.txt").open("a") as out:
            out.write(" ".join(command) + "\n" + result.stdout + result.stderr)
        if refusal:
            assert result.returncode != 0 and refusal in result.stderr, result
        else:
            assert result.returncode == 0, result
            assert link.resolve().parent.name == tag + "-linux-amd64"
            assert subprocess.check_output([str(link), "version"], text=True).strip() == "NockLock " + tag
        assert snapshot(project) == config_before
        assert snapshot(home / ".local/state/nocklock") == state_before
        assert snapshot(old_path.parent) == old_tree
    activate("install", args.newer, args.new_assets)
    new_path = link.resolve()
    new_tree = snapshot(new_path.parent)
    stale = subprocess.run([str(old_path), "version"], text=True, capture_output=True)
    assert stale.returncode != 0, stale
    (args.evidence / "stale.txt").write_text(stale.stdout + stale.stderr)
    activate("install", args.newer, args.new_assets)
    activate("install", args.older, args.old_assets, refusal="downgrade refused")
    assert link.resolve() == new_path
    activate("rollback", args.older)
    assert link.resolve() == old_path and snapshot(new_path.parent) == new_tree
    # The old signed chain remains verifiable after the real downgrade.
    verify = subprocess.run(["/usr/bin/sudo", "-u", ci.TEST_USER, "env", "-i", "HOME=" + str(home),
                             "PATH=/usr/bin:/bin", str(link), "verify", "--audit"],
                            cwd=project, text=True, capture_output=True, check=True)
    assert "AUDIT: AUTHENTIC" in verify.stdout
    (args.evidence / "audit-after-rollback.txt").write_text(verify.stdout)
    # Reverification may checkpoint SQLite; take the baseline again before the
    # final forward switch, which leaves the new release ready for network proof.
    state_before = snapshot(home / ".local/state/nocklock")
    activate("install", args.newer, args.new_assets)
    ci.run("/usr/bin/sudo", "-u", ci.TEST_USER, "sudo", "-n", "/usr/libexec/nocklock-egress-helper", "check")
    (args.evidence / "receipt.json").write_text(json.dumps(dict(
        kind="signed-cross-version-acceptance", older=args.older, newer=args.newer,
        upgrade=True, retry=True, downgrade_refused=True, rollback=True,
        stale_executable_refused=True, config_and_audit_preserved=True,
        old_release_sha256=old_tree, new_release_sha256=new_tree), indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("old_assets", "new_assets", "cosign", "evidence"):
        parser.add_argument(name, type=Path)
    parser.add_argument("older")
    parser.add_argument("newer")
    main(parser.parse_args())
