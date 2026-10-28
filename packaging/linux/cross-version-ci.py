#!/usr/bin/env python3
"""Authenticate two real tagged releases and exercise the managed lifecycle."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

if not __debug__:
    raise RuntimeError("acceptance requires assertions; do not use Python optimization")

spec = importlib.util.spec_from_file_location("release_ci", Path(__file__).with_name("provision-release-ci.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
ci = release.ci
network_spec = importlib.util.spec_from_file_location("network_ci", Path(__file__).with_name("network-acceptance.py"))
network = importlib.util.module_from_spec(network_spec)
network_spec.loader.exec_module(network)
run = network.run


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
    run("/usr/bin/sudo", "-u", ci.TEST_USER, "env", "-i", "HOME=" + str(home),
           "PATH=/usr/bin:/bin", "/bin/bash", "-c",
           'set -eu; cd "$HOME"; mkdir lifecycle-project; cd lifecycle-project; '
           '/usr/local/bin/nocklock init; /usr/local/bin/nocklock wrap -- /bin/echo LIFECYCLE', check=True, env=ci.ENV)
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
        result = run(*command, timeout=180, env=ci.ENV)
        with (args.evidence / "lifecycle.txt").open("a") as out:
            out.write(" ".join(command) + "\n" + result.stdout + result.stderr)
        if refusal:
            assert result.returncode != 0 and refusal in result.stdout, result
        else:
            assert result.returncode == 0, result
            assert link.resolve().parent.name == tag + "-linux-amd64"
            version_output = run(str(link), "version", check=True, env=ci.ENV).stdout.strip()
            assert version_output == "NockLock " + tag, version_output
        assert snapshot(project) == config_before
        assert snapshot(home / ".local/state/nocklock") == state_before
        assert snapshot(old_path.parent) == old_tree
    activate("install", args.newer, args.new_assets)
    new_path = link.resolve()
    new_tree = snapshot(new_path.parent)
    stale = run(str(old_path), "version", env=ci.ENV)
    assert stale.returncode != 0 and "release changed or is inactive" in stale.stdout, stale
    (args.evidence / "stale.txt").write_text(stale.stdout + stale.stderr)
    activate("install", args.newer, args.new_assets)
    activate("install", args.older, args.old_assets, refusal="downgrade refused")
    assert link.resolve() == new_path
    activate("rollback", args.older)
    assert link.resolve() == old_path and snapshot(new_path.parent) == new_tree
    # The old signed chain remains verifiable after the real downgrade.
    verify = run("/usr/bin/sudo", "-u", ci.TEST_USER, "env", "-i", "HOME=" + str(home),
                             "PATH=/usr/bin:/bin", str(link), "verify", "--audit",
                            cwd=project, check=True, env=ci.ENV)
    assert "AUDIT: AUTHENTIC" in verify.stdout
    (args.evidence / "audit-after-rollback.txt").write_text(verify.stdout)
    # Reverification may checkpoint SQLite; take the baseline again before the
    # final forward switch, which leaves the new release ready for network proof.
    state_before = snapshot(home / ".local/state/nocklock")
    activate("install", args.newer, args.new_assets)
    run("/usr/bin/sudo", "-u", ci.TEST_USER, "sudo", "-n", "/usr/libexec/nocklock-egress-helper", "check", check=True, env=ci.ENV)
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
