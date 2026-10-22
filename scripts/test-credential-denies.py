#!/usr/bin/env python3
"""CI-only credential deny proof with fake HOME and a separately built mutant.

The mutant removes ProcessEffectiveConfig's mandatory policy assembly. Each
blocked case must be readable without a fence, fail during a real wrapped read,
refuse an overlapping allow, and become readable when that guard is mutated out.
No real home credentials are inspected. Pre-made hardlink aliases in the project
are an explicit limitation, not a claimed block.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile

CANARY = "NOCKLOCK_FAKE_CREDENTIAL_CANARY\n"


def run(argv, cwd, env, *, timeout=30):
    process = subprocess.Popen(argv, cwd=cwd, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        # The known launcher group must stop even if process enumeration fails.
        # Do not use Popen's context manager: its unbounded wait can hang cleanup.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        groups = set()
        try:
            # wrap gives its child a separate group. Reparented descendants
            # retain this invocation's isolated session ID after the kill above.
            rows = subprocess.check_output(["/bin/ps", "-axo", "pid=,pgid="], text=True, timeout=5)
            for row in rows.splitlines():
                pid, pgid = map(int, row.split())
                try:
                    if os.getsid(pid) == process.pid:
                        groups.add(pgid)
                except OSError:
                    pass
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            expired.add_note(f"Cannot enumerate remaining proof process groups: {error}")
        finally:
            for pgid in groups:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                # A surviving descendant can hold a pipe open after launcher
                # death. Close those readers and reap only the known launcher.
                process.stdout.close()
                process.stderr.close()
                process.wait(timeout=5)
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Enforcement proof is CI-only; do not run on a developer host")
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--mutant", required=True, type=Path)
    args = parser.parse_args()
    binary, mutant = args.binary.resolve(), args.mutant.resolve()
    system = platform.system()
    if system not in ("Linux", "Darwin"):
        raise SystemExit("unsupported platform (no skipped proof)")
    # Outside /tmp: the default /tmp grant must not cover fake credentials or
    # audit state. GitHub's checkout has trusted, non-world-writable ancestors.
    with tempfile.TemporaryDirectory(prefix="credential-proof-", dir=Path.cwd()) as tmp:
        base = Path(tmp).resolve()
        home, project, state = (base / n for n in ("home", "project", "state"))
        for p in (home, project, state):
            p.mkdir(mode=0o700)
        configdir = project / ".nock"
        configdir.mkdir(mode=0o700)
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
               "USER": "nocklock-proof", "XDG_STATE_HOME": str(state),
               "XDG_CONFIG_HOME": str(home / ".config")}
        # Linux needs the LD_PRELOAD library readable after exec. The paired
        # binaries live outside the project in an explicitly allowed directory.
        allow = ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache",
                 str(binary.parent), str(mutant.parent)]

        def configure(extra=(), runtime="", deny=None):
            body = ('[project]\nruntime = ' + json.dumps(runtime) + '\n'
                    '[filesystem]\nroot = "."\nlinux_enforcement = "required"\n'
                    'allow = ' + json.dumps(allow + list(extra)) + '\n'
                    'deny = ' + json.dumps(deny if deny is not None else [str(base / "user-deny")]) + '\n'
                    '[network]\nallow_all = true\n'
                    '[syscall]\nenforcement = "off"\n'
                    '[secrets]\npass = ["HOME", "PATH", "USER"]\n'
                    '[logging]\ndb = "events.db"\n')
            (configdir / "config.toml").write_text(body)

        def read_command(path, grandchild=False):
            # Marker distinguishes a failed read from a wrapper startup failure.
            command = ["/bin/sh", "-c", 'printf "READ_ATTEMPT\\n"; /bin/cat "$1" || exit 73', "read", str(path)]
            if grandchild:
                command = ["/bin/sh", "-c", 'exec /bin/sh -c \'exec "$@"\' grandchild "$@"', "child"] + command
            return command

        paths = [".ssh/canary", ".ssh/id_rsa", ".aws/credentials", ".gnupg/private-keys-v1.d/canary", ".config/canary",
                 ".config/gh/hosts.yml", ".config/gcloud/application_default_credentials.json",
                 ".kube/config", ".docker/config.json", ".nock/canary",
                 "Library/Keychains/canary", ".netrc", ".git-credentials"]
        if system == "Darwin":
            paths += [".env", ".env.production", ".claude/canary", ".claude/.credentials.json", ".claude.json", ".codex/canary", ".codex/auth.json"]
        for rel in paths:
            p = home / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(CANARY)
        cases = [(rel, home / rel, home / rel, False) for rel in paths]
        secret = home / ".ssh/canary"
        symlink = project / "credential-symlink"
        symlink.symlink_to(secret)
        cases.append(("symlink", symlink, secret, False))
        hardlink = home / ".ssh/hardlink"
        os.link(secret, hardlink)
        cases.append(("hardlink-denied-name", hardlink, hardlink, False))
        case_path = home / ".SSH/CANARY"
        # Linux's case-sensitive path is a distinct file, so use a name alias
        # to prove alternate spelling reaches the same protected target.
        if not case_path.exists():
            (home / ".SSH").symlink_to(home / ".ssh")
            (home / ".ssh/CANARY").symlink_to(secret)
        assert os.path.samefile(case_path, secret), "case alias must reach canary"
        cases.append(("different-case", case_path, secret, False))
        cases.append(("grandchild", secret, secret, True))
        if system == "Linux":
            cases.append(("proc-self-root", Path("/proc/self/root") / str(secret).lstrip("/"), secret, False))
        for name, path, grant, grandchild in cases:
            command = read_command(path, grandchild)
            positive = run(command, project, env)
            assert positive.returncode == 0 and CANARY in positive.stdout, (name, "positive control", positive.stderr)
            configure()
            denied = run([str(binary), "wrap", "--"] + command, project, env)
            assert denied.returncode == 73 and "READ_ATTEMPT" in denied.stdout and CANARY not in denied.stdout, (name, "not an enforced read denial", denied.returncode, denied.stdout, denied.stderr)
            configure([str(grant)])
            refused = run([str(binary), "wrap", "--"] + command, project, env)
            assert refused.returncode != 0 and "built-in credential deny" in refused.stderr and "READ_ATTEMPT" not in refused.stdout, (name, "overlapping allow was not refused", refused.returncode, refused.stderr)
            mutated = run([str(mutant), "wrap", "--"] + command, project, env)
            # This is the same refusal assertion above with the guard removed:
            # every case must turn red, and it must reach the fake canary.
            assert mutated.returncode == 0 and CANARY in mutated.stdout, (name, "mutation did not expose canary", mutated.returncode, mutated.stdout, mutated.stderr)
            print(f"PASS {name}: readable control; fenced denial; allow refusal; mutation RED", flush=True)

        configure([str(home)])
        refused = run([str(binary), "wrap", "--", "/bin/echo", "CHILD_STARTED"], project, env)
        assert refused.returncode != 0 and "built-in credential deny" in refused.stderr and "CHILD_STARTED" not in refused.stdout

        # Package manager config is opt-in, and project dotenv stays readable.
        configure()
        for p in (project / ".env", project / "premade-hardlink"):
            if p.name == "premade-hardlink":
                os.link(secret, p)
            else:
                p.write_text(CANARY)
            control = run([str(binary), "wrap", "--"] + read_command(p), project, env)
            assert control.returncode == 0 and CANARY in control.stdout, (p.name, "documented readable control", control.stderr)
        print("PASS project .env and pre-made in-project hardlink remain readable (documented limit)", flush=True)
        for rel in (".npmrc", ".pypirc"):
            p = home / rel
            p.write_text(CANARY)
            configure([str(p)])
            control = run([str(binary), "wrap", "--"] + read_command(p), project, env)
            assert control.returncode == 0 and CANARY in control.stdout, (rel, "opt-in control", control.stderr)
        if system == "Darwin":
            for agent, own, other in (("claude-code", ".claude/canary", ".codex/canary"), ("codex", ".codex/canary", ".claude/canary")):
                configure(runtime=agent)
                permitted = run([str(binary), "wrap", "--"] + read_command(home / own), project, env)
                denied = run([str(binary), "wrap", "--"] + read_command(home / other), project, env)
                assert permitted.returncode == 0 and CANARY in permitted.stdout, (agent, "own login", permitted.stderr)
                assert denied.returncode == 73 and CANARY not in denied.stdout, (agent, "foreign login", denied.stderr)
            print("PASS runtime presets permit only their own agent login store", flush=True)


if __name__ == "__main__":
    main()
