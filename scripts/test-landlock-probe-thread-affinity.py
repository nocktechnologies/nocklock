#!/usr/bin/env python3
"""Require the old unpinned static probe to fail on an unprivileged Linux host.

The positive repetitions run separately in test.yml. This control removes only
the probe's thread pin through a temporary Go overlay; production is unchanged.
Scheduling is nondeterministic, so failure to reproduce within the bounded run
is inconclusive and fails this check. A timeout or unrelated failure never counts.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def is_expected_failure(code, transcript):
    if code != 1 or "panic:" in transcript or "fatal error:" in transcript:
        return False
    events = []
    for line in transcript.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue  # Compiler diagnostics are not accepted as test evidence.
        if isinstance(event, dict):
            events.append(event)
    name = "TestLandlockChildCanMutateRootButNotRelocatedAudit"
    failed_tests = {event.get("Test") for event in events
                    if event.get("Action") == "fail" and event.get("Test")}
    escaped = any(event.get("Test") == name and
                  "write audit database error = <nil>, want EACCES or EPERM" in event.get("Output", "")
                  for event in events)
    return failed_tests == {name} and escaped


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("run the Landlock thread-affinity control as a non-root Linux user")
    if os.environ.get("GOFLAGS"):
        raise SystemExit("unset GOFLAGS before running the isolated mutation control")
    repo = Path(__file__).resolve().parents[1]
    source = repo / "internal/fence/fs/landlock/testdata/staticprobe/main.go"
    original = source.read_text()
    pin = "\truntime.LockOSThread()\n"
    runtime_import = '\t"runtime"\n'
    if original.count(pin) != 1 or original.count(runtime_import) != 1:
        raise SystemExit("static probe changed: review the thread-pin mutation before updating it")

    with tempfile.TemporaryDirectory(prefix="nocklock-thread-pin-") as scratch:
        scratch = Path(scratch)
        mutant = scratch / "main.go"
        mutant.write_text(original.replace(pin, "").replace(runtime_import, ""))
        overlay = scratch / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        env = dict(os.environ, GOFLAGS=f"-overlay={overlay}")
        for procs in (2, 8, 32):
            env["GOMAXPROCS"] = str(procs)
            log = scratch / f"control-{procs}.jsonl"
            command = [
                "go", "test", "./internal/fence/fs/landlock", "-json",
                "-run", "^TestLandlockChildCanMutateRootButNotRelocatedAudit$",
                "-count=25", "-failfast", "-timeout=150s",
            ]
            with log.open("w") as output:
                proc = subprocess.Popen(command, cwd=repo, env=env, stdout=output,
                                        stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = proc.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)
                    raise SystemExit("thread-pin control timed out; no valid negative receipt")
                finally:
                    output.flush()
                    transcript = log.read_text()
                    print(f"UNPINNED_CONTROL GOMAXPROCS={procs} exit={proc.returncode}", flush=True)
                    print(transcript, end="", flush=True)
            if code == 0:
                continue
            if not is_expected_failure(code, transcript):
                raise SystemExit("thread-pin control failed for an unrelated reason; inspect the receipt")
            print("PASS: removing only the static probe's thread pin reproduced the audit-write failure")
            return
    raise SystemExit("INCONCLUSIVE: old unpinned helper did not reproduce within 75 attempts")


if __name__ == "__main__":
    main()
