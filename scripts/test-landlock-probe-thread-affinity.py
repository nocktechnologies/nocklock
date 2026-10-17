#!/usr/bin/env python3
"""Prove Landlock's thread boundary on an unprivileged Linux host.

The required control confines thread A, confirms its audit write is denied, then
runs the same checks on a pre-existing, pinned thread B. An optional --unpinned
soak removes only the original pin and attempts natural scheduler migration.
Temporary Go overlays never change production source. Faults are not receipts.
"""

import argparse
import json
import os
from pathlib import Path
import re
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
    operations = ("write audit database", "truncate audit database", "unlink audit database",
                  "rename audit database", "create file in audit directory", "remove audit directory")
    escaped = any(event.get("Test") == name and
                  any(f"{operation} error = <nil>, want EACCES or EPERM" in event.get("Output", "")
                      for operation in operations)
                  for event in events)
    return failed_tests == {name} and escaped


def mutant_source(original, unpinned):
    pin = "\truntime.LockOSThread()\n"
    runtime_import = '\t"runtime"\n'
    call = "\trunFilesystemChecks(root, auditDB, denied)\n"
    if original.count(pin) != 1 or original.count(runtime_import) != 1 or original.count(call) != 1:
        raise ValueError("static probe changed: review the thread-boundary mutation")
    if unpinned:
        return original.replace(pin, "").replace(runtime_import, "")
    # Create B BEFORE applying Landlock on A so it cannot inherit A's policy.
    worker = pin + """	checks := make(chan func())
	ready := make(chan int)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		ready <- syscall.Gettid()
		(<-checks)()
		close(done)
	}()
	otherTID := <-ready
	confinedTID := syscall.Gettid()
	if otherTID == confinedTID {
		fmt.Fprintln(os.Stderr, "control threads are not distinct")
		os.Exit(2)
	}
"""
    dispatch = """	checkDenied("pinned audit write control", os.WriteFile(auditDB, []byte("control"), 0o600))
	fmt.Fprintf(os.Stderr, "CROSS_THREAD_CONTROL restricted_tid=%d probe_tid=%d pinned_write=denied\\n", confinedTID, otherTID)
	checks <- func() { runFilesystemChecks(root, auditDB, denied) }
	<-done
"""
    return original.replace(pin, worker).replace(call, dispatch)


def run_control(command, repo, env, log, label):
    with log.open("w") as output:
        proc = subprocess.Popen(command, cwd=repo, env=env, stdout=output,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            raise SystemExit("thread control timed out; no valid negative receipt")
        finally:
            try:
                # A completed Go test can leave its static probe alive, including
                # after Go's earlier internal timeout. Always retire the group.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
            finally:
                output.flush()
                transcript = log.read_text()
                print(f"{label} exit={proc.returncode}", flush=True)
                print(transcript, end="", flush=True)
    return code, transcript


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unpinned", action="store_true", help="optional natural-migration soak")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("run the Landlock thread control as a non-root Linux user")
    if os.environ.get("GOFLAGS"):
        raise SystemExit("unset GOFLAGS before running the isolated mutation control")
    repo = Path(__file__).resolve().parents[1]
    source = repo / "internal/fence/fs/landlock/testdata/staticprobe/main.go"
    with tempfile.TemporaryDirectory(prefix="nocklock-thread-pin-") as scratch:
        scratch = Path(scratch)
        mutant = scratch / "main.go"
        mutant.write_text(mutant_source(source.read_text(), args.unpinned))
        overlay = scratch / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        env = dict(os.environ, GOFLAGS=f"-overlay={overlay}")
        for procs in ((2, 8, 32) if args.unpinned else (2,)):
            env["GOMAXPROCS"] = str(procs)
            command = [
                "go", "test", "./internal/fence/fs/landlock", "-json",
                "-run", "^TestLandlockChildCanMutateRootButNotRelocatedAudit$",
                f"-count={25 if args.unpinned else 1}", "-failfast", "-timeout=150s",
            ]
            label = f"{'UNPINNED' if args.unpinned else 'CROSS_THREAD'}_CONTROL GOMAXPROCS={procs}"
            code, transcript = run_control(command, repo, env, scratch / f"control-{procs}.jsonl", label)
            if args.unpinned and code == 0:
                continue
            if not is_expected_failure(code, transcript):
                raise SystemExit("thread control did not produce the expected audit escape; inspect the receipt")
            if not args.unpinned:
                tids = re.findall(r"CROSS_THREAD_CONTROL restricted_tid=(\d+) probe_tid=(\d+) pinned_write=denied", transcript)
                if len(tids) != 1 or tids[0][0] == tids[0][1]:
                    raise SystemExit("missing distinct-thread and pinned-denial control receipt")
            print(f"PASS: {'unpinned helper reproduced' if args.unpinned else 'deterministic cross-thread control proved'} the audit escape")
            return
    print("INCONCLUSIVE: optional unpinned helper did not reproduce within 75 attempts; no enforcement pass claimed")


if __name__ == "__main__":
    main()
