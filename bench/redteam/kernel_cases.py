#!/usr/bin/env python3
"""Required companion report for kernel-dependent Unix-socket/io_uring cases.

Runs the real Go/C controls; it does not change attacks.toml or the main bench's
scoring. Known reachable sockets and unavailable proof remain visible gaps.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import signal
import subprocess

CASES = (
    ("unix-wrap", "./internal/cli", "TestWrapUnixSocketReachability"),
    ("abi9", "./internal/fence/fs/landlock", "TestLandlockABI9UnixSocketIsolation"),
    ("io-uring", "./internal/fence/syscallfence", "TestEnforce_IORingSocketConnectDenied"),
)
CASE_TIMEOUT_SECONDS = 300
CLEANUP_TIMEOUT_SECONDS = 5
SIGTERM_GRACE_SECONDS = 2


def parse_result(raw, test, returncode):
    actions, output = {}, []
    for line in raw.splitlines():
        event = json.loads(line)
        name = event.get("Test", "")
        if name == test or name.startswith(test + "/"):
            if "Output" in event:
                output.append(event["Output"])
            if event.get("Action") in ("pass", "skip", "fail"):
                if name in actions:
                    raise ValueError("duplicate final test action")
                actions[name] = event["Action"]
    if returncode != 0 or test not in actions or actions[test] == "fail":
        raise ValueError(f"{test} failed or did not run (exit {returncode})")
    return actions, "".join(output)


def classify(case, actions, output):
    test = next(item[2] for item in CASES if item[0] == case)
    if actions[test] == "skip":
        expected = "ABI9_COVERAGE_GAP:" if case == "abi9" else "ambient io_uring control is unavailable"
        if case == "unix-wrap" or expected not in output:
            raise ValueError(f"unexpected skip in {test}: {output}")
        return dict(case=case, verdict="SKIP", reason=output.strip())
    if case == "unix-wrap":
        below = test + "/default_below_ABI_9_runs_and_records_reachability"
        strict = test + "/strict_config_refuses_below_ABI_9"
        enforced = test + "/Landlock_ABI_9_enforcement_with_filesystem_rules"
        socket_only = test + "/Landlock_ABI_9_synthesized_socket-only_spec_is_applied"
        if actions.get(below) == "pass":
            if actions.get(strict) != "pass" or actions.get(enforced) != "skip" or actions.get(socket_only) != "skip":
                raise ValueError("inconsistent Unix-socket kernel branches")
            return dict(case=case, verdict="KNOWN-LIMIT",
                        reason="Real wrapped pathname and abstract sockets reachable below ABI 9; signed boundary and strict refusal controls passed.")
        if (actions.get(below) != "skip" or actions.get(strict) != "skip"
                or actions.get(enforced) != "pass" or actions.get(socket_only) != "pass"):
            raise ValueError("Unix-socket enforcement subtests did not pass")
        return dict(case=case, verdict="PASS", reason="Full CONFINED wrap: unrelated pathname/abstract denied; proxy/event sockets allowed, with unfenced live controls.")
    if case == "abi9":
        return dict(case=case, verdict="PASS", reason="Real ABI9+ Landlock: exact socket pathname allowed; unrelated pathname and abstract connects return EACCES/EPERM; all sockets reachable unfenced.")
    return dict(case=case, verdict="PASS", reason="Raw seccomp boundary: unfenced io_uring SOCKET+CONNECT reaches live TCP listener; fenced io_uring_setup returns EPERM. This is not a full-wrap probe.")


def _partial(value):
    # TimeoutExpired carries the complete captured bytes so far even in text
    # mode, so decode them when needed.
    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""


def _stop_group(process, stdout="", stderr="", grace=0):
    """Kill the case's owned process group, drain output within a deadline and reap.

    Returns (stdout, stderr, fault). A descendant outside the killed group can
    retain a pipe; the partial receipt is preserved if the bounded drain times out.
    SIGINT and SIGTERM are ignored for the whole cleanup so a second signal cannot
    skip the SIGKILL, drain or reap; the previous handlers are restored afterwards.
    """
    fault = ""
    saved = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            saved[signum] = signal.signal(signum, signal.SIG_IGN)
        except ValueError:
            pass  # Not the main thread: handlers cannot be changed here.
    try:
        if grace:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=grace)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            except OSError as term_error:
                fault += f"; process-group terminate failed: {term_error}"
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # The leader/group can have exited while a pipe remains open.
        except OSError as kill_error:
            fault += f"; process-group kill failed: {kill_error}"
        try:
            stdout, stderr = process.communicate(timeout=CLEANUP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as drain_error:
            stdout, stderr = _partial(drain_error.stdout) or stdout, _partial(drain_error.stderr) or stderr
            fault += "; output drain exceeded cleanup deadline"
            process.stdout.close()
            process.stderr.close()
            try:
                process.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                fault += "; process was not reaped before cleanup deadline"
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)
    return stdout, stderr, fault


def run_case(repo, out, case, package, test):
    cmd = ["go", "test", "-json", "-count=1", "-timeout=4m", package, "-run", "^" + test + "$"]
    process = subprocess.Popen(cmd, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    timeout_fault = None
    try:
        stdout, stderr = process.communicate(timeout=CASE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        timeout_fault = "Harness timeout: not a denial verdict or completed test run"
        stdout, stderr, fault = _stop_group(process, _partial(exc.stdout), _partial(exc.stderr))
        timeout_fault += fault
        stderr += "\n" + timeout_fault + "\n"
    except BaseException:
        # KeyboardInterrupt, SIGTERM (see main) or any other exit path: never
        # leave the owned process group running.
        _stop_group(process, grace=SIGTERM_GRACE_SECONDS)
        raise
    (out / (case + ".jsonl")).write_text(stdout)
    (out / (case + ".stderr.txt")).write_text(stderr)
    # A successful leader and earlier pass events cannot rescue a timed-out
    # run. Persist receipts before raising so main can include this FAIL row.
    if timeout_fault is not None:
        raise ValueError(timeout_fault)
    return classify(case, *parse_result(stdout, test, process.returncode))


def head_commit(repo):
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                                       stderr=subprocess.DEVNULL).strip() or "unknown"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _on_sigterm(signum, frame):
    # Route SIGTERM through the same cleanup as KeyboardInterrupt: the raise
    # unwinds run_case, whose handler stops the process group.
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, _on_sigterm)
    repo = Path(__file__).resolve().parents[2]
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for case, package, test in CASES:
        try:
            if platform.system() != "Linux":
                raise ValueError("Linux kernel required; no cross-platform enforcement claim")
            rows.append(run_case(repo, args.out, case, package, test))
        except Exception as exc:
            rows.append(dict(case=case, verdict="FAIL", reason=str(exc)))
    failed = any(row["verdict"] == "FAIL" for row in rows)
    gaps = any(row["verdict"] in ("SKIP", "KNOWN-LIMIT") for row in rows)
    verdict = "FAIL" if failed else "PASS_WITH_COVERAGE_GAPS" if gaps else "PASS"
    report = dict(verdict=verdict, kernel=platform.release(), architecture=platform.machine(),
                  commit=head_commit(repo), cases=rows)
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# Kernel red-team companion", "", "Verdict: **" + verdict + "**", "",
             "This report is separate from the main bench score. SKIP is missing proof; KNOWN-LIMIT is observed reachable behavior.", ""]
    for row in rows:
        lines += [f"- {row['case']}: **{row['verdict']}** — " + row["reason"].replace("\n", " ")]
    (args.out / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(verdict + "; evidence: " + str(args.out))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
