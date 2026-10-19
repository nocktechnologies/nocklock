#!/usr/bin/env python3
"""Required companion report for kernel-dependent Unix-socket/io_uring cases.

Runs the real Go/C controls; it does not change attacks.toml or the main bench's
scoring. Known reachable sockets and unavailable proof remain visible gaps.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys

CASES = (
    ("unix-wrap", "./internal/cli", "TestWrapUnixSocketReachability"),
    ("abi9", "./internal/fence/fs/landlock", "TestLandlockABI9UnixSocketIsolation"),
    ("io-uring", "./internal/fence/syscallfence", "TestEnforce_IORingSocketConnectDenied"),
)
# With --require-abi, the full CONFINED wrap probe on ABI 9+ must show these
# values (logged by its "Landlock ABI 9 enforcement with filesystem rules"
# subtest) and the io_uring case, which requires io_uring_setup EPERM, must pass.
WRAP_CLAIMS = (
    ("a-pathname-socket-outside-root", "path", "DENIED"),
    ("b-abstract-socket", "abstract", "DENIED"),
    ("c-allowed-proxy-socket", "proxy", "CONNECTED"),
    ("c-allowed-event-socket", "event", "CONNECTED"),
)
WRAP_PROBE = re.compile(r"ABI9_WRAP_PROBE ((?:\w+=\w+ ?)+)")
SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
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


def landlock_abi():
    """Return the running kernel's Landlock ABI, or 0 when Landlock is absent."""
    if platform.system() != "Linux":
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET), None, ctypes.c_size_t(0),
                       ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    if abi >= 0:
        return abi
    code = ctypes.get_errno()
    if code in (errno.ENOSYS, errno.EOPNOTSUPP):
        return 0
    raise OSError(code, "landlock_create_ruleset version query failed: " + os.strerror(code))


def enforcement_claims(rows, out):
    """Expected vs actual for each required ABI 9+ enforcement claim.

    Reads the raw wrap test output, so a failed run still records what the
    probe observed.
    """
    raw = out / "unix-wrap.jsonl"
    match = WRAP_PROBE.search(raw.read_text()) if raw.exists() else None
    probe = dict(item.split("=", 1) for item in match.group(1).split()) if match else {}
    claims = [dict(claim=name, expected=expected, actual=probe.get(key, "MISSING"))
              for name, key, expected in WRAP_CLAIMS]
    claims.append(dict(claim="d-io-uring-setup-denied", expected="PASS",
                       actual=next((row["verdict"] for row in rows if row["case"] == "io-uring"), "MISSING")))
    return claims


def _partial(value):
    # TimeoutExpired carries the complete captured bytes so far even in text
    # mode, so decode them when needed.
    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""


# Set to a signal number when SIGINT or SIGTERM arrives during cleanup. The
# signal is recorded, never dropped and never raised there; run_case and main
# act on it once cleanup has finished.
_termination_requested = None


def _record_termination(signum, frame):
    global _termination_requested
    if _termination_requested is None:
        _termination_requested = signum


def _raise_if_terminated():
    if _termination_requested == signal.SIGINT:
        raise KeyboardInterrupt
    if _termination_requested is not None:
        raise SystemExit(128 + _termination_requested)


def _stop_group(process, stdout="", stderr="", grace=0):
    """Kill the case's owned process group, drain output within a deadline and reap.

    Returns (stdout, stderr, fault). A descendant outside the killed group can
    retain a pipe; the partial receipt is preserved if the bounded drain times out.
    SIGINT and SIGTERM are only recorded (see _record_termination) for the whole
    cleanup, so a signal cannot skip the SIGKILL, drain or reap and is not lost;
    the previous handlers are restored afterwards. Callers act on the record.
    """
    fault = ""
    saved = {}
    signals = (signal.SIGINT, signal.SIGTERM)
    try:
        # Block both while swapping handlers so none reaches an old handler
        # mid-swap; a pending one is delivered to the recorder on unblock.
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    except (AttributeError, ValueError):
        old_mask = None
    try:
        for signum in signals:
            try:
                saved[signum] = signal.signal(signum, _record_termination)
            except ValueError:
                pass  # Not the main thread: handlers cannot be changed here.
        if old_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

        if grace:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=grace)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                # Group already gone, or the grace period elapsed. The SIGKILL
                # below handles the second case.
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
        if old_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
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
        _, _, fault = _stop_group(process, grace=SIGTERM_GRACE_SECONDS)
        if fault:
            try:
                sys.stderr.write("kernel_cases: cleanup after interrupt" + fault + "\n")
            except OSError:
                pass  # A closed pipe after Ctrl-C must not replace the interrupt.
        _raise_if_terminated()
        raise
    (out / (case + ".jsonl")).write_text(stdout)
    (out / (case + ".stderr.txt")).write_text(stderr)
    # A successful leader and earlier pass events cannot rescue a timed-out
    # run. Persist receipts before raising so main can include this FAIL row.
    _raise_if_terminated()
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
    parser.add_argument("--out", type=Path)
    parser.add_argument("--require-abi", type=int, metavar="N",
                        help="fail before any case unless the kernel's Landlock ABI is at least N; "
                             "with --out, every case and enforcement claim must then pass")
    args = parser.parse_args()
    if args.out is None and args.require_abi is None:
        parser.error("--out is required")
    abi = landlock_abi()
    print(f"Landlock ABI: {abi}", flush=True)
    if args.require_abi is not None and abi < args.require_abi:
        print(f"FAIL: Landlock ABI {abi} is below the required {args.require_abi}; "
              "this kernel cannot prove the enforcement claims", file=sys.stderr)
        return 1
    if args.out is None:
        return 0
    signal.signal(signal.SIGTERM, _on_sigterm)
    repo = Path(__file__).resolve().parents[2]
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for case, package, test in CASES:
        _raise_if_terminated()
        try:
            if platform.system() != "Linux":
                raise ValueError("Linux kernel required; no cross-platform enforcement claim")
            rows.append(run_case(repo, args.out, case, package, test))
        except Exception as exc:
            rows.append(dict(case=case, verdict="FAIL", reason=str(exc)))
    failed = any(row["verdict"] == "FAIL" for row in rows)
    gaps = any(row["verdict"] in ("SKIP", "KNOWN-LIMIT") for row in rows)
    claims = []
    if args.require_abi is not None:
        # A gap is missing proof, so it fails a run that requires the proof.
        claims = enforcement_claims(rows, args.out)
        for row in rows:
            row["expected"] = "PASS"
        failed = gaps or failed or any(claim["actual"] != claim["expected"] for claim in claims)
    verdict = "FAIL" if failed else "PASS_WITH_COVERAGE_GAPS" if gaps else "PASS"
    report = dict(verdict=verdict, kernel=platform.release(), architecture=platform.machine(),
                  landlock_abi=abi, commit=head_commit(repo), cases=rows)
    if claims:
        report["claims"] = claims
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# Kernel red-team companion", "", "Verdict: **" + verdict + "**", "",
             "This report is separate from the main bench score. SKIP is missing proof; KNOWN-LIMIT is observed reachable behavior.", ""]
    for row in rows:
        lines += [f"- {row['case']}: **{row['verdict']}** — " + row["reason"].replace("\n", " ")]
    if claims:
        lines += ["", f"Required Landlock ABI {args.require_abi}+ claims (kernel ABI {abi}):", ""]
        lines += [f"- {c['claim']}: expected {c['expected']}, actual **{c['actual']}**" for c in claims]
    (args.out / "REPORT.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[2:]))
    print(verdict + "; evidence: " + str(args.out))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
