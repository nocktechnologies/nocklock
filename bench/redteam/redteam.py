#!/usr/bin/env python3
"""Red-team bench driver (N11623). Started by run.sh; see attacks.toml.

Runs each scripted attack inside its own `nocklock wrap` session, pairs the
attempt with the signed row that proves the verdict, runs `nocklock verify
--audit` and `nockguard verify`, and writes REPORT.md + report.json.
"""
import argparse
import json
import os
import re
import signal
import socket
import sqlite3
import shlex
import stat
import subprocess
import sys
import time
import tempfile
import tomllib
from pathlib import Path

ATTACK_DEADLINE = 120  # seconds per attack
HEX64 = r"[0-9a-fA-F]{64}"
CANARY_ENV = {"BENCH_SECRET_TOKEN": "bench-canary-not-a-real-secret"}


class FaultExit(int):
    """An exit status whose process-group cleanup failed: the real status, flagged as a harness fault."""


class SetupFault(Exception):
    """The bench is mis-set-up; no attack may run, because its verdicts would mean nothing."""


def run(argv, cwd, env, dir_fd, name, until):
    """Run argv in its own session, output to the regular file `name` under `dir_fd`.

    The log is created O_EXCL|O_NOFOLLOW|O_NONBLOCK through the directory fd, so a symlink or
    FIFO planted at its path is refused, and is read back through that same fd (pread), never
    by path. A non-regular file is a HARNESS-FAULT. Returns (exit, output). Exit 124 means the
    deadline `until` (a time.monotonic() value) expired and the process group was SIGKILLed;
    None means a harness fault; a FaultExit is the real exit with a failed process-group cleanup, so a
    breach stays visible. An interrupt kills the group before it propagates. Nothing here blocks unbounded, and no pipe is held open.
    """
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
    except OSError as e:
        return None, f"HARNESS-FAULT: could not create log {name}: {e}"
    with os.fdopen(fd, "r+b") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None, f"HARNESS-FAULT: log {name} is not a regular file"
        try:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=f,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as e:
            return None, f"HARNESS-FAULT: could not launch {argv[0]}: {e}"
        rc, timed_out = 124, False
        try:
            rc = p.wait(timeout=max(0.0, until - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
        except BaseException:  # Ctrl-C, or SIGTERM turned into KeyboardInterrupt by main()
            try:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise
        try:
            os.killpg(p.pid, signal.SIGKILL)  # also reaps stragglers a finished attack left behind
        except ProcessLookupError:
            pass
        except OSError as e:  # e.g. a root-owned helper in the group cannot be signalled
            text = os.pread(f.fileno(), 1 << 20, 0).decode(errors="replace").strip()
            return FaultExit(rc), f"HARNESS-FAULT: process-group cleanup failed (killpg {p.pid}: {e}); attack exit was {rc}; {text[-300:]}"
        if timed_out:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return None, "HARNESS-FAULT: process not reaped after SIGKILL"
        text = os.pread(f.fileno(), 1 << 20, 0).decode(errors="replace").strip()
    return rc, f"timed out; {text[-300:]}" if timed_out else text


def udp_sink():
    """Host-side UDP receiver on port 53 outside the fence: any datagram it sees escaped.

    It binds the host's outbound address, not the wildcard, so a local stub resolver on
    127.0.0.53:53 does not collide. Port 53 needs privilege (CI lowers ip_unprivileged_port_start).
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))  # route lookup only, nothing is sent
        ip = probe.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        probe.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, 53))
    except OSError as e:
        raise SetupFault(f"cannot bind the DNS receiver {ip}:53 (needs root or net.ipv4.ip_unprivileged_port_start<=53): {e}")
    s.settimeout(0.2)
    return s, f"{ip}:53"


def sink_hits(s, until):
    """Datagrams the sink sees before `until`, plus any already queued when the deadline passes.

    The queued remainder is drained without waiting and capped, so a flood cannot stall the bench.
    """
    n = 0
    try:
        while time.monotonic() < until:
            s.recvfrom(512)
            n += 1
        s.setblocking(False)
        for _ in range(1000):
            s.recvfrom(512)
            n += 1
    except (socket.timeout, BlockingIOError):
        pass
    finally:
        s.settimeout(0.2)
    return n


def control_result(exit_code, sink_count):
    """An unfenced control reached if it exited 0 or a datagram arrived at the host sink."""
    return {"exit": exit_code, "reached": exit_code == 0 or sink_count > 0}


def classify(rc, atk):
    """(executed, fault) for an attack's exit status.

    Only the exits an attack declares in `blocked_exit` count as its blocked outcome; any other
    non-zero exit (a crashed client's own 1, a missing binary's 127) is a fault, never a block. A
    deadline kill (124) is left to verdict() as INCONCLUSIVE. mcp_client.py: 3 no reply, 4 stopped +
    shutdown fault, 5 executed + shutdown fault.
    """
    if rc is None:
        return False, True
    cleanup_fault = isinstance(rc, FaultExit)
    executed, fault = _classify(int(rc), atk)
    return executed, fault or cleanup_fault


def _classify(rc, atk):
    """classify() for a plain exit status."""
    if atk["evidence"] == "nockguard":
        executed, fault = rc in (0, 5), rc in (3, 4, 5)
    else:
        executed, fault = rc == 0, False
    if atk["expect"] == "blocked" and not executed and rc != 124 and rc not in atk.get("blocked_exit", []):
        fault = True
    return executed, fault


def verdict(res, atk, executed):
    """(outcome, ok) for one attack. A timeout (exit 124) or an unreached control is INCONCLUSIVE, never a block."""
    ctl = res["control"]
    if res["exit"] == 124 or (ctl is not None and (ctl["exit"] == 124 or not ctl["reached"])):
        return "INCONCLUSIVE", False
    outcome = "ALLOWED" if executed else "HARNESS-FAULT" if res["fault"] else "BLOCKED"
    ok = res["ran"] and executed == (atk["expect"] == "allowed") and not res["planted"] and not res["fault"]
    return outcome, ok


def find_audit_db(state):
    dbs = sorted(Path(state).rglob("events.db"))
    if len(dbs) != 1:
        raise RuntimeError(f"expected exactly one NockLock audit db under {state}, found {len(dbs)}")
    return dbs[0]


def check_setup(config, evidence):
    """Raise SetupFault if any evidence path lies under a directory or file the fence grants.

    Grants are read from the config the fence will enforce (root, allow, allow_rw).
    Reading the config file is equivalent to
    the effective config here because run.sh writes every grant into it explicitly.
    """
    fs = tomllib.loads(Path(config).read_text())["filesystem"]
    base = Path(config).parent.parent
    grants = [os.path.realpath(base / g) for g in [fs["root"], *fs.get("allow", []), *fs.get("allow_rw", [])]]
    bad = [f"{name} {p} is under grant {g}" for name, p in evidence.items()
           for g in grants if Path(os.path.realpath(p)).is_relative_to(g)]
    if bad:
        raise SetupFault("evidence reachable from inside the fence: " + "; ".join(bad))


def nocklock_detail_matches(detail, atk):
    """Match file report fields, never collector provenance; retain legacy text support."""
    if not isinstance(detail, str):
        return False
    legacy_match = atk["rule"] in detail and (not atk.get("match") or atk["match"] in detail)
    if atk["event"] != "file_blocked":
        return legacy_match
    try:
        envelope = json.loads(detail)
    except json.JSONDecodeError:
        # An invalid JSON-looking envelope is not a legacy proof string.
        return not detail.lstrip().startswith(("{", "[", '"')) and legacy_match
    if (not isinstance(envelope, dict) or type(envelope.get("version")) is not int
            or envelope["version"] != 1 or not isinstance(envelope.get("connection_peer"), dict)):
        return False
    report = envelope.get("report")
    fields = {"type", "action", "path", "operation", "reason", "timestamp"}
    if (not isinstance(report, dict) or set(report) != fields
            or not all(isinstance(value, str) for value in report.values())
            or report["type"] != "fs" or report["action"] != "blocked"):
        return False
    field, separator, value = atk["rule"].partition("=")
    report_field = {"op": "operation", "path": "path", "reason": "reason"}.get(field)
    if not separator or report_field is None:
        return False
    # A path rule is a substring test: report paths are absolute, so a bare
    # filename rule would never match a prefix test. op and reason stay prefix.
    field_ok = value in report["path"] if report_field == "path" else report[report_field].startswith(value)
    return field_ok and (not atk.get("match") or atk["match"] in report["path"])


def nocklock_proof(rows, atk):
    """First row of this attack's session matching the attack's proof fields."""
    want_blocked = 1 if atk["expect"] == "blocked" and not atk.get("floor") else 0
    for r in rows:
        if r["event_type"] != atk["event"] or not nocklock_detail_matches(r["detail"], atk):
            continue
        if r["blocked"] != want_blocked:
            continue
        return {"source": "nocklock", "event_id": r["id"], "event_type": r["event_type"],
                "rule": atk["rule"], "detail": r["detail"], "chain_hash": r["entry_hash"],
                "prev_hash": r["prev_hash"], "signed": bool(r["entry_sig"])}
    return None


def nockguard_proof(trail, atk):
    for n, ent in enumerate(trail, 1):
        if ent.get("tool") != atk["tool"] or ent.get("decision") != atk["decision"]:
            continue
        if atk["rule"] not in ent.get("reason", ""):
            continue
        return {"source": "nockguard", "event_id": n, "event_type": ent["decision"],
                "rule": ent["reason"], "detail": f"agent={ent.get('agent')} tool={ent['tool']}",
                "chain_hash": ent.get("sig", ""), "prev_hash": "", "signed": bool(ent.get("sig"))}
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--nocklock", required=True)
    ap.add_argument("--nockguard", required=True)
    a = ap.parse_args()

    def on_term(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, on_term)
    try:
        bench(a)
    except SystemExit:
        raise
    except BaseException as e:  # the report is always written, whatever broke
        kind = "SETUP-FAULT" if isinstance(e, SetupFault) else "HARNESS-FAULT"
        out = Path(a.out)
        report = {"passed": False, "verdict": kind, "error": f"{type(e).__name__}: {e}", "attacks": []}
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (out / "REPORT.md").write_text(f"# NockLock + NockGuard red-team bench\n\n**Verdict: {kind}**\n\n{cell(report['error'])}\n")
        print(f"{kind}: {e}", file=sys.stderr)
        sys.exit(2)


def bench(a):
    work, out = Path(a.work), Path(a.out)
    root = work / "root"
    attacks = tomllib.loads((out / "attacks.toml").read_text())["attack"]

    env = {"PATH": os.environ["PATH"], "HOME": str(work / "home"), "XDG_STATE_HOME": str(work / "state"),
           "LANG": "C.UTF-8", **CANARY_ENV}
    keydir = work / "home/.nockguard/keys"
    key, pubfile = keydir / "bench.ed25519", keydir / "bench.pub"  # nockguard keygen --agent bench
    try:
        seed, pub = key.read_text().strip(), pubfile.read_text().strip()
    except OSError as e:
        raise SetupFault(f"nockguard keygen left no key pair under {keydir}: {e}")
    if not (re.fullmatch(HEX64, seed) and re.fullmatch(HEX64, pub) and seed != pub):
        raise SetupFault("bench.ed25519 must hold the 64-hex private seed and bench.pub a different 64-hex public key")
    # The private seed stays host-side (the proxy finds it by name under HOME). verify runs with an
    # empty HOME and the trail (--audit) and public key (--ed25519-pub-env) passed explicitly: `--agent`
    # would derive the trail path from HOME and ignore --audit, so it is not used.
    empty_home = tempfile.mkdtemp(prefix="verify-home.", dir=work)
    verify_env = {**env, "HOME": empty_home, "NOCKGUARD_AGENT_BENCH_ED25519_PUB": pub}
    trail_path = work / "home/.nockguard/logs/bench.audit.jsonl"  # <agent>.audit.jsonl beside the policy audit path
    subst = {"@WORK@": str(work), "@BIN@": str(work / "bin"),
             "@KEY@": str(key), "@TRAIL@": str(trail_path)}
    check_setup(work / "root/.nock/config.toml",
                {"scratch root": work, "canary": work / "outside/canary.txt", "outside dir": work / "outside",
                 "audit state": work / "state", "nockguard key": key, "nockguard trail": trail_path,
                 "nockguard policy": work / "policy"})
    proxy = [a.nockguard, "proxy", "--upstream", f"python3 {work}/bin/mcp_upstream.py",
             "--agent", "bench", "--policy", str(work / "policy/policy.yaml")]
    sink, subst["@SINK@"] = udp_sink()
    # Sink self-check: a sink that cannot receive would make "nothing escaped" meaningless.
    chk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chk.sendto(b"x", sink.getsockname())
    chk.close()
    if sink_hits(sink, time.monotonic() + 5) != 1:
        raise SetupFault("UDP sink failed its self-check; refusing to run")

    def sub(text):
        for k, v in subst.items():
            text = text.replace(k, v)
        return text

    # Inside the fence root: the fenced child fstat()s its stdout, so the log must be reachable.
    # Opened once; every log is created through this fd, never by a path the child could redirect.
    logfd = os.open(root / "logs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    results = []
    for atk in attacks:
        cmd = sub(atk["cmd"])
        until = time.monotonic() + ATTACK_DEADLINE  # one deadline: control, fenced run and sink drain
        control = None
        if atk.get("floor"):
            # Same command outside the fence: the attack must reach, or the fenced block proves nothing.
            crc, _ = run(["/bin/sh", "-c", cmd], root, env, logfd, f"{atk['id']}.control.log", until)
            control = control_result(crc, sink_hits(sink, until))
        if atk.get("host"):
            # NockGuard's own proof is its signed policy deny: run the client on the host, outside the fence.
            argv = [sys.executable, str(work / "bin/mcp_client.py"), atk["tool"], "10", "--", *proxy]
            cmd = shlex.join(argv)  # report the command that really ran
            rc, output = run(argv, root, env, logfd, f"{atk['id']}.log", until)
        else:
            rc, output = run([a.nocklock, "wrap", "--net-fence=netns", "--", "/bin/sh", "-c", cmd],
                             root, env, logfd, f"{atk['id']}.log", until)
        # "planted": the attack left its mark (file written / datagram reached the sink).
        planted = (bool(atk.get("absent")) and Path(sub(atk["absent"])).exists()) or sink_hits(sink, until) > 0
        results.append({"atk": atk, "cmd": cmd, "exit": rc, "output": output[-400:], "planted": planted,
                        "control": control})
        print(f"[{atk['id']}] exit={rc}", flush=True)
        if os.environ.get("REDTEAM_VERBOSE"):
            print(output, flush=True)

    # Pair attempts with their signed rows. Sessions are strictly sequential, so
    # the Nth session_start in the chain is the Nth attack; the count is asserted.
    try:
        con = sqlite3.connect(f"file:{find_audit_db(work / 'state')}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        sessions = [r["session_id"] for r in con.execute(
            "SELECT session_id FROM events WHERE event_type='session_start' ORDER BY id")]
    except (RuntimeError, sqlite3.Error) as e:
        con, sessions = None, []
        print(f"no audit pairing: {e}", file=sys.stderr)
    lines = trail_path.read_text().splitlines() if trail_path.exists() else []
    trail = []
    for line in lines:
        try:
            trail.append(json.loads(line))
        except ValueError:
            pass  # a damaged line is `nockguard verify`'s to report, not a reason to lose the run

    # After a timeout, a launch failure or a session-count mismatch the pairing is unreliable, so no proof is claimed.
    fenced = [r for r in results if not r["atk"].get("host")]  # host attacks open no NockLock session
    paired = len(sessions) == len(fenced)
    sids = iter(sessions if paired else [])
    for res in results:
        atk = res["atk"]
        sid = None if atk.get("host") else next(sids, None)
        rows = [dict(r) for r in con.execute("SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))] if paired and sid else []
        end = next((r["detail"] for r in rows if r["event_type"] == "session_end"), "")
        # A wrap that failed to launch has no session_end matching the child's status.
        res["ran"] = res["exit"] is not None if atk.get("host") else end == f"exit_code={res['exit']}"
        # A fault never turns a verdict into BLOCKED: a breach seen before a shutdown fault stays ALLOWED
        # and the fault is reported beside it. Faults come only from harness-side signals (no result from
        # run(), the MCP client's exit codes), never from text the fenced child printed.
        executed, res["fault"] = classify(res["exit"], atk)
        res["outcome"], res["outcome_ok"] = verdict(res, atk, executed)
        res["proof"] = nockguard_proof(trail, atk) if atk["evidence"] == "nockguard" else nocklock_proof(rows, atk)
        res["proof_ok"] = bool(res["proof"] and res["proof"]["signed"])
        # A missing proof is diagnosable from the report alone: keep what the session did log.
        res["session_rows"] = [] if res["proof"] else [f"{r['event_type']} blocked={r['blocked']} {r['detail'][:160]}" for r in rows]
    if con:
        con.close()

    tool_faults = []

    def tool(name, argv, tool_env=env, must_succeed=False):
        rc, text = run(argv, root, tool_env, logfd, f"{name}.log", time.monotonic() + 60)
        # A launch or cleanup fault means the exit cannot be trusted; a failing version command is a broken binary.
        if rc is None or isinstance(rc, FaultExit) or (must_succeed and rc != 0):
            tool_faults.append(name)
        return rc, text

    lock_rc, lock_out = tool("verify-nocklock", [a.nocklock, "verify", "--audit"])
    guard_rc, guard_out = tool("verify-nockguard", [a.nockguard, "verify", "--ed25519-pub-env", "NOCKGUARD_AGENT_BENCH_ED25519_PUB", "--audit", str(trail_path)], verify_env)
    versions = {n: tool(f"version-{n}", [b, "version"], must_succeed=True)[1]
                for n, b in (("nocklock", a.nocklock), ("nockguard", a.nockguard))}

    attack_rows = [r for r in results if r["atk"]["expect"] == "blocked"]
    controls = [r for r in results if r["atk"]["expect"] == "allowed"]
    bar = {
        "every_attack_has_signed_deny_row_naming_rule": all(r["proof_ok"] for r in attack_rows),
        "kernel_floor_attacks_reached_when_unfenced": all(r["control"]["reached"] for r in attack_rows if r["control"]),
        "no_attack_inconclusive": all(r["outcome"] != "INCONCLUSIVE" for r in results),
        "no_attack_succeeds": all(r["outcome_ok"] for r in attack_rows),
        "no_deny_unsigned": all(r["proof"] is None or r["proof"]["signed"] for r in attack_rows),
        "nocklock_verify_audit_exit0": lock_rc == 0 and "verify-nocklock" not in tool_faults,
        "nockguard_verify_exit0": guard_rc == 0 and "verify-nockguard" not in tool_faults,
        "no_harness_fault_after_scoring": not tool_faults,
        "negative_control_allowed_and_logged": bool(controls) and all(r["outcome_ok"] and r["proof_ok"] for r in controls),
    }
    passed = all(bar.values())

    report = {"passed": passed, "pass_bar": bar, "versions": versions,
              "verify": {"nocklock": {"exit": lock_rc, "output": lock_out},
                         "nockguard": {"exit": guard_rc, "output": guard_out}},
              "attacks": [{
                  "id": r["atk"]["id"], "class": r["atk"]["class"], "tried": r["cmd"],
                  "expected": r["atk"]["expect"], "result": r["outcome"], "exit": r["exit"],
                  "host": bool(r["atk"].get("host")), "floor_only": bool(r["atk"].get("floor")), "control": r["control"], "outcome_ok": r["outcome_ok"], "harness_fault": r["fault"], "output": r["output"],
                  "session_rows": r["session_rows"],
                  "proof": r["proof"]} for r in results]}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "REPORT.md").write_text(render_md(report))
    print(("PASS" if passed else "FAIL") + " - see " + str(out / "REPORT.md"))
    sys.exit(0 if passed else 1)


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_md(rep):
    atk = [r for r in rep["attacks"] if r["expected"] == "blocked"]
    held = [r for r in atk if r["outcome_ok"] and r["proof"] and r["proof"]["signed"]]
    floor = sum(r["floor_only"] for r in held)
    lines = ["# NockLock + NockGuard red-team bench", "",
             f"{len(held) - floor} of {len(atk)} attacks have a per-attempt signed deny row; "
             f"{floor} blocked by the kernel floor (unfenced control reached, fenced blocked).", "",
             f"**Verdict: {'PASS' if rep['passed'] else 'FAIL'}**", "",
             f"nocklock `{cell(rep['versions']['nocklock'])}` / nockguard `{cell(rep['versions']['nockguard'])}`", "",
             "## Pass bar", ""]
    lines += [f"- [{'x' if ok else ' '}] {k.replace('_', ' ')}" for k, ok in rep["pass_bar"].items()]
    lines += ["", "## Attempts", "",
              "| attack | class | tried | unfenced control | result | proof | event id | rule | chain hash (NockGuard: entry signature) |",
              "|---|---|---|---|---|---|---|---|---|"]
    for r in rep["attacks"]:
        p = r["proof"]
        proof = "MISSING" if not p else (f"{p['source']} {'signed' if p['signed'] else 'UNSIGNED'}"
                                         + (": blocked by kernel floor: session fence-state row cited, no per-attempt row"
                                            if r["floor_only"] else ""))
        c = r["control"]
        ctl = "n/a" if c is None else "reached" if c["reached"] else "NOT REACHED"
        verdict = (r["result"] + (" + HARNESS-FAULT" if r["harness_fault"] and r["result"] != "HARNESS-FAULT" else "")
                   + ("" if r["outcome_ok"] else " ✗ UNEXPECTED"))
        lines.append("| " + " | ".join([
            f"`{r['id']}`", ("NockGuard (host): " if r["host"] else "") + r["class"], "`" + cell(" ".join(r["tried"].split()))[:110] + "…` (full command in report.json)", ctl, verdict, proof,
            str(p["event_id"]) if p else "-", f"`{cell(p['rule'])}`" if p else "-",
            f"`{p['chain_hash'][:16]}…`" if p and p["chain_hash"] else "-"]) + " |")
    lines += ["", "Attempts marked *blocked by kernel floor* are stopped by the kernel floor (netns default-drop) "
              "before any proxy sees them; NockLock writes no per-attempt row for those today, so "
              "the pinned row is the session's signed row proving the floor was armed. Each is also run once "
              "outside `nocklock wrap`; if that control does not reach, the attack is INCONCLUSIVE, not a pass. "
              "Full hashes are in "
              "`report.json`.", "", "## Verification", "",
              f"- `nocklock verify --audit` exit {rep['verify']['nocklock']['exit']}",
              f"- `nockguard verify --ed25519-pub-env … --audit <trail>` exit {rep['verify']['nockguard']['exit']}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
