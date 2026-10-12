#!/usr/bin/env python3
"""Red-team bench driver (N11623). Started by run.sh; see attacks.toml.

Runs each scripted attack inside its own `nocklock wrap` session, pairs the
attempt with the signed row that proves the verdict, runs `nocklock verify
--audit` and `nockguard verify`, and writes REPORT.md + report.json.
"""
import argparse
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ATTACK_DEADLINE = 120  # seconds per attack
CANARY_ENV = {"BENCH_SECRET_TOKEN": "bench-canary-not-a-real-secret"}


def run(argv, cwd, env, log, until):
    """Run argv in its own session, output to a file (no pipe a descendant could hold open).

    Returns (exit, output). Exit 124 means the deadline `until` (a time.monotonic()
    value) expired and the process group was SIGKILLed; None means the process was
    still not reaped after the kill (HARNESS-FAULT). Nothing here blocks unbounded.
    """
    with open(log, "wb") as f:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=f,
                             stderr=subprocess.STDOUT, start_new_session=True)
    rc, timed_out = 124, False
    try:
        rc = p.wait(timeout=max(0.0, until - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
    try:
        os.killpg(p.pid, signal.SIGKILL)  # also reaps stragglers a finished attack left behind
    except ProcessLookupError:
        pass
    if timed_out:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return None, "HARNESS-FAULT: process not reaped after SIGKILL"
    text = Path(log).read_text(errors="replace").strip()
    return rc, f"timed out; {text[-300:]}" if timed_out else text


def udp_sink():
    """Host-side UDP receiver outside the fence: any datagram it sees escaped."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.settimeout(0.2)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))  # route lookup only, nothing is sent
        ip = probe.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        probe.close()
    return s, f"{ip}:{s.getsockname()[1]}"


def sink_hits(s, until):
    """Datagrams the sink sees before `until`; stops draining at the attack's deadline."""
    n = 0
    try:
        while time.monotonic() < until:
            s.recvfrom(512)
            n += 1
    except (socket.timeout, BlockingIOError):
        pass
    return n


def find_audit_db(state):
    dbs = sorted(Path(state).rglob("events.db"))
    if len(dbs) != 1:
        sys.exit(f"expected exactly one NockLock audit db under {state}, found {len(dbs)}")
    return dbs[0]


def nocklock_proof(rows, atk):
    """First row of this attack's session matching the attack's proof fields."""
    want_blocked = 1 if atk["expect"] == "blocked" and not atk.get("floor") else 0
    for r in rows:
        if r["event_type"] != atk["event"] or atk["rule"] not in r["detail"]:
            continue
        if atk.get("match") and atk["match"] not in r["detail"]:
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
    work, out = Path(a.work), Path(a.out)
    root = work / "root"
    attacks = tomllib.loads((out / "attacks.toml").read_text())["attack"]

    env = {"PATH": os.environ["PATH"], "HOME": str(work / "home"), "XDG_STATE_HOME": str(work / "state"),
           "LANG": "C.UTF-8", **CANARY_ENV}
    subst = {"@WORK@": str(work), "@BIN@": str(work / "bin"), "@POLICY@": str(work / "policy" / "policy.yaml")}
    sink, subst["@SINK@"] = udp_sink()
    # Sink self-check: a sink that cannot receive would make "nothing escaped" meaningless.
    chk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chk.sendto(b"x", sink.getsockname())
    chk.close()
    if sink_hits(sink, time.monotonic() + 5) != 1:
        sys.exit("UDP sink failed its self-check; refusing to run")

    def sub(text):
        for k, v in subst.items():
            text = text.replace(k, v)
        return text

    logs = work / "logs"
    logs.mkdir()
    results = []
    for atk in attacks:
        cmd = sub(atk["cmd"])
        until = time.monotonic() + ATTACK_DEADLINE  # one deadline: control, fenced run and sink drain
        control = None
        if atk.get("floor"):
            # Same command outside the fence: the attack must reach, or the fenced block proves nothing.
            crc, _ = run(["/bin/sh", "-c", cmd], root, env, logs / f"{atk['id']}.control.log", until)
            sink_hits(sink, until)  # discard what the control sent
            control = {"exit": crc, "reached": crc == 0}
        rc, output = run([a.nocklock, "wrap", "--net-fence=netns", "--", "/bin/sh", "-c", cmd],
                         root, env, logs / f"{atk['id']}.log", until)
        # "planted": the attack left its mark (file written / datagram reached the sink).
        planted = (bool(atk.get("absent")) and Path(sub(atk["absent"])).exists()) or sink_hits(sink, until) > 0
        results.append({"atk": atk, "cmd": cmd, "exit": rc, "output": output[-400:], "planted": planted,
                        "control": control})
        print(f"[{atk['id']}] exit={rc}", flush=True)
        if os.environ.get("REDTEAM_VERBOSE"):
            print(output, flush=True)

    # Pair attempts with their signed rows. Sessions are strictly sequential, so
    # the Nth session_start in the chain is the Nth attack; the count is asserted.
    con = sqlite3.connect(f"file:{find_audit_db(work / 'state')}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    sessions = [r["session_id"] for r in con.execute(
        "SELECT session_id FROM events WHERE event_type='session_start' ORDER BY id")]
    if len(sessions) != len(attacks) and not any(r["exit"] in (124, None) for r in results):
        sys.exit(f"audit chain holds {len(sessions)} sessions for {len(attacks)} attacks; refusing to pair")
    trail_path = work / "home/.nockguard/logs/bench.audit.jsonl"  # <agent>.audit.jsonl beside the policy audit path
    lines = trail_path.read_text().splitlines() if trail_path.exists() else []
    trail = [json.loads(line) for line in lines if line.strip()]

    # After a timeout the pairing is unreliable (a killed wrap may leave no session), so no proof is claimed.
    paired = len(sessions) == len(attacks)
    for res, sid in zip(results, sessions if paired else [None] * len(results)):
        atk = res["atk"]
        rows = [dict(r) for r in con.execute("SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))] if paired else []
        end = next((r["detail"] for r in rows if r["event_type"] == "session_end"), "")
        # A wrap that failed to launch has no session_end matching the child's status.
        res["ran"] = end == f"exit_code={res['exit']}"
        res["outcome"] = ("HARNESS-FAULT" if res["exit"] is None else "TIMEOUT" if res["exit"] == 124
                          else "ALLOWED" if res["exit"] == 0 else "BLOCKED")
        res["outcome_ok"] = res["ran"] and (res["exit"] == 0) == (atk["expect"] == "allowed") and not res["planted"]
        if res["control"] is not None and not res["control"]["reached"]:
            res["outcome"], res["outcome_ok"] = "INCONCLUSIVE", False  # unfenced control did not reach
        res["proof"] = nockguard_proof(trail, atk) if atk["evidence"] == "nockguard" else nocklock_proof(rows, atk)
        res["proof_ok"] = bool(res["proof"] and res["proof"]["signed"])
    con.close()

    def tool(name, argv):
        return run(argv, root, env, logs / f"{name}.log", time.monotonic() + 60)

    lock_rc, lock_out = tool("verify-nocklock", [a.nocklock, "verify", "--audit"])
    guard_rc, guard_out = tool("verify-nockguard", [a.nockguard, "verify", "--agent", "bench", "--audit", str(trail_path)])
    versions = {"nocklock": tool("version-nocklock", [a.nocklock, "version"])[1],
                "nockguard": tool("version-nockguard", [a.nockguard, "version"])[1]}

    attack_rows = [r for r in results if r["atk"]["expect"] == "blocked"]
    controls = [r for r in results if r["atk"]["expect"] == "allowed"]
    bar = {
        "every_attack_has_signed_deny_row_naming_rule": all(r["proof_ok"] for r in attack_rows),
        "kernel_floor_attacks_reached_when_unfenced": all(r["control"]["reached"] for r in attack_rows if r["control"]),
        "no_attack_succeeds": all(r["outcome_ok"] for r in attack_rows),
        "no_deny_unsigned": all(r["proof"] is None or r["proof"]["signed"] for r in attack_rows),
        "nocklock_verify_audit_exit0": lock_rc == 0,
        "nockguard_verify_exit0": guard_rc == 0,
        "negative_control_allowed_and_logged": bool(controls) and all(r["outcome_ok"] and r["proof_ok"] for r in controls),
    }
    passed = all(bar.values())

    report = {"passed": passed, "pass_bar": bar, "versions": versions,
              "verify": {"nocklock": {"exit": lock_rc, "output": lock_out},
                         "nockguard": {"exit": guard_rc, "output": guard_out}},
              "attacks": [{
                  "id": r["atk"]["id"], "class": r["atk"]["class"], "tried": r["cmd"],
                  "expected": r["atk"]["expect"], "result": r["outcome"], "exit": r["exit"],
                  "floor_only": bool(r["atk"].get("floor")), "control": r["control"], "outcome_ok": r["outcome_ok"],
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
        verdict = r["result"] + ("" if r["outcome_ok"] else " ✗ UNEXPECTED")
        lines.append("| " + " | ".join([
            f"`{r['id']}`", r["class"], "`" + cell(" ".join(r["tried"].split()))[:110] + "…` (full command in report.json)", ctl, verdict, proof,
            str(p["event_id"]) if p else "-", f"`{cell(p['rule'])}`" if p else "-",
            f"`{p['chain_hash'][:16]}…`" if p and p["chain_hash"] else "-"]) + " |")
    lines += ["", "Attempts marked *blocked by kernel floor* are stopped by the kernel floor (netns default-drop, "
              "seccomp) before any proxy sees them; NockLock writes no per-attempt row for those today, so "
              "the pinned row is the session's signed row proving the floor was armed. Each is also run once "
              "outside `nocklock wrap`; if that control does not reach, the attack is INCONCLUSIVE, not a pass. "
              "Full hashes are in "
              "`report.json`.", "", "## Verification", "",
              f"- `nocklock verify --audit` exit {rep['verify']['nocklock']['exit']}",
              f"- `nockguard verify --agent bench` exit {rep['verify']['nockguard']['exit']}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
