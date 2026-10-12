#!/usr/bin/env python3
"""Red-team bench driver (N11623). Started by run.sh; see attacks.toml.

Runs each scripted attack inside its own `nocklock wrap` session, pairs the
attempt with the signed row that proves the verdict, runs `nocklock verify
--audit` and `nockguard verify`, and writes REPORT.md + report.json.
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tomllib
from pathlib import Path

CANARY_ENV = {"BENCH_SECRET_TOKEN": "bench-canary-not-a-real-secret"}


def run(argv, cwd, env, timeout=120):
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return p.returncode, (p.stdout + p.stderr).strip()


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

    def sub(text):
        for k, v in subst.items():
            text = text.replace(k, v)
        return text

    results = []
    for atk in attacks:
        cmd = sub(atk["cmd"])
        rc, output = run([a.nocklock, "wrap", "--net-fence=netns", "--", "/bin/sh", "-c", cmd], root, env)
        planted = bool(atk.get("absent")) and Path(sub(atk["absent"])).exists()
        results.append({"atk": atk, "cmd": cmd, "exit": rc, "output": output[-400:], "planted": planted})
        print(f"[{atk['id']}] exit={rc}", flush=True)
        if os.environ.get("REDTEAM_VERBOSE"):
            print(output, flush=True)

    # Pair attempts with their signed rows. Sessions are strictly sequential, so
    # the Nth session_start in the chain is the Nth attack; the count is asserted.
    con = sqlite3.connect(f"file:{find_audit_db(work / 'state')}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    sessions = [r["session_id"] for r in con.execute(
        "SELECT session_id FROM events WHERE event_type='session_start' ORDER BY id")]
    if len(sessions) != len(attacks):
        sys.exit(f"audit chain holds {len(sessions)} sessions for {len(attacks)} attacks; refusing to pair")
    trail_path = work / "home/.nockguard/logs/bench.audit.jsonl"  # <agent>.audit.jsonl beside the policy audit path
    lines = trail_path.read_text().splitlines() if trail_path.exists() else []
    trail = [json.loads(line) for line in lines if line.strip()]

    for res, sid in zip(results, sessions):
        atk = res["atk"]
        rows = [dict(r) for r in con.execute("SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))]
        end = next((r["detail"] for r in rows if r["event_type"] == "session_end"), "")
        # A wrap that failed to launch has no session_end matching the child's status.
        res["ran"] = end == f"exit_code={res['exit']}"
        res["outcome"] = "ALLOWED" if res["exit"] == 0 else "BLOCKED"
        res["outcome_ok"] = res["ran"] and (res["exit"] == 0) == (atk["expect"] == "allowed") and not res["planted"]
        res["proof"] = nockguard_proof(trail, atk) if atk["evidence"] == "nockguard" else nocklock_proof(rows, atk)
        res["proof_ok"] = bool(res["proof"] and res["proof"]["signed"])
    con.close()

    lock_rc, lock_out = run([a.nocklock, "verify", "--audit"], root, env)
    guard_rc, guard_out = run([a.nockguard, "verify", "--agent", "bench", "--audit", str(trail_path)], root, env)
    versions = {"nocklock": run([a.nocklock, "version"], root, env)[1],
                "nockguard": run([a.nockguard, "version"], root, env)[1]}

    attack_rows = [r for r in results if r["atk"]["expect"] == "blocked"]
    controls = [r for r in results if r["atk"]["expect"] == "allowed"]
    bar = {
        "every_attack_has_signed_deny_row_naming_rule": all(r["proof_ok"] for r in attack_rows),
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
                  "floor_only": bool(r["atk"].get("floor")), "outcome_ok": r["outcome_ok"],
                  "proof": r["proof"]} for r in results]}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "REPORT.md").write_text(render_md(report))
    print(("PASS" if passed else "FAIL") + " - see " + str(out / "REPORT.md"))
    sys.exit(0 if passed else 1)


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_md(rep):
    lines = ["# NockLock + NockGuard red-team bench", "",
             f"**Verdict: {'PASS' if rep['passed'] else 'FAIL'}**", "",
             f"nocklock `{cell(rep['versions']['nocklock'])}` / nockguard `{cell(rep['versions']['nockguard'])}`", "",
             "## Pass bar", ""]
    lines += [f"- [{'x' if ok else ' '}] {k.replace('_', ' ')}" for k, ok in rep["pass_bar"].items()]
    lines += ["", "## Attempts", "",
              "| attack | class | tried | result | proof | event id | rule | chain hash (NockGuard: entry signature) |",
              "|---|---|---|---|---|---|---|---|"]
    for r in rep["attacks"]:
        p = r["proof"]
        proof = "MISSING" if not p else (f"{p['source']} {'signed' if p['signed'] else 'UNSIGNED'}"
                                         + (" (fence-state only)" if r["floor_only"] else ""))
        verdict = r["result"] + ("" if r["outcome_ok"] else " ✗ UNEXPECTED")
        lines.append("| " + " | ".join([
            f"`{r['id']}`", r["class"], "`" + cell(" ".join(r["tried"].split()))[:110] + "…` (full command in report.json)", verdict, proof,
            str(p["event_id"]) if p else "-", f"`{cell(p['rule'])}`" if p else "-",
            f"`{p['chain_hash'][:16]}…`" if p and p["chain_hash"] else "-"]) + " |")
    lines += ["", "Attempts marked *fence-state only* are stopped by the kernel floor (netns default-drop, "
              "seccomp) before any proxy sees them; NockLock writes no per-attempt row for those today, so "
              "the pinned row is the session's signed row proving the floor was armed. Full hashes are in "
              "`report.json`.", "", "## Verification", "",
              f"- `nocklock verify --audit` exit {rep['verify']['nocklock']['exit']}",
              f"- `nockguard verify --agent bench` exit {rep['verify']['nockguard']['exit']}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
