#!/usr/bin/env python3
"""Bench MCP client: run on the host, spawn `nockguard proxy` and send one tools/call.

usage: mcp_client.py <tool> <shutdown timeout seconds> -- <proxy argv...>
Exit 0 only when the call reached the upstream (the upstream's executed marker
came back); a call the firewall stopped exits 1. A breach is decided and printed
the moment the reply arrives; trouble while shutting down afterwards (a hang or a nonzero proxy exit) cannot
change it. Exit 3 (no reply), 4 (shutdown failed on a stopped call) and 5
(shutdown failed after the call executed: still a breach) are HARNESS-FAULTs,
never a block. Blocking reads are bounded by the caller's single deadline
(redteam.run() kills the whole process group), so this client has no threads.
"""
import json
import subprocess
import sys

tool, timeout = sys.argv[1], float(sys.argv[2])
argv = sys.argv[sys.argv.index("--") + 1:]
try:
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
except OSError as e:
    print("HARNESS-FAULT: cannot start the proxy: %r" % e, flush=True)
    sys.exit(3)


def rpc(mid, method, params):
    try:
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        if line:
            return json.loads(line)
    except (OSError, ValueError) as e:
        line = "%r" % e
    print("HARNESS-FAULT: no usable reply from the proxy: %s" % (line.strip() or "closed"), flush=True)
    p.kill()
    p.wait()
    sys.exit(3)


rpc(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "redteam", "version": "0"}})
reply = rpc(2, "tools/call", {"name": tool, "arguments": {}})
executed = "UPSTREAM-EXECUTED" in json.dumps(reply)
print("tools/call %s -> %s" % (tool, "EXECUTED" if executed else "STOPPED"), flush=True)
try:
    p.stdin.close()  # EOF lets the proxy write its last signed trail entry and exit
    if p.wait(timeout=timeout) != 0:
        raise OSError("proxy exited %d" % p.returncode)
except (OSError, subprocess.TimeoutExpired) as e:
    p.kill()
    p.wait()
    print("HARNESS-FAULT: proxy shutdown did not complete: %r" % e, flush=True)
    sys.exit(5 if executed else 4)
sys.exit(0 if executed else 1)
