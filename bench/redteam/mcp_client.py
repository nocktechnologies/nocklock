#!/usr/bin/env python3
"""Bench MCP client: connect to the host-side proxy socket and send one tools/call.

usage: mcp_client.py <tool> <socket path> [timeout seconds]
Exit 0 only when the call reached the upstream (the upstream's executed marker
came back); a call the firewall stopped exits 1. A breach is decided and printed
the moment the reply arrives; trouble while shutting down afterwards cannot
change it. Exit 3 (no reply), 4 (shutdown failed on a stopped call) and 5
(shutdown failed after the call executed: still a breach) are HARNESS-FAULTs,
never a block.
"""
import json
import socket
import sys

tool, path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.settimeout(float(sys.argv[3]) if len(sys.argv) > 3 else 10)
try:
    s.connect(path)
except OSError as e:
    print("HARNESS-FAULT: cannot reach the proxy socket: %r" % e, flush=True)
    sys.exit(3)
f = s.makefile("rw")


def rpc(mid, method, params):
    try:
        f.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) + "\n")
        f.flush()
        line = f.readline()
        if line:
            return json.loads(line)
    except (OSError, ValueError) as e:
        line = "%r" % e
    print("HARNESS-FAULT: no usable reply from the proxy: %s" % (line.strip() or "closed"), flush=True)
    sys.exit(3)


rpc(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "redteam", "version": "0"}})
reply = rpc(2, "tools/call", {"name": tool, "arguments": {}})
executed = "UPSTREAM-EXECUTED" in json.dumps(reply)
print("tools/call %s -> %s" % (tool, "EXECUTED" if executed else "STOPPED"), flush=True)
try:
    s.shutdown(socket.SHUT_WR)
    f.read()  # the broker closes the connection once the proxy has exited
except OSError as e:
    print("HARNESS-FAULT: shutdown did not complete: %r" % e, flush=True)
    sys.exit(5 if executed else 4)
sys.exit(0 if executed else 1)
