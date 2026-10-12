#!/usr/bin/env python3
"""Bench MCP client: spawn a proxy command and send one tools/call.

usage: mcp_client.py <tool> -- <proxy argv...>
Exit 0 only when the call reached the upstream (the upstream's executed marker
came back); a call the firewall stopped exits 1.
"""
import json
import subprocess
import sys

tool = sys.argv[1]
argv = sys.argv[3:]
p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def rpc(mid, method, params):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())


rpc(1, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "redteam", "version": "0"}})
reply = rpc(2, "tools/call", {"name": tool, "arguments": {}})
p.stdin.close()
p.wait(timeout=10)
executed = "UPSTREAM-EXECUTED" in json.dumps(reply)
print("tools/call %s -> %s" % (tool, "EXECUTED" if executed else "STOPPED"))
sys.exit(0 if executed else 1)
