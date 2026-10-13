#!/usr/bin/env python3
"""Minimal stdio MCP server used as the bench's upstream behind `nockguard proxy`.

Answers initialize, tools/list and tools/call. Every tools/call that reaches it
returns the text "UPSTREAM-EXECUTED:<tool>", so a client can tell a call the
firewall let through from one it stopped.
"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        continue
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "bench-upstream", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": []}
    elif method == "tools/call":
        tool = msg["params"]["name"]
        result = {"content": [{"type": "text", "text": "UPSTREAM-EXECUTED:" + tool}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}), flush=True)
