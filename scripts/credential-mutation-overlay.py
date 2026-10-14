#!/usr/bin/env python3
"""Create one test-only Go overlay; never rewrite or build production sources."""

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("mutation", choices=("child-exec-thread", "proxy-groups-thread"))
parser.add_argument("output", type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
if args.mutation == "child-exec-thread":
    source = repo / "internal/fence/network/netns/egress_helper_linux.go"
    text = source.read_text()
    start = text.index("func DropAndExecChild(req Request) error {")
    end = text.index("\nfunc RunHostProxy", start)
    body = text[start:end]
    old = "unix.Exec(req.Argv[0], req.Argv, req.Env)"
    assert body.count(old) == 1, "final child exec changed; review mutation target"
    text = text[:start] + body.replace(old, "credentialExecOnOtherThread(req)") + text[end:]
else:
    source = repo / "internal/fence/network/netns/transparent_linux.go"
    text = source.read_text()
    old = "syscall.Setgroups(nil)"
    assert text.count(old) == 1, "proxy group drop changed; review mutation target"
    text = text.replace(old, "unix.Setgroups(nil)")
args.output.mkdir(parents=True, exist_ok=False)
replacement = (args.output / source.name).resolve()
replacement.write_text(text)
(args.output / "overlay.json").write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
print(args.output / "overlay.json")
