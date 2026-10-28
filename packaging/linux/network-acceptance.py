#!/usr/bin/env python3
"""Installed-release network proof; root on disposable GitHub-hosted VMs only.

The Linux observer appends counters without verdicts after the existing output
rules. The shipped default-drop policy remains responsible for denial.
"""
import argparse
import errno
import http.server
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ALLOWED = "nocklock-allowed.test"
BLOCKED = "nocklock-blocked.test"
PORT = 19191


def run(*args, **kwargs):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=90, **kwargs)


def wait_for(test, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = test()
        if value:
            return value
        time.sleep(.1)
    raise RuntimeError("timed out waiting for acceptance synchronization")


def probe(address, fenced, direct_only=False):
    """Run as the ordinary account, both outside and inside the real CLI."""
    linux = platform.system() == "Linux"
    if fenced:
        Path("ready").touch()
        wait_for(lambda: Path("go").exists())
    results = {}
    for scheme in (() if direct_only else ("http", "https")):
        for host in (ALLOWED, BLOCKED):
            key = scheme + "-" + host
            command = ["/usr/bin/curl", "-ksS", "--max-time", "8", "--fail"]
            if not fenced or linux:
                command += ["--noproxy", "*"]
            if fenced and linux:
                # Production netns has no default route. Its DNS stub supplies
                # loopback; the transparent proxy resolves Host/SNI on the host.
                command += ["--resolve", host + ":" + ("80" if scheme == "http" else "443") + ":127.0.0.1"]
            result = run(*command, scheme + "://" + host + "/" + key)
            expected = not fenced or host == ALLOWED
            assert (result.returncode == 0 and result.stdout == "REACHED") == expected, (key, result)
            results[key] = "allowed" if expected else "denied"
    if fenced and linux:
        address = Path("direct-address").read_text()
    for kind, socktype in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
        with socket.socket(socket.AF_INET, socktype) as client:
            client.settimeout(2)
            try:
                client.connect((address, PORT))
                client.sendall(b"control")
                assert client.recv(64) == b"REACHED"
            except OSError as exc:
                assert fenced, (kind, exc)
                if not linux:
                    assert exc.errno in (errno.EPERM, errno.EACCES), (kind, exc)
                results[kind] = "denied"
            else:
                assert not fenced, kind + " escaped"
                results[kind] = "reachable"
    print(json.dumps(results), flush=True)
    if fenced:
        Path("done").touch()
        wait_for(lambda: Path("finish").exists())


def accept(args):
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("require root on a disposable GitHub-hosted VM")
    linux = platform.system() == "Linux"
    account = pwd.getpwnam(args.user)
    assert account.pw_uid != 0
    os.umask(0o022)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True)
    fixture = Path(tempfile.mkdtemp(prefix="network-accept-", dir=account.pw_dir))
    project = fixture / "project"
    project.mkdir()
    (project / ".nock").mkdir()
    state = fixture / "state"
    state.mkdir(mode=0o700)
    address = "127.0.0.1"
    bind = "0.0.0.0" if linux else address
    hosts = Path("/etc/hosts")
    original_hosts = hosts.read_bytes()
    hits = []
    servers = []
    process = None
    namespace = None
    helper = Path("/usr/libexec/nocklock-egress-helper")
    saved_helper = helper.with_name(helper.name + ".acceptance-disabled")
    env = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", HOME=account.pw_dir,
               USER=args.user, LOGNAME=args.user, XDG_STATE_HOME=str(state), LC_ALL="C")
    prefix = ["/usr/bin/sudo", "-u", args.user, "env", "-i"] + [k + "=" + v for k, v in env.items()]
    def user(*command):
        result = run(*prefix, *command, cwd=project)
        assert result.returncode == 0, result.stdout
        return result.stdout
    class HTTP(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"REACHED")
        def log_message(self, *unused):
            pass
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            hits.append("tcp")
            self.request.recv(64)
            self.request.sendall(b"REACHED")
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            hits.append("udp")
            self.request[1].sendto(b"REACHED", self.client_address)
    try:
        hosts.write_bytes(original_hosts + ("\n" + address + " " + ALLOWED + " " + BLOCKED + "\n").encode())
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=" + ALLOWED, "-keyout", str(fixture / "key.pem"),
            "-out", str(fixture / "cert.pem"), check=True)
        for port in (80, 443):
            server = http.server.ThreadingHTTPServer((bind, port), HTTP)
            if port == 443:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(fixture / "cert.pem"), str(fixture / "key.pem"))
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(server)
        servers += [socketserver.ThreadingTCPServer((bind, PORT), TCP),
                    socketserver.ThreadingUDPServer((bind, PORT), UDP)]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        paths = ["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/", "/dev/", "/proc/"] if linux else ["/usr/", "/bin/", "/sbin/", "/System/", "/Library/", "/private/etc/", "/dev/"]
        (project / ".nock/config.toml").write_text(
            '[project]\nname = "release-network-acceptance"\n[filesystem]\nroot = ' + json.dumps(str(project)) +
            '\nmode = "read-write"\nlinux_enforcement = "required"\nallow = ' + json.dumps(paths) +
            '\n[network]\nallow = ["' + ALLOWED + '"]\nallow_private_ranges = true\n[syscall]\nenforcement = "' + ("required" if linux else "off") + '"\n')
        shutil.copyfile(__file__, project / "probe.py")
        for path in [fixture, *fixture.rglob("*")]:
            os.chown(path, account.pw_uid, account.pw_gid)
        (evidence / "version.txt").write_text(user(args.binary, "version"))
        (evidence / "unfenced.json").write_text(user("/usr/bin/python3", "-I", "probe.py", "probe", address, "unfenced"))
        assert len(hits) == 6, hits
        hits.clear()
        flags = ["--net-fence=netns"] if linux else []
        command = [*prefix, args.binary, "wrap", *flags, "--require-enforced-egress", "--",
                   "/usr/bin/python3", "-I", "probe.py", "probe", address, "fenced"]
        with (evidence / "wrap.txt").open("w") as output:
            process = subprocess.Popen(command, cwd=project, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            wait_for(lambda: (project / "ready").exists() or process.poll() is not None)
            assert process.poll() is None, (evidence / "wrap.txt").read_text()
            if linux:
                namespaces = run("ip", "netns", "list", check=True).stdout.splitlines()
                assert len(namespaces) == 1, namespaces
                namespace = namespaces[0].split()[0]
                original = run("ip", "netns", "exec", namespace, "nft", "-j", "list", "ruleset", check=True).stdout
                (evidence / "rules-original.json").write_text(original)
                assert any(x.get("chain", {}).get("name") == "output" and x["chain"].get("policy") == "drop" for x in json.loads(original)["nftables"])
                interfaces = json.loads(run("ip", "-j", "-n", namespace, "addr", "show", check=True).stdout)
                child_ips = [a["local"] for i in interfaces for a in i["addr_info"]
                             if a["family"] == "inet" and a["local"].startswith("169.254.")]
                assert len(child_ips) == 1, interfaces
                direct_address = str(ipaddress.ip_address(child_ips[0]) - 1)
                (project / "direct-address").write_text(direct_address)
                # Same live destination and ports as the fenced direct probes.
                (evidence / "direct-unfenced.json").write_text(user(
                    "/usr/bin/python3", "-I", "probe.py", "control", direct_address))
                assert sorted(hits) == ["tcp", "udp"], hits
                hits.clear()
                for protocol in ("tcp", "udp"):
                    run("ip", "netns", "exec", namespace, "nft", "add", "rule", "inet", "nocklock", "output",
                        "ip", "daddr", direct_address, protocol, "dport", str(PORT), "counter", "comment", '"acceptance-' + protocol + '"', check=True)
            (project / "go").touch()
            wait_for(lambda: (project / "done").exists() or process.poll() is not None, 50)
            assert process.poll() is None, (evidence / "wrap.txt").read_text()
            assert sorted(hits) == ["/http-" + ALLOWED, "/https-" + ALLOWED], hits
            counters = {}
            if linux:
                observed = run("ip", "netns", "exec", namespace, "nft", "-j", "list", "ruleset", check=True).stdout
                (evidence / "rules-observed.json").write_text(observed)
                for entry in json.loads(observed)["nftables"]:
                    rule = entry.get("rule", {})
                    if rule.get("comment", "").startswith("acceptance-"):
                        counters[rule["comment"]] = sum(e.get("counter", {}).get("packets", 0) for e in rule["expr"])
                assert set(counters) == {"acceptance-tcp", "acceptance-udp"} and min(counters.values()) > 0, counters
            (project / "finish").touch()
            assert process.wait(timeout=30) == 0, (evidence / "wrap.txt").read_text()
        pub = user(args.binary, "verify", "--export-pubkey").strip()
        (evidence / "public-key.txt").write_text(pub)
        audit = user(args.binary, "verify", "--audit", "--ed25519-pub", pub)
        assert "AUDIT: AUTHENTIC" in audit
        (evidence / "audit.txt").write_text(audit)
        events = user(args.binary, "log", "--json")
        (evidence / "events.json").write_text(events)
        rows = json.loads(events)
        level = "KERNEL" if linux else "SEATBELT"
        assert any(e["EventType"] == "session_start" and e["egress_level"] == level for e in rows)
        for host, event in ((ALLOWED, "network_passed"), (BLOCKED, "network_blocked")):
            for port, method in ((80, "GET"), (443, "CONNECT")):
                marker = host + ":" + str(port) if linux else "host=" + host
                assert any(e["EventType"] == event and marker in e.get("Detail", "")
                           and (linux or "method=" + method in e.get("Detail", "")) for e in rows), (host, port, rows)
        if linux:
            helper.rename(saved_helper)
            failed = run(*prefix, args.binary, "wrap", "--net-fence=netns", "--", "/usr/bin/touch", "fallback-ran", cwd=project)
            (evidence / "helper-failure.txt").write_text(failed.stdout)
            assert failed.returncode == 2 and "helper" in failed.stdout and not (project / "fallback-ran").exists(), failed
            saved_helper.rename(helper)
        (evidence / "receipt.json").write_text(json.dumps(dict(
            kind="installed-release-network-acceptance", binary=args.binary, platform=platform.platform(),
            egress_level=level, audit="AUTHENTIC", unfenced_controls=6,
            allowed_http_https=True, denied_http_https=True, direct_tcp_udp=True,
            drop_counters=counters, helper_failure_no_fallback=linux), indent=2))
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
        if saved_helper.exists():
            saved_helper.rename(helper)
        hosts.write_bytes(original_hosts)
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "control":
        probe(sys.argv[2], False, direct_only=True)
    elif len(sys.argv) > 1 and sys.argv[1] == "probe":
        probe(sys.argv[2], sys.argv[3] == "fenced")
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("user")
        parser.add_argument("evidence", type=Path)
        parser.add_argument("--binary", default="/usr/local/bin/nocklock")
        accept(parser.parse_args())
