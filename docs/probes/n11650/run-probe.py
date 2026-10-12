#!/usr/bin/env python3
"""Probe AF_UNIX pathname and abstract reachability in Linux CONFINED mode."""

import datetime
import os
import pathlib
import platform
import socket
import subprocess
import sys
import tempfile
import threading


def main() -> int:
    if sys.platform != "linux":
        print("probe requires Linux", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("probe must run as a non-root user", file=sys.stderr)
        return 2

    repo = pathlib.Path(__file__).resolve().parents[3]
    work = pathlib.Path(tempfile.mkdtemp(prefix="nocklock-n11650-", dir="/tmp"))
    project = work / "project"
    project.mkdir(mode=0o700)
    binary = work / "nocklock"
    pathname = work / "outside.sock"
    abstract = "\0nocklock-n11650-" + work.name.rsplit("-", 1)[-1]
    accepted: list[tuple[str, str]] = []
    listeners: list[socket.socket] = []
    threads: list[threading.Thread] = []

    def accept_one(label: str, listener: socket.socket) -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                data = conn.recv(64)
            accepted.append((label, data.decode("ascii", "replace")))
        except TimeoutError:
            pass

    print("date_utc=" + datetime.datetime.now(datetime.timezone.utc).isoformat())
    print("repo_head=" + subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"], cwd=repo, text=True
    ).strip())
    print("kernel=" + platform.release())
    print("uid=" + str(os.geteuid()))
    print("probe_dir=" + str(work))

    build = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/nocklock"],
        cwd=repo,
        text=True,
        capture_output=True,
    )
    print("build_exit=" + str(build.returncode))
    if build.stdout.strip():
        print("build_stdout=" + build.stdout.strip())
    if build.stderr.strip():
        print("build_stderr=" + build.stderr.strip())
    if build.returncode != 0:
        return build.returncode

    for label, address in (("path", str(pathname)), ("abstract", abstract)):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(address)
        listener.listen(4)
        listener.settimeout(8)
        listeners.append(listener)
        thread = threading.Thread(target=accept_one, args=(label, listener), daemon=True)
        thread.start()
        threads.append(thread)

    init = subprocess.run([str(binary), "init"], cwd=project, text=True, capture_output=True)
    print("init_exit=" + str(init.returncode))
    if init.stdout.strip():
        print("init_stdout=" + init.stdout.strip())
    if init.stderr.strip():
        print("init_stderr=" + init.stderr.strip())
    if init.returncode != 0:
        return init.returncode

    child = f'''import socket
for name, address in [('path', {str(pathname)!r}), ('abstract', {abstract!r})]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(address)
        s.sendall(b'probe')
        print(name + '=CONNECTED')
    except OSError as e:
        print(name + '=DENIED errno=' + str(e.errno) + ' ' + e.strerror)
    finally:
        s.close()
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print('inet_datagram=UNEXPECTED_ALLOWED')
except OSError as e:
    print('inet_datagram=DENIED errno=' + str(e.errno) + ' ' + e.strerror)
'''
    run = subprocess.run(
        [str(binary), "wrap", "--", "/usr/bin/python3", "-c", child],
        cwd=project,
        text=True,
        capture_output=True,
        timeout=30,
    )
    print("path_socket=" + str(pathname))
    print("abstract_socket=@" + abstract[1:])
    print("wrap_exit=" + str(run.returncode))
    print("child_stdout_begin")
    print(run.stdout.rstrip())
    print("child_stdout_end")
    print("wrap_stderr_begin")
    print(run.stderr.rstrip())
    print("wrap_stderr_end")

    for thread in threads:
        thread.join(timeout=9)
    for listener in listeners:
        listener.close()
    print("server_accepts=" + repr(sorted(accepted)))
    print("probe_artifacts_retained=yes")
    if run.returncode != 0:
        return run.returncode
    if "CONFINED (syscall fence; proxy bridge only)" not in run.stderr:
        print("probe did not reach CONFINED egress", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
