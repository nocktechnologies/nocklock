#!/usr/bin/env python3
"""Exercise NockLock against real NCC handlers on private loopback + SQLite.

Set NCC_CHECKOUT and NCC_PYTHON explicitly. No resident settings, credentials,
database, root privilege, external service, or mock anchor store is used.
"""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


SETTINGS = '''from config.settings.ci import *
import os
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3",
    "NAME": os.environ["NOCKCC_LOCAL_SQLITE_PATH"], "OPTIONS": {"timeout": 20}}}
ROOT_URLCONF = "ncc_acceptance_urls"
ALLOWED_HOSTS = ["127.0.0.1"]
MIDDLEWARE = []
TEMPLATES = []
DEBUG = False
NO_EXTERNAL_SERVICES = True
MORNING_NOTE_ENABLED = False
CELERY_TASK_ALWAYS_EAGER = False
CELERY_BROKER_URL = "memory://"
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
LOGGING = {"version": 1, "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "WARNING"}}
'''
URLS = '''from django.urls import include, path
urlpatterns = [path("api/nocklock/", include("nocklock.urls"))]
'''


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def write_json(path, value):
    """Publish complete control/evidence files; never expose a partial JSON read."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def serve(scratch):
    """Internal subprocess entry: actual Django WSGI, migrations and storage."""
    if (os.geteuid() == 0 or os.environ.get("NOCKCC_SKIP_DOTENV") != "1"
            or os.environ.get("DJANGO_SETTINGS_MODULE") != "ncc_acceptance_settings"
            or not (scratch / "harness-private-directory").is_file()):
        raise RuntimeError("refusing server without non-root isolated harness settings")
    import django
    django.setup()
    from django.conf import settings
    from django.core.management import call_command
    from django.core.wsgi import get_wsgi_application
    expected = scratch / "ncc.sqlite3"
    if (settings.DATABASES["default"]["ENGINE"] != "django.db.backends.sqlite3"
            or Path(settings.DATABASES["default"]["NAME"]).resolve() != expected
            or expected.exists()):
        raise RuntimeError("refusing an existing or non-harness database")
    with (scratch / "migration.log").open("w") as output:
        call_command("migrate", interactive=False, verbosity=1, stdout=output)
    django_app = get_wsgi_application()
    request_lock = threading.Lock()

    def application(environ, start_response):
        # Transport fault injection surrounds the real application. A swapped
        # route still executes the actual target handler; a held response is
        # held only AFTER the real registration transaction has committed.
        fault = json.loads((scratch / "fault.json").read_text())
        original = environ["PATH_INFO"]
        if original == fault.get("swap_from"):
            environ["PATH_INFO"] = fault["swap_to"]
        if fault.get("v1_only") and original.startswith("/api/nocklock/anchors/v2/"):
            environ["PATH_INFO"] = "/unmounted-v2-route/"
        if fault.get("reject_registration") and original.endswith("/register/"):
            body = json.loads(environ["wsgi.input"].read(int(environ["CONTENT_LENGTH"])))
            body["anchor"]["sig"] = "A" * 86 + "=="
            changed = json.dumps(body).encode()
            environ["wsgi.input"] = io.BytesIO(changed)
            environ["CONTENT_LENGTH"] = str(len(changed))
        response = {}

        def capture(status, headers, exc_info=None):
            response.update(status=status, headers=headers)

        iterable = django_app(environ, capture)
        try:
            body = b"".join(iterable)
        finally:
            if hasattr(iterable, "close"):
                iterable.close()
        event = dict(method=environ["REQUEST_METHOD"], path=original,
                     served_path=environ["PATH_INFO"], status=int(response["status"].split()[0]))
        with request_lock, (scratch / "requests.jsonl").open("a") as log:
            log.write(json.dumps(event) + "\n")
        if (fault.get("hold_registration") and original.endswith(("/register/", "/migrate/"))
                and event["status"] in (200, 201)):
            write_json(scratch / "registration-committed.json", event)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if not json.loads((scratch / "fault.json").read_text()).get("hold_registration"):
                    break
                time.sleep(0.05)
        start_response(response["status"], response["headers"])
        return [body]

    class Server(socketserver.ThreadingMixIn, WSGIServer):
        daemon_threads = True

    class QuietHandler(WSGIRequestHandler):
        def log_message(self, fmt, *args):
            pass  # Structured method/path/status receipt above contains no token.

    server = make_server("127.0.0.1", 0, application, server_class=Server, handler_class=QuietHandler)
    write_json(scratch / "ready.json", {"url": "http://127.0.0.1:" + str(server.server_port),
                                       "database": str(expected), "django": django.get_version()})
    server.serve_forever()


class Harness:
    def __init__(self, args, scratch):
        self.args, self.scratch = args, scratch
        self.rows, self.commands = [], []
        self.token = secrets.token_urlsafe(32)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.env = {"PATH": os.defpath, "HOME": str(scratch / "home"), "LC_ALL": "C",
                    "PYTHONDONTWRITEBYTECODE": "1", "NOCKCC_SKIP_DOTENV": "1",
                    "DJANGO_SETTINGS_MODULE": "ncc_acceptance_settings",
                    "PYTHONPATH": str(scratch) + os.pathsep + str(args.ncc_checkout),
                    "NOCKCC_LOCAL_SQLITE_PATH": str(scratch / "ncc.sqlite3"),
                    "DATABASE_URL": "sqlite:///" + str(scratch / "ncc.sqlite3"),
                    "SECRET_KEY": secrets.token_urlsafe(48), "NOCKCC_API_KEY": self.token,
                    "TEST_WEBHOOK_SECRET": secrets.token_urlsafe(32),
                    "GITHUB_WEBHOOK_SECRET": secrets.token_urlsafe(32)}
        # Valid ephemeral Fernet keys, generated locally without importing the
        # operator's Django config or reading any configured vault credentials.
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        self.env.update(FERNET_KEYS=key, TEST_FERNET_KEY=key, MARA_PRIVATE_KEY=key,
                        MIRA_PRIVATE_KEY=key, KEVIN_MASTER_PRIVATE_KEY=key, VAULT_HANDOFF_MASTER_KEY=key)
        for name in ("home", "config", "state"):
            (scratch / name).mkdir(mode=0o700)
        (scratch / "harness-private-directory").touch(mode=0o600)
        (scratch / "ncc_acceptance_settings.py").write_text(SETTINGS)
        (scratch / "ncc_acceptance_urls.py").write_text(URLS)
        write_json(scratch / "fault.json", {})
        self.server_log = (scratch / "server.log").open("w")
        self.server = subprocess.Popen([str(args.ncc_python), str(Path(__file__).resolve()),
                                        "--serve", str(scratch)], cwd=scratch, env=self.env,
                                       stdout=self.server_log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        try:
            self.wait_file(scratch / "ready.json", timeout=120)
        except Exception:
            self.close()
            (args.out / "bootstrap-error.log").write_text(
                (scratch / "server.log").read_text().replace(self.token, "[temporary token redacted]"))
            raise
        self.ready = json.loads((scratch / "ready.json").read_text())
        self.url = self.ready["url"]
        self.cli_env = {"PATH": os.defpath, "HOME": str(scratch / "home"),
                        "XDG_CONFIG_HOME": str(scratch / "config"),
                        "XDG_STATE_HOME": str(scratch / "state"),
                        "NOCKLOCK_ANCHOR_URL": self.url, "NOCKLOCK_ANCHOR_TOKEN": self.token}

    def command(self, project, *args, fails=False, remote=True):
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]))
        if not remote:
            env.pop("NOCKLOCK_ANCHOR_URL", None)
            env.pop("NOCKLOCK_ANCHOR_TOKEN", None)
        result = subprocess.run([str(self.args.nocklock_bin), *args], cwd=project["path"],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=45)
        output = result.stdout.replace(self.token, "[temporary token redacted]")
        self.commands.append(dict(project=project["path"].name, args=args,
                                  exit=result.returncode, output=output))
        require((result.returncode != 0) == fails, (args, result.returncode, output))
        return output

    def project(self, name, count, group="shared"):
        project = self.scratch / name
        project.mkdir(mode=0o700)
        (project / ".nock").mkdir(mode=0o700)
        (project / ".nock/config.toml").write_text('''[project]
name = "anchor-protocol-acceptance"
[filesystem]
root = ""
linux_enforcement = "off"
[network]
allow_all = true
[syscall]
enforcement = "off"
[logging]
db = "events.db"
''')
        key_root = self.scratch / ("key-" + group)
        key_root.mkdir(mode=0o700, exist_ok=True)
        state = self.state_path(project)
        state.mkdir(mode=0o700, parents=True)
        info = dict(path=project, state=state, db=state / "events.db", key_root=key_root)
        self.append_rows(info, count)
        return info

    def state_path(self, project):
        project_hash = hashlib.sha256(str(project.resolve()).encode()).hexdigest()[:16]
        return self.scratch / "state/nocklock" / project_hash

    def append_rows(self, project, count):
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]),
                   NOCKLOCK_NCC_TEST_ROOT=str(self.scratch))
        subprocess.run([str(self.fixture), str(project["db"]), str(project["path"]), str(count)],
                       env=env, check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def identity(self, project):
        return json.loads((project["state"] / "chain-identity.json").read_text())

    def emit(self, project):
        path = self.scratch / (project["path"].name + "-anchor.json")
        self.command(project, "anchor", "emit", "--out", str(path), remote=False)
        return json.loads(path.read_text()), path

    def public_key(self, project):
        exported = self.command(project, "verify", "--export-pubkey", remote=False).strip()
        algorithm, key = exported.split()
        require(algorithm == "ed25519" and len(base64.b64decode(key, validate=True)) == 32,
                "unexpected public-key export format")
        return key

    def latest_path(self, anchor):
        return "/api/nocklock/anchors/v2/" + anchor["agent_id"] + "/" + anchor["chain_id"] + "/latest/"

    def latest(self, anchor):
        status, result = self.http(self.latest_path(anchor))
        require(status == 200, (status, result))
        return result

    @staticmethod
    def database_fingerprint(path):
        with sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True) as db:
            return hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()

    @staticmethod
    def snapshot(source, destination):
        with sqlite3.connect(source) as original, sqlite3.connect(destination) as backup:
            original.backup(backup)

    def prune_refused(self, project):
        before = self.database_fingerprint(project["db"])
        store_before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        requests_before = (self.scratch / "requests.jsonl").read_bytes()
        output = self.command(project, "log", "--prune", "0s", fails=True)
        require("prun" in output.lower() and ("pin" in output.lower() or "identity" in output.lower()), output)
        require(self.database_fingerprint(project["db"]) == before, "prune refusal changed the DB")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == store_before, "prune refusal changed remote state")
        require((self.scratch / "requests.jsonl").read_bytes() == requests_before, "prune consulted the remote store")

    def cli_acceptance(self):
        repo = Path(__file__).resolve().parents[1]
        self.fixture = self.scratch / "anchor-fixture"
        go = shutil.which("go")
        require(go, "Go is required to build the signed-row fixture")
        # This compiles the real logging package. The fixture generates rows;
        # every anchor transition/verdict below goes through the actual CLI.
        subprocess.run([go, "build", "-o", str(self.fixture), "./scripts/testdata/anchor-v2-fixture"],
                       cwd=repo, check=True, timeout=120)
        self.case("two-projects-same-key-independent-pins", self.two_projects)
        self.case("swapped-pair-before-count-and-server-url-binding", self.swapped_pair)
        self.case("rollback-rejected-pin-and-other-project-unchanged", self.rollback)
        self.case("missing-local-identity-does-not-mint", self.missing_identity)
        self.case("missing-pin-and-old-store-never-downgrade", self.missing_remote)
        self.case("legacy-wrong-owner-refused-correct-migration-verifies", self.legacy_migration)
        self.case("committed-response-loss-crash-pending-retry-prune", self.crash_retry)
        self.case("registration-validation-error-stays-pending", self.rejected_registration)
        self.case("offline-project-and-state-move-preserves-pair", self.moved_identity)
        self.case("unenrolled-legacy-prune-positive-control", self.legacy_prune)

    def two_projects(self):
        self.a, self.b = self.project("project-a", 7), self.project("project-b", 3)
        for project in (self.a, self.b):
            self.command(project, "anchor", "enroll")
            self.command(project, "verify", "--against-remote-anchor")
        self.anchor_a, _ = self.emit(self.a)
        self.anchor_b, _ = self.emit(self.b)
        a, b = self.anchor_a, self.anchor_b
        require(a["agent_id"] == b["agent_id"] and a["chain_id"] != b["chain_id"], "pair isolation failed")
        require(a["row_count"] > b["row_count"], "different-count control failed")
        for candidate in (a, b):
            stored = self.latest(candidate)
            require(all(stored[field] == candidate[field] for field in
                        ("agent_id", "chain_id", "head_hash", "row_count", "legacy_anchor_digest")),
                    "store latest did not preserve each pair")
        self.anchor_a, self.anchor_b = self.latest(a), self.latest(b)
        with sqlite3.connect(self.scratch / "ncc.sqlite3") as db:
            pairs = db.execute("SELECT s.chain_id FROM nocklock_anchorstream s JOIN nocklock_anchoragent a ON s.agent_id=a.id WHERE a.agent_id=?",
                               (a["agent_id"],)).fetchall()
        require({row[0] for row in pairs} == {a["chain_id"], b["chain_id"]}, "actual database pair keys differ")
        self.a_early = self.scratch / "a-early.sqlite3"
        self.snapshot(self.a["db"], self.a_early)
        return dict(agent_id=a["agent_id"], chains=[a["chain_id"], b["chain_id"]], counts=[a["row_count"], b["row_count"]])

    def swapped_pair(self):
        self.append_rows(self.b, 10)
        self.anchor_b, path = self.emit(self.b)
        self.command(self.b, "anchor", "push", "--file", str(path))
        require(self.anchor_b["row_count"] > self.anchor_a["row_count"], "swap count control missing")
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        write_json(self.scratch / "fault.json", dict(swap_from=self.latest_path(self.anchor_a), swap_to=self.latest_path(self.anchor_b)))
        try:
            output = self.command(self.a, "verify", "--against-remote-anchor", fails=True)
            require("TRUNCATION" not in output and ("identity" in output.lower() or "chain" in output.lower()), output)
        finally:
            write_json(self.scratch / "fault.json", {})
        pair_path = self.latest_path(self.anchor_a).removesuffix("latest/")
        status, response = self.http(pair_path, dict(anchor=self.anchor_b, pubkey=self.public_key(self.b), expected_previous="0" * 64))
        require(status == 400 and "URL pair" in response.get("message", ""), (status, response))
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "swapped pair changed store")
        self.command(self.b, "verify", "--against-remote-anchor")
        return "Real B latest served for A; valid higher-count foreign identity refused before truncation. URL/body mismatch rejected by actual NCC validator."

    def rollback(self):
        self.append_rows(self.a, 4)
        advanced, path = self.emit(self.a)
        self.command(self.a, "anchor", "push", "--file", str(path))
        status, remote, headers = self.http(self.latest_path(advanced), include_headers=True)
        require(status == 200, remote)
        other = self.latest(self.anchor_b)
        current = self.scratch / "a-current.sqlite3"
        self.snapshot(self.a["db"], current)
        self.snapshot(self.a_early, self.a["db"])
        try:
            output = self.command(self.a, "verify", "--against-remote-anchor", fails=True)
            require("TRUNCATION" in output, output)
            old_anchor, old_path = self.emit(self.a)
            self.command(self.a, "anchor", "push", "--file", str(old_path), fails=True)
            # Separately hit the real store's monotonic boundary, bypassing only
            # the CLI's successful refusal, with its current CAS precondition.
            status, result = self.http("/api/nocklock/anchors/v2/", dict(anchor=old_anchor,
                pubkey=self.public_key(self.a), expected_previous=headers["ETag"].strip('"')))
            require(status == 409 and result.get("data", {}).get("code") == "row_count_regression", (status, result))
            require(self.latest(advanced) == remote and self.latest(self.anchor_b) == other, "rollback moved a remote pin")
        finally:
            self.snapshot(current, self.a["db"])
        self.anchor_a = advanced
        self.command(self.a, "verify", "--against-remote-anchor")
        return dict(rolled_back_count=7, retained_remote_count=remote["row_count"], other_project_unchanged=True,
                    direct_store_rejection="row_count_regression")

    def missing_identity(self):
        record = self.a["state"] / "chain-identity.json"
        saved = self.scratch / "saved-identity.json"
        record.rename(saved)
        before = self.database_fingerprint(self.a["db"])
        try:
            for args in (("verify", "--against-remote-anchor"), ("anchor", "push")):
                self.command(self.a, *args, fails=True)
                require(not record.exists(), "missing identity was silently recreated")
            self.prune_refused(self.a)
            require(self.database_fingerprint(self.a["db"]) == before, "missing identity changed DB")
        finally:
            saved.rename(record)
        fresh = self.project("existing-unenrolled", 2)
        for args in (("verify", "--against-remote-anchor"), ("anchor", "push")):
            self.command(fresh, *args, fails=True)
            require(not (fresh["state"] / "chain-identity.json").exists(), "legacy chain silently enrolled")
        return "Existing v2 mirror and entirely legacy DB both refuse ordinary remote commands without minting an identity; missing-record prune refused unchanged."

    def missing_remote(self):
        missing = self.project("missing-pin", 2)
        self.command(missing, "anchor", "enroll")
        anchor, path = self.emit(missing)
        # Deliberately remove ONLY this disposable fixture's remote pin to model
        # store loss; this is not an exposed server operation or a recovery path.
        with sqlite3.connect(self.scratch / "ncc.sqlite3") as db:
            stream_id = db.execute("SELECT id FROM nocklock_anchorstream WHERE chain_id=?", (anchor["chain_id"],)).fetchone()[0]
            db.execute("DELETE FROM nocklock_chainanchorv2 WHERE stream_id=?", (stream_id,))
            db.execute("DELETE FROM nocklock_anchorstream WHERE id=?", (stream_id,))
        offset = len((self.scratch / "requests.jsonl").read_text().splitlines())
        self.command(missing, "verify", "--against-remote-anchor", fails=True)
        self.command(missing, "anchor", "push", "--file", str(path), fails=True)
        require(self.http(self.latest_path(anchor))[0] == 404, "ordinary push recreated lost pin")
        write_json(self.scratch / "fault.json", dict(v1_only=True))
        try:
            self.command(self.a, "verify", "--against-remote-anchor", fails=True)
        finally:
            write_json(self.scratch / "fault.json", {})
        requests = [json.loads(line) for line in (self.scratch / "requests.jsonl").read_text().splitlines()[offset:]]
        require(all("/anchors/v2/" in item["path"] for item in requests), "v1 downgrade request observed")
        require(requests[-1]["served_path"] == "/unmounted-v2-route/" and requests[-1]["status"] == 404,
                "old-store control did not produce a real missing route")
        return "Actual lost pair stays absent; missing v2 route exits nonzero; request receipt contains only v2 paths."

    def legacy_migration(self):
        owner = self.project("legacy-owner", 5, "legacy")
        wrong = self.project("legacy-wrong", 8, "legacy")
        legacy, path = self.emit(owner)
        require(legacy["version"] == 1, "legacy fixture is not v1")
        with sqlite3.connect(wrong["db"]) as db:
            wrong_prefix = db.execute("SELECT entry_hash FROM events ORDER BY id LIMIT 1 OFFSET ?",
                                      (legacy["row_count"] - 1,)).fetchone()[0]
        require(wrong_prefix != legacy["head_hash"], "wrong-owner negative control has identical legacy history")
        self.command(owner, "verify", "--against-anchor", str(path))
        status, response = self.http("/api/nocklock/anchors/", dict(anchor=legacy, pubkey=self.public_key(owner)))
        require(status == 201, ("v1 fixture push failed", status, response))
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        output = self.command(wrong, "anchor", "migrate", fails=True)
        require("legacy migration preflight refused" in output, output)
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "wrong owner changed store")
        self.command(owner, "anchor", "migrate")
        migrated, _ = self.emit(owner)
        require(migrated["version"] == 2 and migrated["legacy_anchor_digest"] != "0" * 64, "migration witness missing")
        self.command(owner, "verify", "--against-remote-anchor")
        require(self.http("/api/nocklock/anchors/" + legacy["agent_id"] + "/latest/")[0] == 409, "v1 read not frozen")
        self.command(wrong, "anchor", "enroll", fails=True)
        require(not (wrong["state"] / "chain-identity.json").exists(), "ordinary fresh enrollment claimed legacy history")
        self.command(wrong, "anchor", "enroll", "--acknowledge-no-legacy-history")
        acknowledged, _ = self.emit(wrong)
        require(acknowledged["legacy_anchor_digest"] == "0" * 64, "unrelated project absorbed legacy witness")
        self.command(owner, "verify", "--against-remote-anchor")
        return dict(correct_owner_verified=True, wrong_owner_refused=True, explicit_unrelated_acknowledgement=True,
                    legacy_anchor_digest=migrated["legacy_anchor_digest"])

    def crash_retry(self):
        project = self.project("pending-crash", 4)
        write_json(self.scratch / "fault.json", dict(hold_registration=True))
        output_path = self.scratch / "killed-enroll.log"
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]))
        with output_path.open("w") as output:
            process = subprocess.Popen([str(self.args.nocklock_bin), "anchor", "enroll"],
                                       cwd=project["path"], env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                self.wait_file(self.scratch / "registration-committed.json")
                require(self.identity(project)["registration_state"] == "pending", "pending not durable before committed response")
                require(process.poll() is None, "CLI exited before crash injection")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                write_json(self.scratch / "fault.json", {})
        require(process.returncode == -signal.SIGKILL, "CLI did not undergo the intended crash")
        require(self.identity(project)["registration_state"] == "pending", "crash cleared pending")
        self.prune_refused(project)
        self.command(project, "anchor", "enroll")
        require(self.identity(project)["registration_state"] == "enrolled", "retry failed to confirm exact original registration")
        self.command(project, "verify", "--against-remote-anchor")
        self.prune_refused(project)
        return "Real NCC commit withheld; CLI killed; durable pending blocks prune; exact registration retry confirms enrolled and remote verification passes."

    def rejected_registration(self):
        project = self.project("pending-rejection", 2)
        write_json(self.scratch / "fault.json", dict(reject_registration=True))
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        try:
            self.command(project, "anchor", "enroll", fails=True)
        finally:
            write_json(self.scratch / "fault.json", {})
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "invalid signature modified store")
        require(self.identity(project)["registration_state"] == "pending", "validation error cleared pending")
        self.prune_refused(project)
        return "Transport-corrupted signature rejected by actual NCC validator; local pending persists and prune refuses without DB changes."

    def moved_identity(self):
        project = self.a
        before = self.identity(project)
        remote = self.latest(self.anchor_a)
        destination = self.scratch / "project-a-moved"
        state = self.state_path(destination)
        require(not destination.exists() and not state.exists(), "move destinations must be absent")
        project["path"].rename(destination)
        project["state"].rename(state)
        project.update(path=destination, state=state, db=state / "events.db")
        require(self.identity(project) == before, "move changed identity tuple")
        self.command(project, "verify", "--audit")
        self.command(project, "verify", "--against-remote-anchor")
        require(self.latest(self.anchor_a) == remote, "move changed remote pair")
        return dict(agent_id=before["agent_id"], chain_id=before["chain_id"], registration_state=before["registration_state"])

    def legacy_prune(self):
        project = self.project("prune-unenrolled", 3)
        self.command(project, "log", "--prune", "0s")
        with sqlite3.connect(project["db"]) as db:
            require(db.execute("SELECT count(*) FROM events").fetchone()[0] == 0, "unenrolled control did not prune")
        return "Actual legacy CLI prune removes rows when registration was never sent. Identity-none and lock/crash filesystem edge cases remain lower-level Go coverage."

    def wait_file(self, path, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            if self.server.poll() is not None:
                raise RuntimeError("NCC server stopped: " + (self.scratch / "server.log").read_text()[-6000:])
            time.sleep(0.05)
        raise RuntimeError("timed out waiting for " + path.name)

    def close(self):
        if self.server.poll() is None:
            os.killpg(self.server.pid, signal.SIGTERM)
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.server.pid, signal.SIGKILL)
                self.server.wait()
        self.server_log.close()

    def http(self, path, body=None, token=True, include_headers=False):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read()
            result = (response.status, json.loads(raw) if raw else None)
            return (*result, dict(response.headers)) if include_headers else result

    def case(self, name, callback):
        try:
            detail = callback()
            self.rows.append(dict(case=name, verdict="PASS", detail=detail))
            print(name + ": PASS", flush=True)
        except Exception as exc:
            self.rows.append(dict(case=name, verdict="FAIL", detail=str(exc)))
            raise

    def store_smoke(self):
        vectors = json.loads((self.args.ncc_checkout / "nocklock/tests/fixtures/anchor_v2_vectors.json").read_text())
        cases = {case["name"]: case for case in vectors["cases"]}
        base = "/api/nocklock/anchors/v2/"
        a, b = [cases[name]["anchor"] for name in ("valid_chain_a", "valid_chain_b")]
        require(a["agent_id"] == b["agent_id"] and a["chain_id"] != b["chain_id"], "public vector pair control failed")
        status, _ = self.http(base + "register/", {}, token=False)
        require(status == 401, status)
        for anchor in (a, b):
            status, result = self.http(base + "register/", dict(anchor=anchor, pubkey=vectors["public_key"], mode="fresh"))
            require(status == 201, (status, result))
            path = base + anchor["agent_id"] + "/" + anchor["chain_id"] + "/latest/"
            require(self.http(path) == (200, anchor), "public vector latest differs")
        with sqlite3.connect("file:" + str(self.scratch / "ncc.sqlite3") + "?mode=ro", uri=True) as db:
            require(db.execute("SELECT count(*) FROM nocklock_anchorstream").fetchone()[0] == 2, "real store did not create two pairs")
        return "Actual bearer gate, signed public vectors, two separate stored pairs and real HTTP latest reads; no CLI acceptance claim."

    def evidence(self):
        # Deliberate allowlist: never copy the SQLite files, temporary HOME,
        # settings, signing seeds, tokens or subprocess environments.
        for name in ("requests.jsonl", "migration.log", "server.log"):
            source = self.scratch / name
            if source.exists():
                text = source.read_text().replace(self.token, "[temporary token redacted]")
                (self.args.out / name).write_text(text)
        write_json(self.args.out / "commands.json", self.commands)
        write_json(self.args.out / "report.json", {
            "verdict": "FAIL" if any(row["verdict"] == "FAIL" for row in self.rows) else "PASS",
            "scope": "server-smoke" if self.args.server_smoke else "CLI-and-real-NCC",
            "ncc_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.args.ncc_checkout, text=True).strip(),
            "ncc_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=self.args.ncc_checkout)),
            "nocklock_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True).strip(),
            "nocklock_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=Path(__file__).resolve().parents[1])),
            "nocklock_binary_sha256": hashlib.sha256(self.args.nocklock_bin.read_bytes()).hexdigest() if self.args.nocklock_bin else None,
            "django": self.ready["django"], "cases": self.rows,
            "lower_level_only": ["identity-none prune with present record", "registration/prune lock interleaving",
                                 "durable-write failure before send", "symlink/hardlink/FIFO identity-file controls",
                                 "stale legacy digest and duplicate migration claims"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ncc-checkout", type=Path, default=os.environ.get("NCC_CHECKOUT"))
    parser.add_argument("--ncc-python", type=Path, default=os.environ.get("NCC_PYTHON"))
    parser.add_argument("--nocklock-bin", type=Path, default=os.environ.get("NOCKLOCK_BIN"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--server-smoke", action="store_true", help="only prove isolated real-server lifecycle/auth/storage")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("never run this harness as root")
    for name in ("ncc_checkout", "ncc_python"):
        value = getattr(args, name)
        if value is None or not value.exists():
            parser.error(name + " must name an existing explicit path")
        # Resolving a venv's Python symlink would silently select the system
        # interpreter and lose that venv's packages. Preserve the launcher path.
        setattr(args, name, value.absolute() if name == "ncc_python" else value.resolve())
    if not args.server_smoke:
        if args.nocklock_bin is None or not args.nocklock_bin.is_file():
            parser.error("--nocklock-bin must name the built v2 CLI")
        args.nocklock_bin = args.nocklock_bin.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.umask(0o077)
    harness = None
    with tempfile.TemporaryDirectory(prefix="nocklock-ncc-acceptance-") as temporary:
        try:
            harness = Harness(args, Path(temporary).resolve())
            harness.case("real-ncc-server-smoke", harness.store_smoke)
            if not args.server_smoke:
                harness.cli_acceptance()
        except Exception as exc:
            if harness is not None and not any(row["verdict"] == "FAIL" for row in harness.rows):
                harness.rows.append(dict(case="harness-execution", verdict="FAIL", detail=str(exc)))
            raise
        finally:
            if harness is not None:
                harness.close()
                harness.evidence()
    print("Evidence: " + str(args.out))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(Path(sys.argv[2]).resolve())
    else:
        main()
