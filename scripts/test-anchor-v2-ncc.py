#!/usr/bin/env python3
"""Exercise NockLock against real NCC handlers on private loopback + SQLite.

Set NCC_CHECKOUT and NCC_PYTHON explicitly. No resident settings, credentials,
database, root privilege, external service, or mock anchor store is used.
"""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
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


FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


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


def require_diagnostic(output, expected):
    """Require the actual leading CLI refusal, not a matching help-text substring."""
    require(output.splitlines() and output.splitlines()[0] == expected, output)


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
        raw_request = b""
        posted = {}
        if environ["REQUEST_METHOD"] == "POST":
            raw_request = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
            environ["wsgi.input"] = io.BytesIO(raw_request)
            try:
                posted = json.loads(raw_request)
            except ValueError:
                pass  # Malformed input still reaches the actual validator.
        pause = fault.get("pause_before", {})
        candidate = posted.get("anchor", {}) if isinstance(posted, dict) else {}
        if (pause and original == pause["path"] and environ["REQUEST_METHOD"] == "POST"
                and all(candidate.get(field) == value for field, value in pause["anchor"].items())):
            write_json(scratch / (pause["id"] + "-paused.json"), {"path": original})
            deadline = time.monotonic() + 20
            while json.loads((scratch / "fault.json").read_text()).get("pause_before", {}).get("id") == pause["id"]:
                if time.monotonic() >= deadline:
                    raise RuntimeError("test did not release the paused request")
                time.sleep(0.02)
        if original == fault.get("swap_from"):
            environ["PATH_INFO"] = fault["swap_to"]
        if fault.get("v1_only") and original.startswith("/api/nocklock/anchors/v2/"):
            environ["PATH_INFO"] = "/unmounted-v2-route/"
        if fault.get("reject_registration") and original.endswith("/register/"):
            body = json.loads(raw_request)
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
        if raw_request:
            event["request_sha256"] = hashlib.sha256(raw_request).hexdigest()
        try:
            reply = json.loads(body)
            if isinstance(reply, dict) and isinstance(reply.get("data"), dict):
                event["code"] = reply["data"].get("code")
        except ValueError:
            # The body is not JSON (for example a plain-text or HTML error
            # page). The event is still logged, only without a "code" field.
            pass
        if original == fault.get("corrupt_response_path") and event["status"] == 200:
            kind = fault["corrupt_response"]
            if kind == "malformed":
                body = b'{"version":'
            else:
                broken = json.loads(body)
                if kind in ("chain_id", "chain_id_only"):
                    broken["chain_id"] = "f" * 64
                else:
                    broken["sig"] = "A" * 86 + "=="
                if kind != "chain_id_only":
                    broken["row_count"] = 2**64 - 1
                body = json.dumps(broken).encode()
            response["headers"] = [(key, value) for key, value in response["headers"]
                                   if key.lower() != "content-length"]
            response["headers"].append(("Content-Length", str(len(body))))
            event["invalid_response_fault"] = kind
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
        self.env = {"PATH": FIXED_PATH, "HOME": str(scratch / "home"), "LC_ALL": "C",
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
        self.secret_values = {self.token, key, self.env["SECRET_KEY"],
                              self.env["TEST_WEBHOOK_SECRET"], self.env["GITHUB_WEBHOOK_SECRET"]}
        for name in ("home", "config", "state"):
            (scratch / name).mkdir(mode=0o700)
        (scratch / "harness-private-directory").touch(mode=0o600)
        (scratch / "ncc_acceptance_settings.py").write_text(SETTINGS)
        (scratch / "ncc_acceptance_urls.py").write_text(URLS)
        write_json(scratch / "fault.json", {})
        self.server_log = (scratch / "server.log").open("w")
        self.server = None
        initialized = False
        try:
            self.server = subprocess.Popen([str(args.ncc_python), str(Path(__file__).resolve()),
                                            "--serve", str(scratch)], cwd=scratch, env=self.env,
                                           stdout=self.server_log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            self.wait_file(scratch / "ready.json", timeout=120)
            self.ready = json.loads((scratch / "ready.json").read_text())
            self.url = self.ready["url"]
            self.cli_env = {"PATH": FIXED_PATH, "HOME": str(scratch / "home"),
                            "XDG_CONFIG_HOME": str(scratch / "config"),
                            "XDG_STATE_HOME": str(scratch / "state"),
                            "NOCKLOCK_ANCHOR_URL": self.url, "NOCKLOCK_ANCHOR_TOKEN": self.token}
            initialized = True
        except Exception as exc:
            raise RuntimeError(self.redact(str(exc))) from None
        finally:
            # Includes KeyboardInterrupt/SystemExit before __init__ returns;
            # main has no assigned Harness yet and cannot clean up this child.
            if not initialized:
                self.close()
                (args.out / "bootstrap-error.log").write_text(self.redact((scratch / "server.log").read_text()))

    def redact(self, value):
        if isinstance(value, str):
            for secret in sorted(self.secret_values, key=len, reverse=True):
                value = value.replace(secret, "[temporary secret redacted]")
            return value
        if isinstance(value, dict):
            return {self.redact(key): self.redact(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact(item) for item in value]
        return value

    def command(self, project, *args, fails=False, remote=True, base_url=None):
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]))
        if base_url is not None:
            env["NOCKLOCK_ANCHOR_URL"] = base_url
        if not remote:
            env.pop("NOCKLOCK_ANCHOR_URL", None)
            env.pop("NOCKLOCK_ANCHOR_TOKEN", None)
        result = subprocess.run([str(self.args.nocklock_bin), *args], cwd=project["path"],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=45)
        output = self.redact(result.stdout)
        self.commands.append(dict(project=project["path"].name, args=args,
                                  exit=result.returncode, output=output))
        require((result.returncode != 0) == fails, (args, result.returncode, output))
        return output

    @contextmanager
    def running_cli(self, project, *args):
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]))
        with tempfile.TemporaryFile(mode="w+t", dir=self.scratch) as output:
            process = subprocess.Popen([str(self.args.nocklock_bin), *args], cwd=project["path"],
                                       env=env, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                yield process, output
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    def finish_cli(self, project, args, process, output, fails=False):
        process.wait(timeout=35)
        output.seek(0)
        text = self.redact(output.read())
        self.commands.append(dict(project=project["path"].name, args=args,
                                  exit=process.returncode, output=text))
        require((process.returncode != 0) == fails, (args, process.returncode, text))
        return text

    @contextmanager
    def fault(self, value):
        write_json(self.scratch / "fault.json", value)
        try:
            yield
        finally:
            write_json(self.scratch / "fault.json", {})

    def requests(self):
        path = self.scratch / "requests.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def project(self, name, count, group="shared", in_project=False, key_root=None):
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
db = "DB_PATH"
'''.replace("DB_PATH", ".nock/events.db" if in_project else "events.db"))
        key_root = key_root or self.scratch / ("key-" + group)
        key_root.mkdir(mode=0o700, exist_ok=True)
        state = self.state_path(project)
        state.mkdir(mode=0o700, parents=True)
        info = dict(path=project, state=state, db=(project / ".nock/events.db") if in_project else state / "events.db",
                    key_root=key_root, in_project=in_project)
        if count:
            self.append_rows(info, count)
        return info

    def state_path(self, project):
        project_hash = hashlib.sha256(str(project.resolve()).encode()).hexdigest()[:16]
        return self.scratch / "state/nocklock" / project_hash

    def append_rows(self, project, count):
        self.fixture_action(project, str(count))

    def fixture_action(self, project, *args):
        env = dict(self.cli_env, XDG_CONFIG_HOME=str(project["key_root"]),
                   NOCKLOCK_NCC_TEST_ROOT=str(self.scratch))
        subprocess.run([str(self.fixture), str(project["db"]), str(project["path"]), *args],
                       env=env, check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def clone_project(self, source, name, identity=False):
        clone = self.project(name, 0, in_project=source["in_project"], key_root=source["key_root"])
        self.snapshot(source["db"], clone["db"])
        if identity:
            for name in ("chain-identity.json", "anchor-registration.json"):
                shutil.copy2(source["state"] / name, clone["state"] / name)
        return clone

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
        if (project["state"] / "chain-identity.json").exists():
            identity = self.identity(project)
            expected = ("refusing prune: remote pin for (" + identity["agent_id"] + ", " + identity["chain_id"] +
                        ") is " + identity["registration_state"] + "; archive the old DB and enroll a fresh chain to bound growth; "
                        "for moved state follow docs/runbooks/chain-identity-move.md")
        else:
            expected = ("refusing chain operation: trusted identity record and DB mirror are incomplete; remote pin may exist; "
                        "follow docs/runbooks/chain-identity-move.md, never mint a replacement ID")
        require_diagnostic(output, "Error: failed to prune events: " + expected)
        require(self.database_fingerprint(project["db"]) == before, "prune refusal changed the DB")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == store_before, "prune refusal changed remote state")
        require((self.scratch / "requests.jsonl").read_bytes() == requests_before, "prune consulted the remote store")

    def cli_acceptance(self):
        repo = Path(__file__).resolve().parents[1]
        self.fixture = self.scratch / "anchor-fixture"
        go = shutil.which("go")
        require(go, "Go is required to build the signed-row fixture")
        # This compiles the real logging package. The fixture generates rows
        # and explicit none-state identities. CLI preflights and separately
        # labeled direct-handler negative controls both use real signed records.
        subprocess.run([go, "build", "-o", str(self.fixture), "./scripts/testdata/anchor-v2-fixture"],
                       cwd=repo, check=True, timeout=120)
        self.case("two-projects-same-key-independent-pins", self.two_projects)
        self.case("cli-same-head-push-real-http-already-stored", self.same_head_push)
        self.case("swapped-pair-before-count-and-server-url-binding", self.swapped_pair)
        self.case("cli-rollback-and-direct-http-regression-control", self.rollback)
        for kind in ("chain_id_only", "chain_id", "signature", "malformed"):
            self.case("transit-invalid-remote-" + kind + "-before-count-and-direct-http-controls", lambda kind=kind: self.invalid_remote(kind))
        self.case("local-mirror-disagreement-before-remote-verdict", self.mirror_disagreement)
        self.case("missing-local-identity-does-not-mint", self.missing_identity)
        self.case("missing-pin-and-old-store-never-downgrade", self.missing_remote)
        self.case("unreachable-loopback-store-never-downgrades", self.unreachable_remote)
        self.case("stale-cli-cas-retains-competing-pin", self.stale_cas)
        self.case("legacy-wrong-owner-refused-correct-migration-verifies", self.legacy_migration)
        self.case("cli-migration-shorter-and-direct-http-refusal", lambda: self.migration_history_conflict(shorter=True))
        self.case("cli-migration-divergence-and-direct-http-refusal", lambda: self.migration_history_conflict(shorter=False))
        self.case("migration-stale-witness-retains-advanced-legacy", self.stale_migration)
        self.case("migration-preidentity-clone-cannot-claim-twice", self.duplicate_migration)
        self.case("migration-lost-committed-response-exact-retry", lambda: self.crash_retry(mode="migrate"))
        self.case("direct-http-v1-read-write-before-migration", self.v1_before)
        self.case("direct-http-v1-frozen-after-cli-migration", self.v1_frozen)
        self.case("direct-http-v2-body-rejected-by-v1-retained-history-unchanged", self.v1_rejects_v2)
        self.case("committed-response-loss-crash-pending-retry-prune", self.crash_retry)
        self.case("registration-validation-error-stays-pending", self.rejected_registration)
        self.case("offline-project-and-state-move-preserves-pair", self.moved_identity)
        self.case("in-project-db-and-external-identity-move", self.in_project_move)
        self.case("explicit-fresh-fork-gets-new-chain-id", self.fresh_fork)
        self.case("copied-enrolled-id-divergence-cannot-replace-pin", self.copied_fork)
        self.case("present-identity-none-prune-positive-control", self.identity_none_prune)
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

    def same_head_push(self):
        status, original, headers = self.http(self.latest_path(self.anchor_a), include_headers=True)
        require(status == 200, original)
        candidate, path = self.emit(self.a)
        require(candidate["row_count"] == original["row_count"] and candidate["head_hash"] == original["head_hash"],
                "same-head candidate changed the signed history")
        require(candidate != original, "same-head control must re-attest the original snapshot")
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        offset = len(self.requests())
        self.command(self.a, "anchor", "push", "--file", str(path))
        requests = self.requests()[offset:]
        require(len(requests) == 2 and requests[0]["method"] == "GET" and
                requests[0]["path"] == self.latest_path(candidate) and requests[0]["status"] == 200 and
                requests[1]["method"] == "POST" and requests[1]["path"] == "/api/nocklock/anchors/v2/" and
                requests[1]["status"] == 200 and requests[1].get("code") == "already_stored", requests)
        status, retained, retained_headers = self.http(self.latest_path(candidate), include_headers=True)
        require(status == 200 and retained == original and retained_headers["ETag"] == headers["ETag"],
                "same-head push replaced the original signed snapshot")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "same-head push changed the store")
        return dict(http_status=requests[1]["status"], code=requests[1]["code"],
                    original_snapshot_etag=headers["ETag"], original_snapshot_retained=True)

    def swapped_pair(self):
        self.append_rows(self.b, 10)
        self.anchor_b, path = self.emit(self.b)
        self.command(self.b, "anchor", "push", "--file", str(path))
        require(self.anchor_b["row_count"] > self.anchor_a["row_count"], "swap count control missing")
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        write_json(self.scratch / "fault.json", dict(swap_from=self.latest_path(self.anchor_a), swap_to=self.latest_path(self.anchor_b)))
        try:
            output = self.command(self.a, "verify", "--against-remote-anchor", fails=True)
            require_diagnostic(output, "ANCHOR: UNAVAILABLE (anchor_unavailable) — anchor identity mismatch: signed pair differs from the trusted expected pair")
        finally:
            write_json(self.scratch / "fault.json", {})
        pair_path = self.latest_path(self.anchor_a).removesuffix("latest/")
        status, response = self.http(pair_path, dict(anchor=self.anchor_b, pubkey=self.public_key(self.b), expected_previous="0" * 64))
        require(status == 400 and response.get("message") == "signed identity does not match the URL pair", (status, response))
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
            output = self.command(self.a, "anchor", "push", "--file", str(old_path), fails=True)
            require("remote anchor preflight refused: truncation detected" in output, output)
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
        return dict(rolled_back_count=old_anchor["row_count"], retained_remote_count=remote["row_count"], other_project_unchanged=True,
                    direct_store_rejection="row_count_regression")

    def invalid_remote(self, kind):
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        local = self.database_fingerprint(self.a["db"])
        with self.fault(dict(corrupt_response_path=self.latest_path(self.anchor_a), corrupt_response=kind)):
            output = self.command(self.a, "verify", "--against-remote-anchor", fails=True)
        expected = {"chain_id_only": "signature does not verify", "chain_id": "signature does not verify",
                    "signature": "signature does not verify",
                    "malformed": "invalid remote v2 anchor"}
        require(expected[kind] in output.lower() and "TRUNCATION" not in output, output)
        # The invalid fields travel through the actual POST validator too.
        # The count deliberately exceeds the local count, but is not trusted.
        if kind != "malformed":
            _, anchor, headers = self.http(self.latest_path(self.anchor_a), include_headers=True)
            invalid = dict(anchor)
            if kind != "chain_id_only":
                invalid["row_count"] = 2**64 - 1
            invalid.update({"chain_id": "f" * 64} if kind in ("chain_id", "chain_id_only") else {"sig": "A" * 86 + "=="})
            if kind == "chain_id_only":
                require({key for key in anchor if invalid[key] != anchor[key]} == {"chain_id"},
                        "ID-only negative changed another signed field")
            status, result = self.http("/api/nocklock/anchors/v2/", dict(anchor=invalid,
                pubkey=self.public_key(self.a), expected_previous=headers["ETag"].strip('"')))
            require(status == 400 and result.get("data", {}).get("code") == "invalid_anchor", (status, result))
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "invalid anchor changed remote store")
        require(self.database_fingerprint(self.a["db"]) == local, "invalid response changed local DB")
        return dict(invalid_response=kind, before_count=True, id_only_binding=kind == "chain_id_only",
                    real_post_rejected=kind != "malformed",
                    remote_fingerprint=before, local_fingerprint=local)

    def mirror_disagreement(self):
        saved = self.scratch / "mirror-before.sqlite3"
        self.snapshot(self.a["db"], saved)
        remote = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        try:
            with sqlite3.connect(self.a["db"]) as db:
                db.execute("UPDATE chain_identity SET chain_id=?", ("e" * 64,))
            # Baseline after deliberate corruption; a refusal must not repair it.
            corrupted = self.database_fingerprint(self.a["db"])
            requests = len(self.requests())
            for args in (("verify", "--against-remote-anchor"), ("anchor", "push")):
                output = self.command(self.a, *args, fails=True)
                require("trusted identity and DB mirror disagree" in output and "TRUNCATION" not in output, output)
            require(len(self.requests()) == requests, "mirror disagreement made an HTTP request")
            require(self.database_fingerprint(self.a["db"]) == corrupted, "refusal changed corrupted mirror")
            require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == remote, "mirror refusal changed remote store")
        finally:
            self.snapshot(saved, self.a["db"])
        return dict(no_http=True, before_count=True, corrupted_db_fingerprint=corrupted, remote_fingerprint=remote)

    def unreachable_remote(self):
        local = self.database_fingerprint(self.a["db"])
        remote = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        requests = len(self.requests())
        _, path = self.emit(self.a)
        # Reserve a loopback port without listening: no reuse race or external host.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            url = "http://127.0.0.1:" + str(reserved.getsockname()[1])
            for args in (("verify", "--against-remote-anchor"), ("anchor", "push", "--file", str(path))):
                output = self.command(self.a, *args, fails=True, base_url=url)
                require("dial tcp 127.0.0.1:" in output and "connect:" in output and
                        any(reason in output.lower() for reason in ("connection refused", "operation timed out")), output)
        require(len(self.requests()) == requests, "unreachable store triggered another endpoint")
        require(self.database_fingerprint(self.a["db"]) == local, "unreachable store changed local DB")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == remote, "unreachable store changed pin")
        return dict(loopback_connect_failed=True, no_fallback=True, local_fingerprint=local, remote_fingerprint=remote)

    def stale_cas(self):
        project = self.project("stale-cas", 3)
        self.command(project, "anchor", "enroll")
        self.append_rows(project, 1)
        intermediate, _ = self.emit(project)
        self.append_rows(project, 1)
        candidate, path = self.emit(project)
        _, _, headers = self.http(self.latest_path(candidate), include_headers=True)
        endpoint = "/api/nocklock/anchors/v2/"
        pause = dict(id="stale-cas", path=endpoint,
                     anchor=dict(chain_id=candidate["chain_id"], row_count=candidate["row_count"]))
        args = ("anchor", "push", "--file", str(path))
        offset = len(self.requests())
        with self.fault(dict(pause_before=pause)), self.running_cli(project, *args) as (process, output):
            self.wait_file(self.scratch / "stale-cas-paused.json")
            status, result = self.http(endpoint, dict(anchor=intermediate, pubkey=self.public_key(project),
                                                     expected_previous=headers["ETag"].strip('"')))
            require(status == 201, (status, result))
            competing = self.latest(candidate)
            before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
            write_json(self.scratch / "fault.json", {})
            text = self.finish_cli(project, args, process, output, fails=True)
            require("previous_mismatch" in text, text)
        require(self.latest(candidate) == competing, "stale CLI replaced competing pin")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "stale CAS changed store")
        posts = [row for row in self.requests()[offset:] if row["method"] == "POST" and row["path"] == endpoint]
        require(len(posts) == 2 and posts[0]["status"] == 201 and posts[1]["status"] == 409 and
                posts[1].get("code") == "previous_mismatch", ("this case did not receive real stale CAS", posts))
        return dict(candidate_count=candidate["row_count"], retained_count=competing["row_count"],
                    actual_error=posts[1]["code"], post_competing_write_fingerprint=before)

    def missing_identity(self):
        record = self.a["state"] / "chain-identity.json"
        saved = self.scratch / "saved-identity.json"
        record.rename(saved)
        before = self.database_fingerprint(self.a["db"])
        requests = len(self.requests())
        try:
            for args in (("verify", "--against-remote-anchor"), ("anchor", "push")):
                output = self.command(self.a, *args, fails=True)
                prefix = "ANCHOR: UNAVAILABLE (anchor_unavailable) — " if args[0] == "verify" else "Error: anchor push failed: "
                require_diagnostic(output, prefix + "refusing chain operation: trusted identity record and DB mirror are incomplete; remote pin may exist; follow docs/runbooks/chain-identity-move.md, never mint a replacement ID")
                require(not record.exists(), "missing identity was silently recreated")
            self.prune_refused(self.a)
            require(self.database_fingerprint(self.a["db"]) == before, "missing identity changed DB")
            require(len(self.requests()) == requests, "missing identity consulted remote")
        finally:
            saved.rename(record)
        fresh = self.project("existing-unenrolled", 2)
        # Supply an existing valid v2 record with the same shared key. A missing
        # default file must not satisfy this no-identity preflight control.
        _, valid_v2_path = self.emit(self.a)
        for args in (("verify", "--against-remote-anchor"), ("anchor", "push", "--file", str(valid_v2_path))):
            output = self.command(fresh, *args, fails=True)
            prefix = "ANCHOR: UNAVAILABLE (anchor_unavailable) — " if args[0] == "verify" else "Error: anchor push failed: "
            require_diagnostic(output, prefix + "chain identity is not initialized; explicit operator enrollment is required")
            require(not (fresh["state"] / "chain-identity.json").exists(), "legacy chain silently enrolled")
        require(len(self.requests()) == requests, "unenrolled legacy chain consulted remote")
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
        offset = len(self.requests())
        expected_reason = "v2 endpoint or stream unavailable"
        for args in (("verify", "--against-remote-anchor"), ("anchor", "push", "--file", str(path))):
            command_offset = len(self.requests())
            output = self.command(missing, *args, fails=True)
            require(expected_reason in output and "no v1 fallback" in output, output)
            requests = self.requests()[command_offset:]
            require(len(requests) == 1 and requests[0]["method"] == "GET" and
                    requests[0]["path"] == self.latest_path(anchor) and requests[0]["status"] == 404 and
                    requests[0].get("code") == "not_registered", ("lost-pin command did not reach real missing pair", requests))
        require(self.http(self.latest_path(anchor))[0] == 404, "ordinary push recreated lost pin")
        write_json(self.scratch / "fault.json", dict(v1_only=True))
        try:
            output = self.command(self.a, "verify", "--against-remote-anchor", fails=True)
            require(expected_reason in output and "no v1 fallback" in output, output)
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
        output = self.command(wrong, "anchor", "enroll", fails=True)
        require("this key has legacy remote history" in output and "--acknowledge-no-legacy-history" in output, output)
        require(not (wrong["state"] / "chain-identity.json").exists(), "ordinary fresh enrollment claimed legacy history")
        self.command(wrong, "anchor", "enroll", "--acknowledge-no-legacy-history")
        acknowledged, _ = self.emit(wrong)
        require(acknowledged["legacy_anchor_digest"] == "0" * 64, "unrelated project absorbed legacy witness")
        self.command(owner, "verify", "--against-remote-anchor")
        return dict(correct_owner_verified=True, wrong_owner_refused=True, explicit_unrelated_acknowledgement=True,
                    legacy_anchor_digest=migrated["legacy_anchor_digest"])

    def post_legacy(self, project):
        anchor, _ = self.emit(project)
        require(anchor["version"] == 1, "legacy fixture already has an identity")
        status, result = self.http("/api/nocklock/anchors/", dict(anchor=anchor, pubkey=self.public_key(project)))
        require(status == 201, (status, result))
        return anchor

    def legacy_latest(self, anchor):
        status, result, headers = self.http("/api/nocklock/anchors/v2/" + anchor["agent_id"] + "/legacy/",
                                            include_headers=True)
        require(status == 200, (status, result))
        return result, headers["ETag"].strip('"')

    def migration_history_conflict(self, shorter):
        name = "migration-shorter" if shorter else "migration-divergent"
        owner = self.project(name + "-owner", 3 if shorter else 5, name)
        if shorter:
            candidate = self.clone_project(owner, name + "-candidate")
            self.append_rows(owner, 2)
        else:
            candidate = self.project(name + "-candidate", 5, name)
        legacy = self.post_legacy(owner)
        _, digest = self.legacy_latest(legacy)
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        output = self.command(candidate, "anchor", "migrate", fails=True)
        require("legacy migration preflight refused" in output, output)
        require(not (candidate["state"] / "chain-identity.json").exists(), "invalid history minted an identity")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "migration preflight changed store")
        # Separately exercise the server boundary with a real signed candidate.
        # Only the private fixture initializes identity; the CLI signs the record.
        self.fixture_action(candidate, "init-identity", digest)
        signed, _ = self.emit(candidate)
        require((signed["row_count"] < legacy["row_count"]) if shorter else
                (signed["row_count"] == legacy["row_count"] and signed["head_hash"] != legacy["head_hash"]),
                "migration history negative control does not differ as intended")
        status, result = self.http("/api/nocklock/anchors/v2/migrate/", dict(anchor=signed,
            pubkey=self.public_key(candidate), expected_legacy=digest))
        code = "row_count_regression" if shorter else "head_conflict"
        require(status == 409 and result.get("data", {}).get("code") == code, (status, result))
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "rejected migration changed store")
        return dict(cli_preflight_refused_without_identity=True, separate_real_handler_error=code,
                    legacy_count=legacy["row_count"], candidate_count=signed["row_count"], remote_fingerprint=before)

    def stale_migration(self):
        project = self.project("migration-stale", 3, "migration-stale")
        original = self.post_legacy(project)
        self.append_rows(project, 2)
        advanced, _ = self.emit(project)
        endpoint = "/api/nocklock/anchors/v2/migrate/"
        pause = dict(id="stale-migration", path=endpoint,
                     anchor=dict(agent_id=original["agent_id"], row_count=advanced["row_count"]))
        args = ("anchor", "migrate")
        with self.fault(dict(pause_before=pause)), self.running_cli(project, *args) as (process, output):
            self.wait_file(self.scratch / "stale-migration-paused.json")
            status, result = self.http("/api/nocklock/anchors/", dict(anchor=advanced, pubkey=self.public_key(project)))
            require(status == 201, (status, result))
            before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
            write_json(self.scratch / "fault.json", {})
            text = self.finish_cli(project, args, process, output, fails=True)
            require("legacy_previous_mismatch" in text, text)
        require(self.identity(project)["registration_state"] == "pending", "stale migration cleared pending")
        require(self.legacy_latest(original)[0] == advanced, "stale migration changed advanced legacy")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "stale migration changed store")
        self.prune_refused(project)
        return dict(actual_error="legacy_previous_mismatch", pending=True, retained_legacy_count=advanced["row_count"],
                    post_competing_write_fingerprint=before)

    def duplicate_migration(self):
        owner = self.project("migration-first-claim", 5, "migration-duplicate")
        legacy = self.post_legacy(owner)
        clone = self.clone_project(owner, "migration-preidentity-clone")
        self.command(owner, "anchor", "migrate")
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        pin, _ = self.emit(owner)
        stored = self.latest(pin)
        output = self.command(clone, "anchor", "migrate", fails=True)
        require("legacy_already_claimed" in output, output)
        clone_id = self.identity(clone)
        require(clone_id["registration_state"] == "pending" and clone_id["chain_id"] != pin["chain_id"],
                "duplicate claimant did not keep a separate pending identity")
        require(self.latest(pin) == stored and self.legacy_latest(legacy)[0] == legacy, "duplicate claim moved history")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "duplicate claim changed store")
        self.prune_refused(clone)
        return dict(actual_error="legacy_already_claimed", preidentity_clone=True, distinct_pending_chain=True,
                    after_first_claim_fingerprint=before)

    def v1_before(self):
        self.v1_project = self.project("v1-compatibility", 3, "v1-compatibility")
        self.v1_anchor = self.post_legacy(self.v1_project)
        self.v1_path = "/api/nocklock/anchors/" + self.v1_anchor["agent_id"] + "/latest/"
        require(self.http(self.v1_path) == (200, self.v1_anchor), "v1 latest differs before migration")
        self.v1_retained = self.legacy_latest(self.v1_anchor)
        return "Real signed v1 POST returns 201 and ordinary GET returns the same anchor before any v2 stream."

    def v1_frozen(self):
        self.command(self.v1_project, "anchor", "migrate")
        self.v1_store_after_migration = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        body = dict(anchor=self.v1_anchor, pubkey=self.public_key(self.v1_project))
        for path, payload in ((self.v1_path, None), ("/api/nocklock/anchors/", body)):
            status, result = self.http(path, payload)
            require(status == 409 and result.get("data", {}).get("code") == "v1_frozen", (status, result))
        require(self.legacy_latest(self.v1_anchor) == self.v1_retained, "v1 freeze changed retained legacy snapshot")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == self.v1_store_after_migration,
                "frozen v1 operations changed store")
        return dict(read_error="v1_frozen", write_error="v1_frozen", retained_anchor_and_etag_unchanged=True,
                    after_migration_fingerprint=self.v1_store_after_migration)

    def v1_rejects_v2(self):
        v2, _ = self.emit(self.v1_project)
        status, result = self.http("/api/nocklock/anchors/", dict(anchor=v2, pubkey=self.public_key(self.v1_project)))
        require(status == 400 and result.get("message") ==
                "invalid anchor: anchor fields mismatch (missing=[], unexpected=['chain_id', 'legacy_anchor_digest'])", (status, result))
        require(self.legacy_latest(self.v1_anchor) == self.v1_retained, "invalid v1 POST changed retained history")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == self.v1_store_after_migration,
                "v2 body at v1 endpoint changed store")
        return "The actual v1 validator rejects the v2 body with HTTP 400; retained signed legacy anchor, ETag and whole store remain unchanged."

    def crash_retry(self, mode="enroll"):
        project = self.project("pending-crash-" + mode, 4, "pending-crash-" + mode)
        if mode == "migrate":
            self.post_legacy(project)
        marker = self.scratch / "registration-committed.json"
        marker.unlink(missing_ok=True)
        offset = len(self.requests())
        args = ("anchor", mode)
        with self.fault(dict(hold_registration=True)), self.running_cli(project, *args) as (process, output):
            self.wait_file(marker)
            require(self.identity(project)["registration_state"] == "pending", "pending not durable before committed response")
            require(process.poll() is None, "CLI exited before crash injection")
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            self.finish_cli(project, args, process, output, fails=True)
        require(process.returncode == -signal.SIGKILL, "CLI did not undergo the intended crash")
        require(self.identity(project)["registration_state"] == "pending", "crash cleared pending")
        request = (project["state"] / "anchor-registration.json").read_bytes()
        self.prune_refused(project)
        self.command(project, *args)
        require((project["state"] / "anchor-registration.json").read_bytes() == request, "retry rewrote original signed request")
        endpoint = "/api/nocklock/anchors/v2/" + ("register/" if mode == "enroll" else "migrate/")
        posts = [row for row in self.requests()[offset:] if row["path"] == endpoint and row["method"] == "POST"]
        code = "already_exists" if mode == "enroll" else "already_migrated"
        require(len(posts) == 2 and posts[0]["request_sha256"] == posts[1]["request_sha256"]
                and posts[1].get("code") == code, ("retry was not exact", posts))
        require(self.identity(project)["registration_state"] == "enrolled", "retry failed to confirm exact original registration")
        self.command(project, "verify", "--against-remote-anchor")
        self.prune_refused(project)
        return dict(mode=mode, real_commit_before_sigkill=True, exact_request_sha256=posts[0]["request_sha256"],
                    retry_confirmation=code, pending_and_enrolled_prune_refused_unchanged=True)

    def rejected_registration(self):
        project = self.project("pending-rejection", 2)
        write_json(self.scratch / "fault.json", dict(reject_registration=True))
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        offset = len(self.requests())
        try:
            self.command(project, "anchor", "enroll", fails=True)
        finally:
            write_json(self.scratch / "fault.json", {})
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "invalid signature modified store")
        require(self.identity(project)["registration_state"] == "pending", "validation error cleared pending")
        self.prune_refused(project)
        identity = self.identity(project)
        request = (project["state"] / "anchor-registration.json").read_bytes()
        database = self.database_fingerprint(project["db"])
        require(self.http(self.latest_path(identity))[0] == 404, "rejected registration unexpectedly has a pin")
        self.move_project(project, "pending-rejection-moved")
        require(self.identity(project) == identity, "pending move changed identity")
        require((project["state"] / "anchor-registration.json").read_bytes() == request, "pending move changed original request")
        require(self.database_fingerprint(project["db"]) == database, "pending move changed signed DB")
        self.command(project, "anchor", "enroll")
        posts = [row for row in self.requests()[offset:]
                 if row["path"] == "/api/nocklock/anchors/v2/register/" and row["method"] == "POST"]
        require(len(posts) == 2 and posts[0]["status"] == 400 and posts[0].get("code") == "invalid_anchor"
                and posts[1]["status"] == 201 and posts[1].get("code") == "registered"
                and posts[0]["request_sha256"] == posts[1]["request_sha256"], ("pending move did not retry exact request", posts))
        require(self.identity(project)["registration_state"] == "enrolled", "pending move retry did not enroll")
        require((project["state"] / "anchor-registration.json").read_bytes() == request, "moved retry rewrote request")
        self.command(project, "verify", "--against-remote-anchor")
        return dict(real_validator_rejected=True, pending_prune_refused_unchanged=True,
                    pending_offline_move_without_remote_pin=True, original_request_preserved=True, retry_verified=True,
                    original_request_sha256=posts[0]["request_sha256"], moved_db_fingerprint=database)

    def move_project(self, project, name):
        destination = self.scratch / name
        state = self.state_path(destination)
        require(not destination.exists() and not state.exists(), "move destinations must be absent")
        project["path"].rename(destination)
        project["state"].rename(state)
        project.update(path=destination, state=state,
                       db=destination / ".nock/events.db" if project["in_project"] else state / "events.db")

    def moved_identity(self):
        project = self.a
        before = self.identity(project)
        request = (project["state"] / "anchor-registration.json").read_bytes()
        database = self.database_fingerprint(project["db"])
        remote = self.latest(self.anchor_a)
        self.move_project(project, "project-a-moved")
        require(self.identity(project) == before, "move changed identity tuple")
        require((project["state"] / "anchor-registration.json").read_bytes() == request, "move changed original request")
        require(self.database_fingerprint(project["db"]) == database, "move changed signed DB")
        self.command(project, "verify", "--audit")
        self.command(project, "verify", "--against-remote-anchor")
        require(self.latest(self.anchor_a) == remote, "move changed remote pair")
        return dict(agent_id=before["agent_id"], chain_id=before["chain_id"], registration_state=before["registration_state"])

    def in_project_move(self):
        self.moving = self.project("in-project-db", 3, "moving-and-forking", in_project=True)
        self.command(self.moving, "anchor", "enroll")
        anchor, _ = self.emit(self.moving)
        identity = self.identity(self.moving)
        request = (self.moving["state"] / "anchor-registration.json").read_bytes()
        database = self.database_fingerprint(self.moving["db"])
        remote = self.latest(anchor)
        require(self.moving["db"].is_relative_to(self.moving["path"]) and
                not self.moving["state"].is_relative_to(self.moving["path"]), "move fixture has wrong DB/state placement")
        self.move_project(self.moving, "in-project-db-moved")
        require(self.identity(self.moving) == identity, "in-project move changed identity")
        require((self.moving["state"] / "anchor-registration.json").read_bytes() == request, "move changed original request")
        require(self.database_fingerprint(self.moving["db"]) == database, "move changed signed DB")
        self.command(self.moving, "verify", "--audit")
        self.command(self.moving, "verify", "--against-remote-anchor")
        require(self.latest(anchor) == remote, "in-project move changed remote pin")
        return dict(db_within_project=True, identity_external=True, chain_id=identity["chain_id"],
                    request_and_signed_db_preserved=True, remote_verified=True)

    def fresh_fork(self):
        original, _ = self.emit(self.moving)
        remote = self.latest(original)
        # A supported fresh fork starts a new audit DB; it never resets a copy
        # of an enrolled chain to none or deletes its trusted identity.
        self.fork = self.project("explicit-new-audit-fork", 3, key_root=self.moving["key_root"], in_project=True)
        self.command(self.fork, "anchor", "enroll")
        anchor, _ = self.emit(self.fork)
        require(anchor["agent_id"] == original["agent_id"] and anchor["chain_id"] != original["chain_id"],
                "fresh fork did not obtain an independent pair")
        for project in (self.moving, self.fork):
            self.command(project, "verify", "--against-remote-anchor")
        require(self.latest(original) == remote, "fresh fork changed source pin")
        return dict(new_audit_db=True, same_key=True, independent_chain_ids=[original["chain_id"], anchor["chain_id"]])

    def copied_fork(self):
        copy = self.clone_project(self.moving, "copied-enrolled-fork", identity=True)
        self.append_rows(self.moving, 1)
        original, path = self.emit(self.moving)
        self.command(self.moving, "anchor", "push", "--file", str(path))
        self.append_rows(copy, 1)
        divergent, copy_path = self.emit(copy)
        require(divergent["chain_id"] == original["chain_id"] and divergent["row_count"] == original["row_count"]
                and divergent["head_hash"] != original["head_hash"], "copied fork is not a signed equal-height divergence")
        self.command(copy, "verify", "--audit")
        _, pin, headers = self.http(self.latest_path(original), include_headers=True)
        fork_anchor, _ = self.emit(self.fork)
        other = self.latest(fork_anchor)
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        local = self.database_fingerprint(copy["db"])
        for args in (("verify", "--against-remote-anchor"), ("anchor", "push", "--file", str(copy_path))):
            text = self.command(copy, *args, fails=True)
            require("does not reproduce the anchored head" in text, text)
        status, result = self.http("/api/nocklock/anchors/v2/", dict(anchor=divergent, pubkey=self.public_key(copy),
                                                                 expected_previous=headers["ETag"].strip('"')))
        require(status == 409 and result.get("data", {}).get("code") == "head_conflict", (status, result))
        require(self.latest(original) == pin and self.latest(fork_anchor) == other, "copied fork replaced a pin")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "copied fork refusal changed store")
        require(self.database_fingerprint(copy["db"]) == local, "copied fork refusal changed local signed history")
        return dict(cli_prefix_refused=True, separate_real_handler_error="head_conflict",
                    original_and_fresh_fork_pins_unchanged=True, post_competing_write_fingerprint=before)

    def identity_none_prune(self):
        project = self.project("prune-present-none", 3)
        self.fixture_action(project, "init-identity")
        identity = self.identity(project)
        require(identity["registration_state"] == "none", "fixture did not create an unregistered identity")
        before = self.database_fingerprint(self.scratch / "ncc.sqlite3")
        requests = len(self.requests())
        self.command(project, "log", "--prune", "0s")
        with sqlite3.connect(project["db"]) as db:
            require(db.execute("SELECT count(*) FROM events").fetchone()[0] == 0, "present-none identity did not permit prune")
        require(self.identity(project) == identity, "allowed prune changed trusted identity")
        require(len(self.requests()) == requests, "none-state prune consulted remote")
        require(self.database_fingerprint(self.scratch / "ncc.sqlite3") == before, "none-state prune changed remote store")
        return dict(real_cli_pruned=True, present_identity_state="none", identity_unchanged=True, no_http=True)

    def legacy_prune(self):
        project = self.project("prune-unenrolled", 3)
        self.command(project, "log", "--prune", "0s")
        with sqlite3.connect(project["db"]) as db:
            require(db.execute("SELECT count(*) FROM events").fetchone()[0] == 0, "unenrolled control did not prune")
        return "Actual legacy CLI prune removes rows when no identity exists and registration was never sent."

    def wait_file(self, path, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            if self.server.poll() is not None:
                raise RuntimeError("NCC server stopped: " + self.redact((self.scratch / "server.log").read_text()[-6000:]))
            time.sleep(0.05)
        raise RuntimeError("timed out waiting for " + path.name)

    def close(self):
        if self.server is not None and self.server.poll() is None:
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
        offset = len(self.requests())
        try:
            detail = callback()
            requests = self.requests()[offset:]
            require(not any(row["status"] == 429 for row in requests),
                    "actual NCC rate limit returned HTTP 429; no negative case may accept it")
            self.rows.append(dict(case=name, verdict="PASS", detail_type="asserted", detail=self.redact(detail),
                                  request_range=[offset, offset + len(requests)]))
            print(name + ": PASS", flush=True)
        except Exception as exc:
            self.rows.append(dict(case=name, verdict="FAIL", detail=self.redact(str(exc))))
            raise RuntimeError(self.redact(str(exc))) from None

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
                text = self.redact(source.read_text())
                (self.args.out / name).write_text(text)
        write_json(self.args.out / "commands.json", self.redact(self.commands))
        rate_limited = [row for row in self.requests() if row["status"] == 429]
        if rate_limited:
            self.rows.append(dict(case="receipt-has-no-http-429", verdict="FAIL", detail=rate_limited))
        write_json(self.args.out / "report.json", self.redact({
            "verdict": "FAIL" if any(row["verdict"] == "FAIL" for row in self.rows) else "PASS",
            "scope": "server-smoke" if self.args.server_smoke else "CLI-and-real-NCC",
            "ncc_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.args.ncc_checkout, text=True).strip(),
            "ncc_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=self.args.ncc_checkout)),
            "nocklock_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1], text=True).strip(),
            "nocklock_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=Path(__file__).resolve().parents[1])),
            "nocklock_binary_sha256": hashlib.sha256(self.args.nocklock_bin.read_bytes()).hexdigest() if self.args.nocklock_bin else None,
            "django": self.ready["django"], "cases": self.rows,
            "lower_level_only": ["registration/prune lock interleaving and bounded lock cancellation",
                                 "durable-write failure before send and retry fsync barriers",
                                 "symlink/hardlink/FIFO identity-file controls"]}))
        require(not rate_limited, "actual NCC returned HTTP 429; see failed receipt")


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
            harness.case("direct-http-real-ncc-server-smoke", harness.store_smoke)
            if not args.server_smoke:
                harness.cli_acceptance()
        except Exception as exc:
            if harness is not None and not any(row["verdict"] == "FAIL" for row in harness.rows):
                harness.rows.append(dict(case="harness-execution", verdict="FAIL", detail=harness.redact(str(exc))))
            if harness is not None:
                raise RuntimeError(harness.redact(str(exc))) from None
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
