#!/usr/bin/env python3
"""Validate a `nocklock verify --export ocsf` JSONL file against the OCSF schema.

Every line must validate against the JSON schema of its class_uid, as served by
the OCSF schema server for the version the exporter pins (internal/ocsf/ocsf.go,
Version). The cloud and osint attributes are dropped from each class's required
list: they belong to profiles that do not apply to a local audit log. Nothing
else is relaxed.

The schema server renders each class on request and can take minutes, so the
schemas are downloaded into --schema-dir only when missing there (CI caches that
directory). Every file, cached or fresh, is checked against the SHA-256 digests
below before use. A cached file that mismatches is deleted and downloaded once
more; a fresh download that mismatches fails the check instead of being trusted.
When the exporter's OCSF version changes, bump OCSF_VERSION and every digest
together.

A negative control runs first: an event missing a required attribute must fail
schema validation,
so a validator that accepts everything cannot pass this check.

Usage: check-ocsf-schema.py --schema-dir DIR EXPORT.jsonl [...]
Needs the jsonschema package (CI installs a pinned version).
"""

import argparse
import copy
import hashlib
import json
import os
import urllib.request

import jsonschema

OCSF_VERSION = "1.9.0"
SCHEMA_URL = "https://schema.ocsf.io/schema/{version}/classes/{name}"
RELAXED = ("cloud", "osint")

# class_uid -> (schema class name, SHA-256 of the served schema bytes)
CLASSES = {
    1001: ("file_activity", "4fbcd82c83507438e4af7dc5f2c9a590e4fdf247b2db4a04e37cc1587b87407b"),
    1007: ("process_activity", "7639515aec8e7dbd95980abed4f3614594b0e2c7ba99d1dc040034b47639b61c"),
    2004: ("detection_finding", "a2c8201bf107f161a5fd89716e8f34ef39eff2bf1ff585b0fa8edab64c52cd62"),
    4001: ("network_activity", "7cfaa82ce06de2b82f935553cadfb883d41a26f2a029b8b5fbd04eb1c60e044d"),
    6002: ("application_lifecycle", "8f90a09ca94b50d1ffc86a2ad00d8105ff933da9f7def4a3b292b4d14f879b74"),
}


def fetch(url, retries=3):
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=300) as resp:
                return resp.read()
        except OSError as err:
            if attempt == retries:
                raise SystemExit(f"{url}: download failed after {retries} attempts: {err}")
            print(f"{url}: attempt {attempt} failed ({err}); retrying")


def download(url, path):
    body = fetch(url)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, path)


def verified_schema(path, url, digest):
    """Return the schema bytes at path, downloading them when missing.

    A cached file whose digest mismatches (a stale or damaged cache) is
    replaced by one fresh download; a fresh download that mismatches fails.
    """
    def read():
        with open(path, "rb") as f:
            body = f.read()
        return body, hashlib.sha256(body).hexdigest()

    cached = os.path.exists(path)
    if not cached:
        download(url, path)
    body, got = read()
    if got != digest and cached:
        print(f"{path}: cached SHA-256 {got} does not match the pinned {digest}; downloading again")
        os.remove(path)
        download(url, path)
        body, got = read()
    if got != digest:
        os.remove(path)
        raise SystemExit(f"{url}: SHA-256 {got} does not match the pinned {digest}; "
                         "review the schema change and bump the digest deliberately")
    return body


def load_validator(schema_dir, name, digest):
    path = os.path.join(schema_dir, f"{OCSF_VERSION}-{name}.json")
    url = SCHEMA_URL.format(version=OCSF_VERSION, name=name)
    schema = json.loads(verified_schema(path, url, digest))
    schema["required"] = [r for r in schema.get("required", []) if r not in RELAXED]
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def errors_for(validators, event):
    uid = event.get("class_uid")
    if uid not in validators:
        return [f"class_uid {uid!r} is not an exported class"]
    version = event.get("metadata", {}).get("version")
    if version != OCSF_VERSION:
        return [f"metadata.version {version!r} is not the pinned {OCSF_VERSION}"]
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in validators[uid].iter_errors(event)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--schema-dir", required=True, help="where the class schemas are cached")
    parser.add_argument("paths", nargs="+", metavar="EXPORT.jsonl")
    args = parser.parse_args()
    os.makedirs(args.schema_dir, exist_ok=True)
    validators = {uid: load_validator(args.schema_dir, name, digest) for uid, (name, digest) in CLASSES.items()}

    events = []
    for path in args.paths:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    events.append((f"{path}:{n}", json.loads(line)))
    if not events:
        raise SystemExit("no events to validate")

    where, control = events[0][0], copy.deepcopy(events[0][1])
    if "severity_id" not in control or control.get("class_uid") not in validators:
        raise SystemExit(f"negative control: {where} needs severity_id and an exported class_uid to build the control from")
    del control["severity_id"]
    if not list(validators[control["class_uid"]].iter_errors(control)):
        raise SystemExit("negative control: an event without severity_id validated; the check proves nothing")

    failed = 0
    seen = set()
    for where, event in events:
        seen.add(event.get("class_uid"))
        for err in errors_for(validators, event):
            failed += 1
            print(f"{where}: {err}")
    if failed:
        raise SystemExit(f"{failed} schema error(s) across {len(events)} event(s)")
    print(f"OCSF {OCSF_VERSION}: {len(events)} event(s) valid across classes {sorted(seen)}")


if __name__ == "__main__":
    main()
