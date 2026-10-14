import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from artifact import FILES, PAYLOAD, digest, names, validate


class CandidateValidationTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.commit = "a" * 40
        self.root, filename = names(self.commit)
        self.archive = Path(self.scratch.name) / filename
        self.manifest = Path(self.scratch.name) / "SHA256SUMS"
        elf = bytearray(64)
        elf[:7], elf[16:20] = b"\x7fELF\x02\x01\x01", b"\x03\x00\x3e\x00"
        self.files = {name: bytes(elf) if name in {"nocklock", "libfence_fs.so"} else b"fixture" for name in PAYLOAD}
        self.info = dict(schema=1, kind="ci-candidate-not-release", commit=self.commit,
                         os="linux", arch="amd64", distribution="ubuntu-24.04",
                         libc_baseline="glibc-2.39", version="0.0.0-candidate." + self.commit)

    def write(self, mutate=None):
        self.info["files"] = {name: digest(data) for name, data in self.files.items()}
        files = self.files | {"build-info.json": json.dumps(self.info).encode()}
        members = []
        directory = tarfile.TarInfo(self.root)
        directory.type, directory.mode = tarfile.DIRTYPE, 0o755
        members.append((directory, b""))
        for name, data in files.items():
            member = tarfile.TarInfo(self.root + "/" + name)
            member.mode = 0o755 if name in {"nocklock", "libfence_fs.so", "install-egress-helper.sh"} else 0o644
            member.size = len(data)
            members.append((member, data))
        if mutate:
            mutate(members)
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for member, data in members:
                tar.addfile(member, io.BytesIO(data))
        self.manifest.write_text(f"{digest(self.archive.read_bytes())}  {self.archive.name}\n")

    def test_valid_candidate(self):
        self.write()
        self.assertEqual(set(validate(self.archive, self.manifest, self.commit)), FILES)

    def test_bad_members(self):
        for case in ("duplicate", "missing", "absolute", "traversal", "symlink", "hardlink", "device", "mode", "owner"):
            with self.subTest(case=case):
                def mutate(members):
                    member = members[1][0]
                    if case == "duplicate": members.append(members[1])
                    elif case == "missing": members.pop()
                    elif case == "absolute": member.name = "/etc/candidate"
                    elif case == "traversal": member.name = self.root + "/../candidate"
                    elif case == "symlink": member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    elif case == "hardlink": member.type, member.linkname = tarfile.LNKTYPE, "/etc/passwd"
                    elif case == "device": member.type = tarfile.CHRTYPE
                    elif case == "mode": member.mode = 0o777
                    elif case == "owner": member.uid = 1000
                self.write(mutate)
                with self.assertRaises(ValueError): validate(self.archive, self.manifest, self.commit)

    def test_manifest_and_provenance(self):
        for case in ("changed_bytes", "extra_entry", "wrong_commit", "wrong_arch", "wrong_hash"):
            with self.subTest(case=case):
                self.write()
                commit = self.commit
                if case == "changed_bytes": self.archive.write_bytes(self.archive.read_bytes() + b"changed")
                elif case == "extra_entry": self.manifest.write_text(self.manifest.read_text() * 2)
                elif case == "wrong_commit": commit = "b" * 40
                else:
                    def mutate(members):
                        for i, (member, data) in enumerate(members):
                            if member.name.endswith("/build-info.json"):
                                info = json.loads(data)
                                if case == "wrong_arch": info["arch"] = "arm64"
                                else: info["files"]["nocklock"] = "0" * 64
                                data = json.dumps(info).encode()
                                member.size = len(data)
                                members[i] = member, data
                    self.write(mutate)
                with self.assertRaises(ValueError): validate(self.archive, self.manifest, commit)

    def test_wrong_elf_even_with_matching_hash(self):
        self.files["libfence_fs.so"] = b"not an amd64 ELF"
        self.write()
        with self.assertRaises(ValueError): validate(self.archive, self.manifest, self.commit)


if __name__ == "__main__":
    unittest.main()
