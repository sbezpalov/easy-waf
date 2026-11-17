"""Exercise the snapshot stager through its CLI."""

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


STAGER = Path(__file__).resolve().with_name("lib") / "offline-crowdsec-snapshot.py"


@unittest.skipUnless(hasattr(os, "fwalk"), "requires POSIX directory descriptors")
class SnapshotTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        self.target = self.root / "destination"
        self.files = {
            "SNAPSHOT.env": b"CROWDSEC_CLI_VERSION=v1.8.2-3d369d64\nCROWDSEC_HUB_BRANCH=master\n",
            "setup.yaml": b"setup: []\n",
            "hub/.index.json": b"{}\n",
            "data/fixture.txt": b"fixture\n",
        }
        for name in ("linux", "haproxy", "sshd", "pgsql"):
            self.files[f"hub/collections/crowdsecurity/{name}.yaml"] = b"fixture\n"
        for name, contents in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        self.manifest = self.source / "SHA256SUMS"
        self.manifest.write_text(
            "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in self.files.items()),
            encoding="ascii",
        )

    def run_stage(self, version="1.8.2"):
        return subprocess.run(
            [sys.executable, "-I", str(STAGER), str(self.source), str(self.target), version],
            capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, reason, version="1.8.2"):
        result = self.run_stage(version)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(reason, result.stderr)
        self.assertFalse(self.target.exists())

    def test_valid_snapshot(self):
        result = self.run_stage("1:1.8.2-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / "SHA256SUMS").read_bytes(), self.manifest.read_bytes())
        for name, content in self.files.items():
            self.assertEqual((self.target / name).read_bytes(), content)

    def test_version_mismatch(self):
        self.assert_rejected("does not match", "1.8.3")

    def test_modified_file(self):
        (self.source / "data/fixture.txt").write_text("changed")
        self.assert_rejected("checksum mismatch")

    def test_missing_file(self):
        (self.source / "data/fixture.txt").unlink()
        self.assert_rejected("missing snapshot files")

    def test_unlisted_file(self):
        (self.source / "data/unlisted.txt").write_text("not in manifest")
        self.assert_rejected("unlisted snapshot file")

    def test_traversal_record(self):
        with self.manifest.open("a") as output:
            output.write(f"{'0' * 64}  data/../outside.txt\n")
        self.assert_rejected("unexpected or duplicate snapshot path")

    def test_symlink(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(self.files["data/fixture.txt"])
        path = self.source / "data/fixture.txt"
        path.unlink()
        path.symlink_to(outside)
        self.assert_rejected("snapshot rejected")


if __name__ == "__main__":
    unittest.main()
