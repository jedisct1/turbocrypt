"""Check malformed archives and publication preconditions without publishing."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "macos_release", Path(__file__).resolve().parents[1] / "scripts/macos_release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, entries):
        archive = self.root / "test.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for name, value in entries:
                member = tarfile.TarInfo(name)
                if value is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/bin/echo"
                    bundle.addfile(member)
                else:
                    member.size = len(value)
                    bundle.addfile(member, io.BytesIO(value))
        return archive

    def test_reject_duplicate_executables(self):
        archive = self.archive([("turbocrypt", b"one"), ("turbocrypt", b"two")])
        with self.assertRaisesRegex(ValueError, "exactly one regular turbocrypt"):
            release.inspect_archive(archive, "1.0.0")

    def test_reject_symlink_executable(self):
        archive = self.archive([("turbocrypt", None)])
        with self.assertRaisesRegex(ValueError, "exactly one regular turbocrypt"):
            release.inspect_archive(archive, "1.0.0")

    def test_reject_metadata_version_mismatch(self):
        archive = self.archive([
            ("turbocrypt", b"binary"),
            ("BUILD-INFO.json", json.dumps({"version": "0.9.0"}).encode()),
        ])
        with patch.object(release, "verify_binary"):
            with self.assertRaisesRegex(ValueError, "wrong version"):
                release.inspect_archive(archive, "1.0.0")

    def test_reject_missing_rebuild_sources(self):
        archive = self.archive([
            ("turbocrypt", b"binary"),
            ("BUILD-INFO.json", json.dumps({"version": "1.0.0"}).encode()),
        ])
        with patch.object(release, "verify_binary"):
            with self.assertRaisesRegex(ValueError, "missing rebuild sources"):
                release.inspect_archive(archive, "1.0.0")

    def test_do_not_publish_stale_formula(self):
        (self.root / "Formula").mkdir()
        (self.root / "Formula/turbocrypt.rb").write_text("outdated formula")
        with patch.object(release, "inspect_archive", return_value={"source_dirty": False}):
            with patch.object(release, "sha256", return_value="a" * 64):
                with self.assertRaisesRegex(ValueError, "doesn't match the archive"):
                    release.publish(self.root, "1.0.0")

    def test_preserve_git_status_leading_space(self):
        with patch.object(release.subprocess, "check_output", return_value=" M Formula/turbocrypt.rb\n"):
            self.assertEqual(release.output("git", "status"), " M Formula/turbocrypt.rb")


if __name__ == "__main__":
    unittest.main()
