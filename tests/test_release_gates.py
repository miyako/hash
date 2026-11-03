import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "package_release", Path(__file__).resolve().parents[1] / "scripts/package-release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseGates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.component = self.root / "hash.4dbase"
        (self.component / "Resources").mkdir(parents=True)
        self.native = self.component / "Resources/native-provenance.json"
        artifacts = {}
        for path in ("bin/macOS/hash", "bin/Windows/hash.exe", "bin/WindowsARM/hash.exe"):
            binary = self.component / "Resources" / path
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(path.encode())
            artifacts[path] = {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        self.native.write_text(json.dumps({"source_revision": "a" * 40,
                                          "source_input_status": [], "artifacts": artifacts}))
        (self.component / "hash.4DZ").write_bytes(b"fixture")
        (self.root / "package.json").write_text(json.dumps({"version": "20.0.1"}))
        self.verification = self.root / "verification.json"
        self.data = {"sourceRevision": "a" * 40, "sourceDirty": False,
                     "installed": {"success": True}, "componentFiles": {
                         p.relative_to(self.component).as_posix():
                         hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in self.component.rglob("*") if p.is_file()}}
        self.save()
        for name in ("source-fixture", "component", "installed-host"):
            (self.root / f"{name}-compile.json").write_text(json.dumps({"success": True, "errors": []}))

    def save(self):
        self.verification.write_text(json.dumps(self.data))

    def package(self):
        arguments = ["package-release.py", "--verification", str(self.verification),
                     "--component", str(self.component), "--output", str(self.root / "release")]
        with patch.object(RELEASE, "ROOT", self.root), patch.object(sys, "argv", arguments):
            with patch.object(RELEASE.subprocess, "check_output",
                              side_effect=["a" * 40 + "\n", ""]):
                RELEASE.main()

    def test_success_and_portable_zip_paths(self):
        self.package()
        archive = self.root / "release/hash.zip"
        with zipfile.ZipFile(archive) as z:
            self.assertIn("hash.4dbase/hash.4DZ", z.namelist())
            self.assertTrue(all("\\" not in name for name in z.namelist()))
        manifest = json.loads((self.root / "release/provenance.json").read_text())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), manifest["archive_sha256"])

    def test_rejects_diagnostics_even_with_success(self):
        (self.root / "component-compile.json").write_text(json.dumps({
            "success": True, "errors": [{"isError": False, "message": "warning"}]}))
        with self.assertRaisesRegex(RuntimeError, "diagnostic-free"):
            self.package()

    def test_rejects_failed_runtime(self):
        self.data["installed"]["success"] = False
        self.save()
        with self.assertRaisesRegex(RuntimeError, "did not pass"):
            self.package()

    def test_rejects_different_source(self):
        self.data["sourceRevision"] = "b" * 40
        self.save()
        with self.assertRaisesRegex(RuntimeError, "clean source revision"):
            self.package()

    def test_rejects_dirty_verification(self):
        self.data["sourceDirty"] = True
        self.save()
        with self.assertRaisesRegex(RuntimeError, "clean source revision"):
            self.package()

    def test_rejects_changed_component_bytes(self):
        (self.component / "hash.4DZ").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "bytes changed"):
            self.package()

    def test_rejects_different_native_source(self):
        self.native.write_text(json.dumps({"source_revision": "b" * 40}))
        with self.assertRaisesRegex(RuntimeError, "does not match HEAD"):
            self.package()

    def test_rejects_corrupted_native_artifact(self):
        (self.component / "Resources/bin/Windows/hash.exe").write_bytes(b"corrupted")
        with self.assertRaisesRegex(RuntimeError, "Native artifact checksum mismatch"):
            self.package()

    def test_rejects_dirty_native_source(self):
        data = json.loads(self.native.read_text())
        data["source_input_status"] = [" M cli/main.go"]
        self.native.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, "dirty source inputs"):
            self.package()

    def test_rejects_incomplete_native_targets(self):
        data = json.loads(self.native.read_text())
        del data["artifacts"]["bin/WindowsARM/hash.exe"]
        self.native.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, "target set is incomplete"):
            self.package()


if __name__ == "__main__":
    unittest.main()
