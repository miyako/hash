import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location(
    "release_inputs", Path(__file__).resolve().parents[1] / "scripts/verify-release-inputs.py")
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)


class ReleaseInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.revision = "a" * 40
        (self.root / "source").write_bytes(b"source")
        self.inputs = {"source": INPUTS.digest(b"source")}
        bundled = {"source_revision": self.revision, "source_input_status": [],
                   "source_inputs": self.inputs, "artifacts": {}}
        files = {"hash.4DZ": b"compiled"}
        for name, (target, resource) in INPUTS.HOSTS.items():
            contents = resource.encode()
            checksum = INPUTS.digest(contents)
            bundled["artifacts"][resource] = {"sha256": checksum}
            files["Resources/" + resource] = contents
            native = {"source_revision": self.revision, "source_input_status": [],
                      "source_inputs": self.inputs, "host": {"go_host": target},
                      "execution": [{"target": target, "status": "passed", "mode": "native"}],
                      "artifacts": {resource: {"sha256": checksum}},
                      "windows_arm64_x64_probe": {"status": "passed", "stdout": "arm64\n"}}
            directory = self.artifacts / name
            directory.mkdir(parents=True)
            (directory / "native-provenance.json").write_text(json.dumps(native))
            executable = directory / resource
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(contents)
        files["Resources/native-provenance.json"] = json.dumps(bundled).encode()
        self.component = self.artifacts / "component-verification"
        self.component.mkdir()
        self.archive = self.component / "hash.zip"
        with zipfile.ZipFile(self.archive, "w") as archive:
            for path, contents in files.items():
                archive.writestr("hash.4dbase/" + path, contents)
        inventory = {path: INPUTS.digest(contents) for path, contents in files.items()}
        self.manifest = {
            "source_revision": self.revision,
            "verification": {"sourceRevision": self.revision, "sourceDirty": False,
                             "installed": {"success": True}, "componentFiles": inventory},
            "component_files": inventory,
            "archive_sha256": INPUTS.digest(self.archive.read_bytes()),
        }
        self.save_manifest()
        for name in ("source-fixture", "component", "installed-host"):
            (self.component / f"{name}-compile.json").write_text(
                json.dumps({"success": True, "errors": []}))

    def save_manifest(self):
        (self.component / "provenance.json").write_text(json.dumps(self.manifest))

    def validate(self):
        return INPUTS.validate(self.artifacts, self.revision, self.root)

    def change_native(self, mutate, name="native-windows-11-arm"):
        path = self.artifacts / name / "native-provenance.json"
        native = json.loads(path.read_text())
        mutate(native)
        path.write_text(json.dumps(native))

    def test_complete_native_and_component_chain(self):
        directory, receipt = self.validate()
        self.assertEqual(directory, self.component)
        self.assertEqual(set(receipt["native_execution"]), set(INPUTS.HOSTS))

    def test_rejects_cross_build_receipt(self):
        self.change_native(lambda native: native["execution"][0].update(mode="cross"))
        with self.assertRaisesRegex(RuntimeError, "actual native execution"):
            self.validate()

    def test_rejects_failed_arm_bootstrap(self):
        self.change_native(lambda native: native["windows_arm64_x64_probe"].update(status="not-run"))
        with self.assertRaisesRegex(RuntimeError, "architecture probe"):
            self.validate()

    def test_rejects_wrong_revision(self):
        self.change_native(lambda native: native.update(source_revision="b" * 40))
        with self.assertRaisesRegex(RuntimeError, "Native source mismatch"):
            self.validate()

    def test_rejects_dirty_native_source(self):
        self.change_native(lambda native: native.update(source_input_status=["M source"]))
        with self.assertRaisesRegex(RuntimeError, "dirty inputs"):
            self.validate()

    def test_rejects_changed_native_executable(self):
        (self.artifacts / "native-windows-11-arm/bin/WindowsARM/hash.exe").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "artifact checksum mismatch"):
            self.validate()

    def test_rejects_changed_source_input(self):
        (self.root / "source").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "differs from checkout"):
            self.validate()

    def test_rejects_diagnostic_even_with_success(self):
        (self.component / "component-compile.json").write_text(
            json.dumps({"success": True, "errors": [{"message": "warning"}]}))
        with self.assertRaisesRegex(RuntimeError, "diagnostic-free"):
            self.validate()

    def test_rejects_modified_archive(self):
        with self.archive.open("ab") as archive:
            archive.write(b"changed")
        with self.assertRaisesRegex(RuntimeError, "archive checksum mismatch"):
            self.validate()

    def test_rejects_failed_installed_execution(self):
        self.manifest["verification"]["installed"]["success"] = False
        self.save_manifest()
        with self.assertRaisesRegex(RuntimeError, "successful installed execution"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
