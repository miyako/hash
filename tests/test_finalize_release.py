import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "finalize", Path(__file__).resolve().parents[1] / "scripts/finalize-release.py")
FINALIZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINALIZE)


class FinalizeRelease(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "signed"
        self.source.mkdir()
        (self.source / "hash.zip").write_bytes(b"final signed zip")
        (self.source / "component").mkdir()
        (self.source / "component/private-staging").write_bytes(b"not an asset")
        self.manifest = {"source_revision": "a" * 40, "component_files": {"hash.4DZ": "digest"},
                         "distribution_sha256": {"hash.zip": FINALIZE.sha256(self.source / "hash.zip")}}
        (self.source / "provenance.json").write_text(json.dumps(self.manifest))
        self.verification = self.root / "runtime.json"
        self.data = {"sourceRevision": "a" * 40, "sourceDirty": False,
                     "installed": {"success": True}, "componentFiles": {"hash.4DZ": "digest"}}
        self.save()
        self.report = self.root / "compile.json"
        self.report.write_text('{"success":true,"errors":[]}')
        self.output = self.root / "public"

    def save(self):
        self.verification.write_text(json.dumps(self.data))

    def finalize(self):
        FINALIZE.finalize(self.source, self.verification, self.report, self.output)

    def test_only_public_assets_and_bound_final_execution(self):
        self.finalize()
        self.assertFalse((self.output / "component").exists())
        manifest = json.loads((self.output / "provenance.json").read_text())
        self.assertEqual(manifest["signed_runtime_verification"]["sha256"],
                         FINALIZE.sha256(self.output / "signed-runtime-verification.json"))
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            checksum, name = line.split("  ", 1)
            self.assertNotIn("/", name)
            self.assertEqual(checksum, FINALIZE.sha256(self.output / name))

    def test_rejects_runtime_component_byte_mismatch(self):
        self.data["componentFiles"]["hash.4DZ"] = "changed"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "exact final component bytes"):
            self.finalize()

    def test_rejects_diagnostics_even_with_success(self):
        self.report.write_text('{"success":true,"errors":[{"message":"warning"}]}')
        with self.assertRaisesRegex(RuntimeError, "diagnostic-free"):
            self.finalize()

    def test_rejects_changed_signed_archive(self):
        (self.source / "hash.zip").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "changed after verification"):
            self.finalize()


if __name__ == "__main__":
    unittest.main()
