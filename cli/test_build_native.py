"""Offline regression checks for the native builder's manifest boundary."""

import importlib.util
from pathlib import Path, PureWindowsPath
import unittest


SPEC = importlib.util.spec_from_file_location(
    "build_native", Path(__file__).resolve().parents[1] / "scripts" / "build-native.py"
)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ProvenanceTests(unittest.TestCase):
    def test_windows_paths_are_portable(self):
        path = PureWindowsPath(r"C:\resources\bin\Windows\hash.exe")
        relative = path.relative_to(PureWindowsPath(r"C:\resources"))
        self.assertEqual(builder.portable(relative), "bin/Windows/hash.exe")

    def test_inventory_is_only_cli_and_build_inputs(self):
        inventory = builder.source_inventory()
        self.assertIn("go.mod", inventory)
        self.assertIn("scripts/build-native.py", inventory)
        self.assertIn("cli/main.go", inventory)
        self.assertTrue(all(
            path.startswith("cli/") or path in {
                "go.mod", "LICENSE", "scripts/build-native.py",
                ".github/workflows/native.yml", "hash/Resources/licenses/Go-LICENSE.txt",
            } for path in inventory
        ))
        self.assertTrue(all(len(digest) == 64 for digest in inventory.values()))

    def test_local_offline_build_environment(self):
        self.assertEqual(builder.BUILD_ENV["GOTOOLCHAIN"], "local")
        self.assertEqual(builder.BUILD_ENV["CGO_ENABLED"], "0")
        self.assertEqual(builder.BUILD_ENV["GOPROXY"], "off")
        self.assertIn("-buildvcs=false", builder.BUILD_FLAGS)


if __name__ == "__main__":
    unittest.main()
