#!/usr/bin/env python3
"""Bind same-run native execution receipts to the verified pre-sign component."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
HOSTS = {
    "native-macos-15-intel": ("darwin/amd64", "bin/macOS/hash"),
    "native-macos-15": ("darwin/arm64", "bin/macOS/hash"),
    "native-windows-2025": ("windows/amd64", "bin/Windows/hash.exe"),
    "native-windows-11-arm": ("windows/arm64", "bin/WindowsARM/hash.exe"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def one(folder, name):
    matches = list(folder.rglob(name))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {name} under {folder}")
    return matches[0]


def validate(artifacts, revision, root=ROOT):
    component = artifacts / "component-verification"
    manifest_path = one(component, "provenance.json")
    manifest = json.loads(manifest_path.read_text())
    verification = manifest["verification"]
    if manifest["source_revision"] != revision or verification["sourceRevision"] != revision:
        raise RuntimeError("Component source revision does not match release source")
    if verification["sourceDirty"] or verification["installed"].get("success") is not True:
        raise RuntimeError("Component requires clean source and successful installed execution")
    if manifest["component_files"] != verification["componentFiles"]:
        raise RuntimeError("Component verification inventory differs from package inventory")
    for name in ("source-fixture", "component", "installed-host"):
        report = json.loads(one(component, f"{name}-compile.json").read_text())
        if report.get("success") is not True or report.get("errors"):
            raise RuntimeError(f"Compilation was not diagnostic-free: {name}")
    archive_path = manifest_path.parent / "hash.zip"
    if digest(archive_path.read_bytes()) != manifest["archive_sha256"]:
        raise RuntimeError("Pre-sign component archive checksum mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        files = {info.filename: digest(archive.read(info)) for info in archive.infolist()
                 if not info.is_dir()}
        expected = {"hash.4dbase/" + path: value
                    for path, value in manifest["component_files"].items()}
        if files != expected:
            raise RuntimeError("Pre-sign component file inventory mismatch")
        bundled = json.loads(archive.read("hash.4dbase/Resources/native-provenance.json"))
    if bundled["source_revision"] != revision or bundled.get("source_input_status"):
        raise RuntimeError("Bundled native source must match clean release source")
    receipts = {}
    for name, (target, resource) in HOSTS.items():
        native_path = one(artifacts / name, "native-provenance.json")
        native = json.loads(native_path.read_text())
        if native["source_revision"] != revision or native.get("source_input_status"):
            raise RuntimeError(f"Native source mismatch or dirty inputs: {name}")
        if native["source_inputs"] != bundled["source_inputs"]:
            raise RuntimeError(f"Native build input mismatch: {name}")
        for path, checksum in native["source_inputs"].items():
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root.resolve()) or digest(resolved.read_bytes()) != checksum:
                raise RuntimeError(f"Native source input differs from checkout: {path}")
        if native["host"]["go_host"] != target or not any(
            item.get("target") == target and item.get("status") == "passed"
            and item.get("mode") == "native" for item in native["execution"]
        ):
            raise RuntimeError(f"Missing actual native execution: {name}")
        if target == "windows/arm64":
            probe = native["windows_arm64_x64_probe"]
            if probe.get("status") != "passed" or probe.get("stdout") != "arm64\n":
                raise RuntimeError("Missing x64-emulated Windows ARM64 architecture probe")
        checksum = native["artifacts"][resource]["sha256"]
        if digest((native_path.parent / resource).read_bytes()) != checksum:
            raise RuntimeError(f"Native execution artifact checksum mismatch: {name}")
        if bundled["artifacts"][resource]["sha256"] != checksum:
            raise RuntimeError(f"Bundled executable differs from native-tested bytes: {name}")
        receipts[name] = native
    return manifest_path.parent, {
        "source_revision": revision,
        "pre_sign_archive_sha256": manifest["archive_sha256"],
        "native_execution": receipts,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, default=ROOT / "build/release-inputs")
    parser.add_argument("--output", type=Path, default=ROOT / "build/release")
    args = parser.parse_args()
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True).strip():
        raise RuntimeError("Release requires a clean source checkout")
    source, receipt = validate(args.artifacts, revision)
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("hash.zip", "provenance.json", "SHA256SUMS"):
        shutil.copy2(source / name, args.output / name)
    (args.output / "native-verification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified all four native hosts and actual 4D compilation/runtime at {revision}")


if __name__ == "__main__":
    main()
