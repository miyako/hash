#!/usr/bin/env python3
"""Bind signed-component execution and stage only public release assets."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def finalize(source, verification_path, report_path, destination):
    manifest = json.loads((source / "provenance.json").read_text())
    verification = json.loads(verification_path.read_text())
    report = json.loads(report_path.read_text())
    if report.get("success") is not True or report.get("errors"):
        raise RuntimeError("Signed installed-host compilation was not diagnostic-free")
    if (verification.get("sourceRevision") != manifest["source_revision"]
            or verification.get("sourceDirty")
            or verification.get("installed", {}).get("success") is not True
            or verification.get("componentFiles") != manifest["component_files"]):
        raise RuntimeError("Signed runtime must bind clean source and exact final component bytes")
    for name, checksum in manifest["distribution_sha256"].items():
        if sha256(source / name) != checksum:
            raise RuntimeError(f"Signed distribution changed after verification: {name}")
    destination.mkdir(parents=True, exist_ok=False)
    for path in source.iterdir():
        if path.is_file() and path.name not in {"SHA256SUMS", "provenance.json"}:
            shutil.copy2(path, destination / path.name)
    shutil.copy2(verification_path, destination / "signed-runtime-verification.json")
    shutil.copy2(report_path, destination / "signed-host-compile.json")
    manifest["signed_runtime_verification"] = {
        "path": "signed-runtime-verification.json",
        "sha256": sha256(destination / "signed-runtime-verification.json"),
        "host_compile": {"path": "signed-host-compile.json",
                         "sha256": sha256(destination / "signed-host-compile.json")},
    }
    (destination / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (destination / "SHA256SUMS").write_text("".join(
        f"{sha256(path)}  {path.name}\n" for path in sorted(destination.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=ROOT / "build/signed-release")
    parser.add_argument("--verification", type=Path, default=ROOT / "build/4d/verification.json")
    parser.add_argument("--compile-report", type=Path, default=ROOT / "build/4d/installed-host-compile.json")
    parser.add_argument("--output", type=Path, default=ROOT / "build/publish-files")
    args = parser.parse_args()
    finalize(args.input, args.verification, args.compile_report, args.output)


if __name__ == "__main__":
    main()
