#!/usr/bin/env python3
"""Package only after the actual 4D harness has completed successfully."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", type=Path, default=ROOT / "build/4d/verification.json")
    parser.add_argument("--component", type=Path, default=ROOT / "build/4d/dist/hash.4dbase")
    parser.add_argument("--output", type=Path, default=ROOT / "build/release")
    args = parser.parse_args()
    verification = json.loads(args.verification.read_text())
    if verification["installed"]["success"] is not True:
        raise RuntimeError("Installed component verification did not pass")
    for name in ("source-fixture", "component", "installed-host"):
        report = json.loads((args.verification.parent / f"{name}-compile.json").read_text())
        if report.get("success") is not True or report.get("errors"):
            raise RuntimeError(f"Compilation was not diagnostic-free: {name}")
    native = json.loads((args.component / "Resources/native-provenance.json").read_text())
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if verification["sourceRevision"] != revision or verification["sourceDirty"]:
        raise RuntimeError("4D verification must describe this clean source revision")
    if native["source_revision"] != revision:
        raise RuntimeError("Native artifact source revision does not match HEAD")
    if native.get("source_input_status"):
        raise RuntimeError("Native artifacts were built from dirty source inputs")
    expected_artifacts = {"bin/macOS/hash", "bin/Windows/hash.exe", "bin/WindowsARM/hash.exe"}
    if set(native["artifacts"]) != expected_artifacts:
        raise RuntimeError("Native target set is incomplete or unexpected")
    for path, artifact in native["artifacts"].items():
        if sha256(args.component / "Resources" / path) != artifact["sha256"]:
            raise RuntimeError(f"Native artifact checksum mismatch: {path}")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"],
                               cwd=ROOT, text=True).strip():
        raise RuntimeError("Release requires a clean source checkout")
    version = json.loads((ROOT / "package.json").read_text())["version"]
    inventory = {p.relative_to(args.component).as_posix(): sha256(p)
                 for p in sorted(args.component.rglob("*")) if p.is_file()}
    if inventory != verification["componentFiles"]:
        raise RuntimeError("Component bytes changed after installed-host verification")
    manifest = {"version": version, "source_revision": revision,
                "verification": verification, "component_files": inventory,
                "signing": "No Developer ID signing or notarization; native Go ad-hoc signatures only."}
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / "hash.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(args.component, args.component.name + "/")
        for path in sorted(args.component.rglob("*")):
            z.write(path, (Path(args.component.name) / path.relative_to(args.component)).as_posix())
    manifest["archive_sha256"] = sha256(archive)
    (args.output / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output / "SHA256SUMS").write_text(
        f"{sha256(archive)}  hash.zip\n"
        f"{sha256(args.output / 'provenance.json')}  provenance.json\n")
    print(f"{version} {revision}\n{sha256(archive)}  {archive}")


if __name__ == "__main__":
    main()
