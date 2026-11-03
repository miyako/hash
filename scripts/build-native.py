#!/usr/bin/env python3
"""Build stdlib-only hash helpers and exact-byte, pre-distribution provenance.

Default (Darwin): python3 scripts/build-native.py [--source-revision REV]
Native CI subsets: --target macos | windows | windows-arm64
Only CLI/build inputs are inventoried; concurrent 4D edits are not build inputs.
No release, version bump, network access, signing or publication is performed.
macOS Go linker ad-hoc signatures, if present, are retained; later signing changes
artifact checksums and needs a separate final-byte inventory.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePath
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "hash" / "Resources"
GO_VERSION = "go1.25.1"
VERSION = "20.0.1"
BUILD_FLAGS = ["-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=-s -w -buildid="]
BUILD_ENV = {
    "GOTOOLCHAIN": "local",
    "CGO_ENABLED": "0",
    "GOWORK": "off",
    "GOPROXY": "off",
    "GOSUMDB": "off",
    "GOENV": "off",
    "GOFLAGS": "",
    "GOEXPERIMENT": "",
    "GOAMD64": "v1",
    "GOARM64": "v8.0",
}


def portable(path: PurePath) -> str:
    return path.as_posix()


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command(args, *, env=None, timeout=180):
    return subprocess.check_output(
        [str(arg) for arg in args], cwd=ROOT, env=env, timeout=timeout
    ).decode("utf-8").strip()


def source_inventory():
    paths = [
        ROOT / "go.mod",
        ROOT / "LICENSE",
        ROOT / "scripts" / "build-native.py",
        ROOT / ".github" / "workflows" / "native.yml",
        RESOURCES / "licenses" / "Go-LICENSE.txt",
    ]
    paths += sorted((ROOT / "cli").rglob("*.go"))
    paths += sorted((ROOT / "cli").rglob("*.py"))
    return {portable(path.relative_to(ROOT)): checksum(path) for path in paths}


def smoke(binary: Path, prefix, target: str, fixture: Path):
    invocation = [*prefix, str(binary)]
    if command([*invocation, "--version"], timeout=30) != VERSION:
        raise RuntimeError(f"{target}: unexpected CLI version")
    if "Usage: hash" not in command([*invocation, "--help"], timeout=30):
        raise RuntimeError(f"{target}: missing CLI help")
    expected_arch = target.split()[0].split("/")[-1]
    if expected_arch == "x86_64":
        expected_arch = "amd64"
    architecture_result = subprocess.run(
        [*invocation, "--architecture"], capture_output=True, timeout=30, cwd=ROOT, check=True
    )
    if architecture_result.stdout != (expected_arch + "\n").encode("ascii") or architecture_result.stderr:
        raise RuntimeError(f"{target}: unexpected architecture output")
    result = subprocess.run(
        invocation,
        input=json.dumps({"path": str(fixture)}, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        timeout=30,
        cwd=ROOT,
        check=True,
    )
    expected = (checksum(fixture) + "\n").encode("ascii")
    if result.stdout != expected or result.stderr:
        raise RuntimeError(f"{target}: invalid digest or unexpected stderr")
    failure = subprocess.run(
        invocation, input=b'{"path":""}', capture_output=True, timeout=30, cwd=ROOT
    )
    if failure.returncode == 0 or failure.stdout or not failure.stderr:
        raise RuntimeError(f"{target}: invalid request did not fail cleanly")
    print(f"PASS execution {target}: version/architecture/help/binary digest/error contract", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["all", "macos", "windows", "windows-arm64"], default="all")
    parser.add_argument("--source-revision", help="source identifier; defaults to git HEAD")
    args = parser.parse_args()
    env = dict(os.environ, **BUILD_ENV)
    # Keep compiler/test intermediates in this checkout, not a system temp directory.
    scratch = ROOT / "build" / "native"
    scratch.mkdir(parents=True, exist_ok=True)
    env.update({key: str(scratch) for key in ("TMPDIR", "TMP", "TEMP", "GOTMPDIR")})
    env["GOCACHE"] = str(ROOT / "build" / "go-cache")
    actual_go = command(["go", "version"], env=env)
    if actual_go.split()[2] != GO_VERSION:
        raise RuntimeError(f"requires {GO_VERSION} with GOTOOLCHAIN=local, found {actual_go}")
    go_host = command(["go", "env", "GOHOSTOS", "GOHOSTARCH"], env=env).splitlines()
    goroot = Path(command(["go", "env", "GOROOT"], env=env))
    license_path = next(
        (path for path in [goroot / "LICENSE", goroot.parent / "LICENSE"] if path.is_file()),
        None,
    )
    if license_path is None or checksum(license_path) != checksum(RESOURCES / "licenses" / "Go-LICENSE.txt"):
        raise RuntimeError("bundled Go license must match the installed pinned toolchain")
    revision = args.source_revision or command(["git", "rev-parse", "HEAD"])
    inputs = source_inventory()
    dirty_inputs = command(["git", "status", "--porcelain", "--", *inputs.keys()])
    targets = ["macos", "windows", "windows-arm64"] if args.target == "all" else [args.target]
    if "macos" in targets and sys.platform != "darwin":
        raise RuntimeError("macOS universal assembly requires Darwin and xcrun lipo")
    artifacts = {}
    execution = []
    windows_arm64_x64_probe = {
        "status": "not-run",
        "reason": "Windows ARM64 x64 --architecture probe requires native Windows ARM64 CI",
    }
    fixture = scratch / "日本語 ' ; $() & sample.bin"
    fixture.write_bytes(bytes(range(256)) * 300)
    try:
        for target in targets:
            if target == "macos":
                slices = []
                for arch in ["arm64", "amd64"]:
                    output = scratch / f"hash-darwin-{arch}"
                    command(["go", "build", *BUILD_FLAGS, "-o", output, "./cli"],
                            env=dict(env, GOOS="darwin", GOARCH=arch))
                    slices.append(output)
                output = RESOURCES / "bin" / "macOS" / "hash"
                output.parent.mkdir(parents=True, exist_ok=True)
                command(["xcrun", "lipo", "-create", *slices, "-output", output])
                arches = command(["xcrun", "lipo", "-archs", output]).split()
                if set(arches) != {"arm64", "x86_64"}:
                    raise RuntimeError(f"incorrect universal architectures: {arches}")
                output.chmod(0o755)
                target_names = ["darwin/arm64", "darwin/amd64"]
                native_arch = "arm64" if go_host == ["darwin", "arm64"] else "x86_64"
                smoke(output, ["/usr/bin/arch", "-" + native_arch], f"darwin/{native_arch} native", fixture)
                execution.append({"target": "darwin/" + ("amd64" if native_arch == "x86_64" else native_arch),
                                  "status": "passed", "mode": "native"})
                if native_arch == "arm64":
                    probe = subprocess.run(
                        ["/usr/bin/arch", "-x86_64", str(output), "--version"],
                        capture_output=True, timeout=30,
                    )
                    if probe.returncode == 0:
                        smoke(output, ["/usr/bin/arch", "-x86_64"], "darwin/amd64 Rosetta", fixture)
                        execution.append({"target": "darwin/amd64", "status": "passed", "mode": "Rosetta"})
                    elif b"Bad CPU type" in probe.stderr:
                        print("SKIP execution darwin/amd64: Rosetta unavailable", flush=True)
                        execution.append({"target": "darwin/amd64", "status": "not-run", "reason": "Rosetta unavailable"})
                    else:
                        raise RuntimeError(f"x86_64 execution failed: {probe.stderr!r}")
                else:
                    execution.append({"target": "darwin/arm64", "status": "not-run",
                                      "reason": "Intel host cannot execute arm64"})
            else:
                arch = "amd64" if target == "windows" else "arm64"
                directory = "Windows" if arch == "amd64" else "WindowsARM"
                output = RESOURCES / "bin" / directory / "hash.exe"
                output.parent.mkdir(parents=True, exist_ok=True)
                command(["go", "build", *BUILD_FLAGS, "-o", output, "./cli"],
                        env=dict(env, GOOS="windows", GOARCH=arch))
                target_names = ["windows/" + arch]
                native = sys.platform == "win32" and go_host == ["windows", arch]
                if sys.platform == "win32" and args.target != "all" and not native:
                    raise RuntimeError(f"native CI target windows/{arch} does not match Go host {go_host}")
                if native:
                    smoke(output, [], "windows/" + arch + " native", fixture)
                    execution.append({"target": "windows/" + arch, "status": "passed", "mode": "native"})
                    if arch == "arm64":
                        probe_output = scratch / "hash-windows-amd64-probe.exe"
                        try:
                            command(["go", "build", *BUILD_FLAGS, "-o", probe_output, "./cli"],
                                    env=dict(env, GOOS="windows", GOARCH="amd64"))
                            probe = subprocess.run(
                                [str(probe_output), "--architecture"],
                                capture_output=True, timeout=30, cwd=ROOT, check=True,
                            )
                            if probe.stdout != b"arm64\n" or probe.stderr:
                                raise RuntimeError("Windows ARM64 x64 probe did not report arm64")
                            windows_arm64_x64_probe = {
                                "status": "passed", "mode": "x64 emulation on Windows ARM64",
                                "command": ["hash-windows-amd64-probe.exe", "--architecture"],
                                "stdout": "arm64\n",
                            }
                            print("PASS Windows ARM64 x64-emulated --architecture probe: arm64", flush=True)
                        finally:
                            probe_output.unlink(missing_ok=True)
                else:
                    print(f"NOT RUN execution windows/{arch}: cross-built only", flush=True)
                    execution.append({"target": "windows/" + arch, "status": "not-run",
                                      "reason": "not the native host OS/architecture"})
            artifacts[portable(output.relative_to(RESOURCES))] = {
                "sha256": checksum(output), "size": output.stat().st_size, "targets": target_names
            }
    finally:
        fixture.unlink(missing_ok=True)
    if source_inventory() != inputs:
        raise RuntimeError("CLI/build inputs changed during build; rerun from one source snapshot")
    manifest = {
        "schema_version": 1,
        "cli_version": VERSION,
        "source_revision": revision,
        "source_input_status": dirty_inputs.splitlines(),
        "source_inputs": inputs,
        "go_toolchain": actual_go,
        "build_flags": BUILD_FLAGS,
        "build_environment": BUILD_ENV,
        "host": {"os": platform.system(), "architecture": platform.machine(),
                 "go_host": "/".join(go_host)},
        "licenses": {
            "LICENSE": {"sha256": checksum(ROOT / "LICENSE"), "license": "MIT", "scope": "helper source"},
            "licenses/Go-LICENSE.txt": {"sha256": checksum(RESOURCES / "licenses" / "Go-LICENSE.txt"),
                                       "license": "BSD-3-Clause", "scope": "Go runtime and standard library"},
        },
        "checksum_stage": "after Go linking/universal assembly, before distribution signing",
        "execution": execution,
        "windows_arm64_x64_probe": windows_arm64_x64_probe,
        "artifacts": artifacts,
    }
    manifest_path = RESOURCES / "native-provenance.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for path, metadata in artifacts.items():
        print(f"SHA256 {path} {metadata['sha256']}", flush=True)
    print(f"Provenance: {manifest_path.relative_to(ROOT)}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"build-native: {error}", file=sys.stderr)
        sys.exit(1)
