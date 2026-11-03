#!/usr/bin/env python3
"""Compile and exercise isolated source and installed component fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "4d"


def run_engine(engine, project, method, config):
    parameter = project.parent / f"{method}-config.json"
    parameter.write_text(json.dumps(config), encoding="utf-8")
    command = [str(engine), "--project", str(project), "--startup-method", method,
               "--user-param", str(parameter), "--dataless", "--skip-onstartup"]
    if engine.name != "tool4d":
        command.append("--headless")
    key = hashlib.sha256(str(project).encode("utf-8")).hexdigest()[:12]
    execution = BUILD / "executions" / f"{method}-{key}.json"
    execution.parent.mkdir(parents=True, exist_ok=True)
    execution.unlink(missing_ok=True)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        execution.write_text(json.dumps({"command": command, "timedOut": True}) + "\n")
        raise
    execution.write_text(json.dumps({"command": command, "returnCode": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr,
                                     "timedOut": False}, indent=2) + "\n")
    print(result.stdout, end="")
    if result.returncode:
        raise RuntimeError(f"4D exited {result.returncode}: {result.stderr}")
    return result


def compile_project(engine, project, name, components=()):
    report = BUILD / f"{name}-compile.json"
    report.unlink(missing_ok=True)
    driver = BUILD / f"compiler-{name}"
    if driver.exists():
        shutil.rmtree(driver)
    shutil.copytree(ROOT / "tests/compiler/Project", driver / "Project",
                    ignore=shutil.ignore_patterns("DerivedData", "*-config.json", "*-execution.json"))
    run_engine(engine, driver / "Project/compiler.4DProject",
               "compile_hash", {"project": str(project), "report": str(report),
                                "components": [str(p) for p in components]})
    data = json.loads(report.read_text())
    if data.get("success") is not True or data.get("errors"):
        raise RuntimeError(f"Compilation failed or has diagnostics: {report}\n{data}")
    print(f"Compiled without diagnostics: {name}")
    return report


def project_at(folder, name="host"):
    project = folder / "Project" / f"{name}.4DProject"
    project.parent.mkdir(parents=True, exist_ok=True)
    project.write_text(json.dumps({"compatibilityVersion": 2007, "tokenizedText": False}))
    return project


def fixtures(folder):
    resources = folder / "Resources"
    resources.mkdir(parents=True, exist_ok=True)
    cases = []
    for name, content in [
        ("empty", b""), ("abc", b"abc"), ("binary", bytes(range(256)) * 17),
        ("same-size", b"one"), ("unicode-\u65e5\u672c ' \" $ & ; %.bin", b"\x00\xffbinary"),
    ]:
        if os.name == "nt":
            name = name.replace('"', "")
        file = resources / name
        file.write_bytes(content)
        cases.append({"name": name, "path": str(file), "digest": hashlib.sha256(content).hexdigest()})
    missing = resources / "missing"
    cases.append({"name": "missing", "path": str(missing), "failure": True})
    unreadable = resources / "unreadable"
    unreadable.write_bytes(b"unreadable")
    unreadable.chmod(0)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        if os.name != "nt":
            cases.append({"name": "unreadable", "path": str(unreadable), "failure": True})
    return cases


def test_source(engine, source):
    fixture = BUILD / "source-fixture"
    if fixture.exists():
        shutil.rmtree(fixture)
    shutil.copytree(source, fixture, ignore=shutil.ignore_patterns("DerivedData", "Libraries", "Logs", "Settings", "userPreferences.*"))
    methods = fixture / "Project/Sources/Methods"
    classes = fixture / "Project/Sources/Classes"
    shutil.copy2(ROOT / "tests/source/test_source.4dm", methods / "test_source.4dm")
    shutil.copy2(ROOT / "tests/source/ConstructorFailure.4dm", classes / "ConstructorFailure.4dm")
    compile_project(engine, fixture / "Project/hash.4DProject", "source-fixture")
    config = {"report": str(fixture / "source-results.json")}
    run_engine(engine, fixture / "Project/hash.4DProject", "test_source", config)
    report = json.loads(Path(config["report"]).read_text())
    if report.get("success") is not True:
        raise RuntimeError(f"Source fixture failed: {report}")
    print("Source error/timeout/malformed-output fixtures passed")
    return report


def package(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "hash.4DZ"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(source / "Project", "Project/")
        for path in sorted((source / "Project").rglob("*")):
            relative = path.relative_to(source)
            if not any(p in {"Classes", "Methods", "Trash"} for p in relative.parts):
                if path.suffix not in {".log", ".jsonl"}:
                    z.write(path, relative.as_posix())
    shutil.copytree(source / "Resources", destination / "Resources")
    libraries = source / "Libraries"
    if libraries.exists():
        shutil.copytree(libraries, destination / "Libraries")
    shutil.copy2(ROOT / "LICENSE", destination / "LICENSE")
    return archive


def test_installed(engine, component):
    host = BUILD / "installed host ' \" quotes $ &"
    staging = BUILD / "installed-host-compilation"
    if host.exists():
        shutil.rmtree(host)
    if staging.exists():
        shutil.rmtree(staging)
    project = project_at(staging)
    installed = staging / "Components/hash.4dbase"
    installed.parent.mkdir(parents=True)
    shutil.copytree(component, installed)
    methods = project.parent / "Sources/Methods"
    methods.mkdir(parents=True)
    shutil.copy2(ROOT / "tests/host/test_installed.4dm", methods / "test_installed.4dm")
    compile_project(engine, project, "installed-host", [installed / "hash.4DZ"])
    # 4D's clang invocation cannot compile paths containing literal quotes.
    # Move the compiled host afterward to verify hostile runtime resource paths.
    staging.rename(host)
    project = host / "Project/host.4DProject"
    installed = host / "Components/hash.4dbase"
    cases = fixtures(host)
    report = host / "installed-results.json"
    report.unlink(missing_ok=True)
    run_engine(engine, project, "test_installed",
               {"report": str(report), "cases": cases,
                "expectedExecutable": str(installed / "Resources/bin/macOS/hash")})
    result = json.loads(report.read_text())
    (BUILD / "installed-results.json").write_text(json.dumps(result, indent=2) + "\n")
    if result.get("success") is not True:
        raise RuntimeError(f"Installed host failed: {result}")
    print(f"Installed component fixture passed: {report}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--component", type=Path, help="Test an already packaged component only")
    parser.add_argument("--output", type=Path, default=BUILD / "dist/hash.4dbase")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD / "verification.json").unlink(missing_ok=True)
    engine = args.engine.resolve()
    version = subprocess.run([str(engine), "--version"], check=True, capture_output=True,
                             text=True, timeout=15).stdout.strip()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True).strip())
    if args.component:
        result = test_installed(engine, args.component.resolve())
    else:
        source = BUILD / "release-source"
        if source.exists():
            shutil.rmtree(source)
        shutil.copytree(ROOT / "hash", source,
                        ignore=shutil.ignore_patterns("DerivedData", "Libraries", "Logs", "Settings", "userPreferences.*"))
        test_source(engine, source)
        compile_project(engine, source / "Project/hash.4DProject", "component")
        if args.output.exists():
            shutil.rmtree(args.output)
        package(source, args.output)
        # Installed execution must not be able to resolve anything through the source project.
        hidden = source.with_name("release-source-unavailable")
        source.rename(hidden)
        try:
            result = test_installed(engine, args.output)
        finally:
            hidden.rename(source)
    component = args.component.resolve() if args.component else args.output.resolve()
    summary = {"engine": version, "enginePath": str(engine),
               "engineSha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
               "installed": result, "sourceRevision": revision, "sourceDirty": dirty,
               "componentFiles": {
                   p.relative_to(component).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(component.rglob("*")) if p.is_file()},
               "compatibilityTarget": 2007, "exact20_7Tested": False}
    (BUILD / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(version)


if __name__ == "__main__":
    main()
