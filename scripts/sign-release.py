#!/usr/bin/env python3
"""Sign the gated pre-release on macOS; never publish or change the login keychain.

Usage: python3 scripts/sign-release.py [--input build/release]
       [--output build/signed-release] [--notary-timeout 1200]
       python3 scripts/sign-release.py --cleanup

Requires APPLE_DEVELOPER_ID_CERTIFICATE (base64 P12),
APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD, KEYCHAIN_PASSWORD,
NOTARYTOOL_APPLE_ID, NOTARYTOOL_PASSWORD, NOTARYTOOL_TEAM_ID.
RUNNER_TEMP must name an existing runner-owned directory. Private files use the
fixed directory $RUNNER_TEMP/hash-release-signing: identity.p12,
release.keychain-db, and home/ (isolated HOME and CFFIXED_USER_HOME).
The workflow must remove this directory in an always() cleanup step, including
on cancellation. If deleting the keychain with security, set both HOME and
CFFIXED_USER_HOME to this directory's home/; never use the global search list.
Normal execution removes it in finally; termination signals also trigger finally,
but a hard kill requires that independent workflow cleanup.
--cleanup needs RUNNER_TEMP but no secrets, and is idempotent.
Input native-verification.json is preserved as pre-sign-native-verification.json
and bound to the final provenance by SHA256.
The output directory must not exist. Only an output containing provenance.json
and SHA256SUMS is complete. Failed runs retain redacted receipts, not credentials.
Signed extracted payloads are component/hash.4dbase and standalone/hash.
This gate does not replace the subsequent real-4D signed-component runtime test.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import quote, quote_plus
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "APPLE_DEVELOPER_ID_CERTIFICATE", "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD",
    "KEYCHAIN_PASSWORD", "NOTARYTOOL_APPLE_ID", "NOTARYTOOL_PASSWORD",
    "NOTARYTOOL_TEAM_ID",
)
CLI = "Resources/bin/macOS/hash"
DYLIB = "Libraries/lib4d-arm64.dylib"
CODE = {CLI: {"arm64", "x86_64"}, DYLIB: {"arm64"}}
NATIVE = {"bin/macOS/hash", "bin/Windows/hash.exe", "bin/WindowsARM/hash.exe"}
NATIVE_HOSTS = {"native-macos-15-intel", "native-macos-15",
                "native-windows-2025", "native-windows-11-arm"}
MACHO = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
)}
STAPLE_BACKOFF = (5, 15)
STAPLE_ATTEMPT_TIMEOUT = 60
STAPLE_TOTAL_TIMEOUT = 180
TRANSIENT_URL_ERRORS = {-1001, -1003, -1004, -1005, -1006, -1009}


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha256(p)
            for p in sorted(folder.rglob("*")) if p.is_file()}


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class GateError(RuntimeError):
    pass


class Runner:
    """Keep arguments (some contain passwords) out of every log and exception."""

    def __init__(self, secrets, receipts):
        self.secrets = secrets
        self.receipts = receipts
        self.events = []
        self.home = None

    def redact(self, text):
        variants = set()
        for value in self.secrets.values():
            if value:
                variants.update((value, json.dumps(value)[1:-1],
                                 json.dumps(value, ensure_ascii=False)[1:-1],
                                 quote(value, safe=""), quote_plus(value, safe="")))
        for value in sorted(variants, key=len, reverse=True):
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def save(self):
        write_json(self.receipts, self.events)

    def run(self, label, command, timeout=120, isolate=True, stdin=None,
            binary=False, expected_returncode=0):
        environment = {k: v for k, v in os.environ.items() if k not in SECRET_NAMES}
        if self.home and isolate:
            # create-keychain adds to its user's search list. Isolate both the
            # Security HOME namespace and CFPreferences, not just the DB path.
            environment.update(HOME=str(self.home), CFFIXED_USER_HOME=str(self.home))
        try:
            options = {"capture_output": True, "text": not binary, "timeout": timeout,
                       "env": environment}
            if not binary:
                options["errors"] = "replace"
            if stdin is not None:
                options["input"] = stdin
            result = subprocess.run(
                [str(arg) for arg in command], **options)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode("utf-8", "replace") if isinstance(value, bytes) else value or ""
            self.events.append({"operation": label, "timed_out": True,
                                "stdout": self.redact(text(error.stdout)),
                                "stderr": self.redact(text(error.stderr))})
            self.save()
            raise GateError(f"{label} timed out") from None
        except OSError:
            raise GateError(f"{label} could not start") from None
        def display(value):
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
        self.events.append({"operation": label, "returncode": result.returncode,
                            "stdout": self.redact(display(result.stdout)),
                            "stderr": self.redact(display(result.stderr))})
        self.save()
        if result.returncode != expected_returncode:
            raise GateError(f"{label} failed; see signing-receipts.json")
        return result.stdout, result.stderr


def select_identity(output, team):
    identities = []
    for line in output.splitlines():
        match = re.fullmatch(r'\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"]+)"\s*', line)
        if match and match[2].startswith("Developer ID Application: ") and match[2].endswith(f" ({team})"):
            identities.append((match[1], match[2]))
    if len(identities) != 1:
        raise GateError("Expected exactly one valid Developer ID Application identity for the team")
    return identities[0]


def extract_component(archive, destination):
    """Extract only regular portable files; reject ambiguous or unsafe ZIPs."""
    seen = set()
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > 20000 or sum(item.file_size for item in members) > 512 * 1024 * 1024:
            raise GateError("Component ZIP exceeds extraction bounds")
        for item in members:
            name = item.filename
            parts = PurePosixPath(name).parts
            mode = item.external_attr >> 16
            if (not parts or parts[0] != "hash.4dbase"
                    or "\\" in name or name.startswith("/") or ":" in name
                    or any(p in {"", ".", ".."} for p in name.rstrip("/").split("/"))
                    or name.rstrip("/") in seen or item.flag_bits & 1
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (stat.S_ISDIR(mode) and not item.is_dir())):
                raise GateError("Unsafe or duplicate component ZIP entry")
            seen.add(name.rstrip("/"))
            target = destination.joinpath(*parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(item) as incoming, target.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                target.chmod(0o755 if mode & 0o111 else 0o644)
    return destination / "hash.4dbase"


def validate_input(archive, provenance, component, revision):
    if sha256(archive) != provenance.get("archive_sha256"):
        raise GateError("Pre-sign archive checksum mismatch")
    files = inventory(component)
    verification = provenance.get("verification", {})
    if (files != provenance.get("component_files")
            or files != verification.get("componentFiles")):
        raise GateError("Pre-sign component inventory mismatch")
    if (provenance.get("source_revision") != revision
            or verification.get("sourceRevision") != revision
            or verification.get("sourceDirty") is not False
            or verification.get("installed", {}).get("success") is not True):
        raise GateError("Pre-sign verification must describe this clean, tested revision")
    native = json.loads((component / "Resources/native-provenance.json").read_text())
    if (native.get("source_revision") != revision or native.get("source_input_status")
            or set(native.get("artifacts", {})) != NATIVE):
        raise GateError("Invalid source/native provenance")
    for path, artifact in native["artifacts"].items():
        if sha256(component / "Resources" / path) != artifact.get("sha256"):
            raise GateError("Pre-sign native checksum mismatch")
    validate_code_inventory(component)


def validate_code_inventory(component):
    found = set()
    for path in component.rglob("*"):
        if path.is_symlink():
            raise GateError("Symlinks are not permitted in the component")
        if path.is_file():
            with path.open("rb") as source:
                magic = source.read(4)
            if magic in MACHO:
                found.add(path.relative_to(component).as_posix())
    if found != set(CODE):
        raise GateError("Expected exactly the universal CLI and compiled arm64 4D dylib")


def verify_signature(runner, path, team, identity, architectures=None):
    runner.run("verify strict signature", [
        "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", path])
    results = {}
    for architecture in sorted(architectures or {None}, key=str):
        arch_args = ["--arch", architecture] if architecture else []
        stdout, stderr = runner.run("inspect signature", [
            "/usr/bin/codesign", "--display", "--verbose=4", *arch_args, path])
        details = stdout + "\n" + stderr
        fields = dict(re.findall(r"^([A-Za-z]+)=(.*)$", details, re.MULTILINE))
        authorities = re.findall(r"^Authority=(.+)$", details, re.MULTILINE)
        timestamp = fields.get("Timestamp", "").strip()
        cdhash = fields.get("CDHash", "").lower()
        if (fields.get("TeamIdentifier") != team or not authorities or authorities[0] != identity
                or not timestamp or timestamp.lower() in {"none", "not set"}
                or "Signature=adhoc" in details):
            raise GateError("Signature identity, team or secure timestamp mismatch")
        if (not re.fullmatch(r"[a-f0-9]{40}", cdhash)
                or not re.search(r"^Hash type=sha256(?:\s|$)", details, re.MULTILINE)):
            raise GateError("Expected a SHA-256 CodeDirectory hash for every signed object")
        if architecture:
            flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\(([^)]*)\)", details)
            if not flags or not int(flags[1], 16) & 0x10000 or "runtime" not in flags[2].split(","):
                raise GateError("Hardened runtime is required on every code slice")
            entitlements, _ = runner.run("inspect entitlements", [
                "/usr/bin/codesign", "--display", "--entitlements", ":-", *arch_args, path])
            if entitlements.strip():
                try:
                    empty = plistlib.loads(entitlements.encode()) == {}
                except (ValueError, plistlib.InvalidFileException):
                    empty = False
                if not empty:
                    raise GateError("Release code must not carry special entitlements")
        results[architecture or "container"] = {"team": team, "authority": identity,
                                                "timestamp": timestamp,
                                                "cdhash": cdhash,
                                                "hardened_runtime": bool(architecture)}
    return results


def validate_ticket_log(log, path, submission, expected_tickets):
    if (not isinstance(log, dict) or type(log.get("logFormatVersion")) is not int
            or log.get("logFormatVersion") != 1
            or str(log.get("jobId", "")).lower() != submission.lower()
            or log.get("status") != "Accepted" or type(log.get("statusCode")) is not int
            or log.get("statusCode") != 0
            or log.get("archiveFilename") != path.name or log.get("sha256") != sha256(path)
            or log.get("issues") not in (None, [])):
        raise GateError("Notary log identity, status, archive digest or diagnostics failed validation")
    contents = log.get("ticketContents")
    if not expected_tickets or not isinstance(contents, list) or not contents:
        raise GateError("Notary log has no required ticket coverage")
    observed = {}
    for item in contents:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or item.get("arch") not in (None, "arm64", "x86_64")
                or item.get("digestAlgorithm") != "SHA-256"
                or not isinstance(item.get("cdhash"), str)
                or not re.fullmatch(r"[a-fA-F0-9]{40}", item["cdhash"])):
            raise GateError("Malformed notarization ticket contents")
        key = (item["path"], item.get("arch"))
        cdhash = item["cdhash"].lower()
        if key in observed and observed[key] != cdhash:
            raise GateError("Conflicting notarization tickets for the same code slice")
        observed[key] = cdhash
    if observed != expected_tickets:
        raise GateError("Notary ticket coverage does not match every expected path/architecture/CDHash")
    return [{"path": name, "arch": arch, "cdhash": cdhash, "digestAlgorithm": "SHA-256"}
            for (name, arch), cdhash in sorted(observed.items(), key=lambda item: str(item[0]))]


def expected_ticket_contents(archive_name, payload, container=None):
    expected = {(f"{archive_name}/{relative}", architecture): receipt["cdhash"]
                for relative, slices in payload.items() for architecture, receipt in slices.items()}
    if container:
        expected[(archive_name, None)] = container["container"]["cdhash"]
    return expected


def notarize(runner, path, keychain, timeout, expected_tickets):
    authentication = ["--keychain-profile", "hash-release-notary", "--keychain", keychain]
    start = len(runner.events)
    failed = False
    try:
        stdout, _ = runner.run(f"notarize {path.name}", [
            "/usr/bin/xcrun", "notarytool", "submit", path, *authentication,
            "--wait", "--timeout", f"{timeout}s", "--output-format", "json"],
            timeout=timeout + 60)
    except GateError:
        failed = True
        # A nonzero exit/timeout may still include a submission ID and diagnostics.
        stdout = runner.events[-1].get("stdout", "") if len(runner.events) > start else ""
    try:
        result = json.loads(stdout)
    except (ValueError, TypeError):
        raise GateError(f"Notarization returned no valid JSON for {path.name}") from None
    if not isinstance(result, dict):
        raise GateError(f"Notarization returned no JSON object for {path.name}")
    submission = result.get("id")
    valid_id = isinstance(submission, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", submission)
    log_path = runner.receipts.parent / f"notary-{path.name}.json"

    def download_log(kind):
        stdout, _ = runner.run(f"notarization {kind} log {path.name}", [
            "/usr/bin/xcrun", "notarytool", "log", submission, *authentication], timeout=120)
        log_path.write_text(runner.redact(stdout) + "\n", encoding="utf-8")
        return stdout

    if failed or result.get("status") != "Accepted" or not valid_id:
        if valid_id:
            try:
                download_log("failure")
            except GateError:
                pass  # The submission remains failed even if Apple cannot return its log.
        raise GateError(f"Notarization was not Accepted for {path.name}")
    # Apple requires inspecting the downloaded log even for Accepted submissions.
    # Container acceptance alone does not establish nested code ticket coverage.
    raw_log = download_log("accepted")
    try:
        log = json.loads(raw_log)
    except ValueError:
        raise GateError("Accepted notarization returned a malformed log") from None
    coverage = validate_ticket_log(log, path, submission, expected_tickets)
    return {"id": submission, "status": "Accepted", "submitted_sha256": sha256(path),
            "log": {"path": log_path.name, "sha256": sha256(log_path)},
            "ticket_contents": coverage}


def transient_staple_network_error(event):
    if event.get("returncode") != 68 or event.get("timed_out"):
        return False
    diagnostics = event.get("stdout", "") + "\n" + event.get("stderr", "")
    codes = {int(code) for code in re.findall(
        r"\b(?:Error )?Domain=NSURLErrorDomain\s+Code=(-\d+)\b", diagnostics)}
    return bool(codes) and codes <= TRANSIENT_URL_ERRORS


def staple(runner, dmg):
    deadline = time.monotonic() + STAPLE_TOTAL_TIMEOUT
    attempts = len(STAPLE_BACKOFF) + 1
    for attempt in range(1, attempts + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"Stapling {dmg.name}: retry deadline exhausted", flush=True)
            raise GateError(f"Stapling {dmg.name} exceeded its retry deadline")
        timeout = min(STAPLE_ATTEMPT_TIMEOUT, remaining)
        print(f"Stapling {dmg.name}: attempt {attempt}/{attempts}, "
              f"timeout at most {timeout:.0f}s", flush=True)
        start = len(runner.events)
        try:
            runner.run(f"staple {dmg.name} (attempt {attempt}/{attempts})",
                       ["/usr/bin/xcrun", "stapler", "staple", dmg], timeout=timeout)
            if time.monotonic() > deadline:
                print(f"Stapling {dmg.name}: retry deadline exhausted", flush=True)
                raise GateError(f"Stapling {dmg.name} exceeded its retry deadline")
            return
        except GateError:
            if (len(runner.events) != start + 1
                    or not transient_staple_network_error(runner.events[-1])):
                print(f"Stapling {dmg.name} failed without a retryable network error; "
                      "see redacted signing-receipts.json", flush=True)
                raise
            if attempt == attempts:
                print(f"Stapling {dmg.name}: exhausted {attempts} transient-network attempts; "
                      "release remains blocked", flush=True)
                raise GateError(f"Stapling {dmg.name} exhausted {attempts} network attempts; "
                                "see redacted signing-receipts.json") from None
            delay = STAPLE_BACKOFF[attempt - 1]
            if deadline - time.monotonic() <= delay:
                print(f"Stapling {dmg.name}: insufficient time for another retry; "
                      "release remains blocked", flush=True)
                raise GateError(f"Stapling {dmg.name} has no retry time remaining") from None
            print(f"Stapling {dmg.name}: transient network failure, retrying in {delay}s; "
                  "attempt diagnostics retained in signing-receipts.json", flush=True)
            time.sleep(delay)


def assess_cli(runner, path):
    start = len(runner.events)
    try:
        runner.run("assess raw CLI execute", [
            "/usr/sbin/spctl", "--assess", "--verbose=4", "--type", "execute", path])
    except GateError:
        event = runner.events[-1] if len(runner.events) > start else {}
        diagnostic = (event.get("stdout", "") + "\n" + event.get("stderr", "")).lower()
        unsupported = "rejected (the code is valid but does not seem to be an app)"
        if (event.get("returncode") != 3 or unsupported not in diagnostic
                or any(error in diagnostic for error in (
                    "unnotarized", "not notarized", "invalid", "revoked", "malware", "not signed"))):
            raise
        # This is not a successful execute assessment. Non-app policy is checked
        # independently with codesign's notarized requirement and signed DMGs.
        return {"result": "unsupported_non_app_tool", "returncode": 3,
                "receipt_event": len(runner.events) - 1}
    return {"result": "accepted", "returncode": 0, "receipt_event": len(runner.events) - 1}


def smoke_cli(runner, binary, version, private):
    fixture = private / "smoke"
    fixture.mkdir()
    files = {"binary": fixture / "binary-日本語 ' $ &.bin", "empty": fixture / "empty.bin"}
    files["binary"].write_bytes(bytes(range(256)) * 257)
    files["empty"].write_bytes(b"")
    host = platform.machine().lower()
    if host in {"arm64", "aarch64"}:
        native_arch = "arm64"
    elif host in {"x86_64", "amd64"}:
        native_arch = "x86_64"
    else:
        raise GateError("Unsupported signed CLI smoke-test host architecture")
    results = []

    def run_slice(architecture, mode):
        prefix = ["/usr/bin/arch", "-" + architecture, binary]
        start = len(runner.events)
        expected_arch = "amd64" if architecture == "x86_64" else "arm64"
        for flag, expected in (("--version", (version + "\n").encode()),
                               ("--architecture", (expected_arch + "\n").encode())):
            stdout, stderr = runner.run(f"signed CLI {mode} {flag}", [*prefix, flag],
                                        timeout=30, binary=True)
            if stdout != expected or stderr:
                raise GateError("Signed CLI version/architecture contract failed")
        stdout, stderr = runner.run(f"signed CLI {mode} help", [*prefix, "--help"],
                                    timeout=30, binary=True)
        if b"Usage: hash" not in stdout or stderr:
            raise GateError("Signed CLI help contract failed")
        for name, path in files.items():
            stdout, stderr = runner.run(
                f"signed CLI {mode} {name} digest", prefix, timeout=30, binary=True,
                stdin=json.dumps({"path": str(path)}, ensure_ascii=False).encode("utf-8"))
            if stdout != (sha256(path) + "\n").encode("ascii") or stderr:
                raise GateError("Signed CLI exact-byte digest contract failed")
        for name, request in (
                ("empty-path", b'{"path":""}'), ("malformed", b"not JSON"),
                ("missing-file", json.dumps({"path": str(fixture / "missing")}).encode())):
            stdout, stderr = runner.run(
                f"signed CLI {mode} {name} error contract", prefix, timeout=30,
                binary=True, stdin=request, expected_returncode=1)
            if stdout or not stderr.startswith(b"hash: ") or not stderr.endswith(b"\n"):
                raise GateError("Signed CLI error output contract failed")
            if name == "empty-path" and stderr != b"hash: JSON request requires a nonempty path string\n":
                raise GateError("Signed CLI empty-path error contract failed")
        results.append({
            "architecture": architecture, "mode": mode, "status": "passed",
            "binary_sha256": sha256(binary),
            "fixture_sha256": {name: sha256(path) for name, path in files.items()},
            "checks": ["version", "architecture", "help", "binary_digest", "empty_digest",
                       "empty_path_error", "malformed_error", "missing_file_error"],
            "receipt_events": [start, len(runner.events) - 1],
        })

    run_slice(native_arch, "native")
    if native_arch == "arm64":
        start = len(runner.events)
        try:
            # Probe the environment, not our CLI: signing/launch errors must
            # never be mistaken for an unavailable Rosetta installation.
            runner.run("probe Rosetta availability",
                       ["/usr/bin/arch", "-x86_64", "/usr/bin/true"], timeout=30)
        except GateError:
            event = runner.events[-1] if len(runner.events) > start else {}
            if (not event.get("returncode")
                    or "bad cpu type in executable" not in event.get("stderr", "").lower()):
                raise
            results.append({"architecture": "x86_64", "mode": "Rosetta", "status": "not-run",
                            "reason": "System executable probe reports Rosetta unavailable",
                            "receipt_event": len(runner.events) - 1})
        else:
            run_slice("x86_64", "Rosetta")
    else:
        results.append({"architecture": "arm64", "status": "not-run",
                        "reason": "Intel host cannot execute arm64; separate ARM component gate required"})
    return results


def make_zip(folder, archive):
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as output:
        for path in sorted(folder.rglob("*")):
            output.write(path, path.relative_to(folder).as_posix())


def private_directory():
    if not os.environ.get("RUNNER_TEMP"):
        raise GateError("RUNNER_TEMP must name an existing runner-owned directory")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if not runner_temp.is_dir():
        raise GateError("RUNNER_TEMP must name an existing runner-owned directory")
    return runner_temp / "hash-release-signing"


def cleanup_release(output):
    """Credential-free recovery for the workflow's independent always() step."""
    private = private_directory()
    if private.is_symlink():
        raise GateError("Refusing a symlink at the private signing directory")
    if not private.exists():
        return
    if not private.is_dir():
        raise GateError("Private signing path is not a directory")
    keychain = private / "release.keychain-db"
    home = private / "home"
    if keychain.is_symlink() or home.is_symlink():
        raise GateError("Refusing symlinked private keychain paths")
    output.mkdir(parents=True, exist_ok=True)
    runner = Runner({name: os.environ.get(name, "") for name in SECRET_NAMES},
                    output / "cleanup-receipts.json")
    runner.home = home
    try:
        if keychain.exists():
            (home / "Library/Keychains").mkdir(parents=True, exist_ok=True)
            (home / "Library/Preferences").mkdir(parents=True, exist_ok=True)
            runner.run("delete abandoned ephemeral keychain",
                       ["/usr/bin/security", "delete-keychain", keychain])
    finally:
        shutil.rmtree(private)


def sign_release(source, output, secrets, notary_timeout):
    private = private_directory()
    # An existing private directory can belong to another active/stale operation.
    # Never reuse, overwrite or silently delete it; the workflow owns recovery.
    private.mkdir(mode=0o700)
    try:
        output.mkdir(parents=True, exist_ok=False)
    except BaseException:
        private.rmdir()
        raise
    runner = Runner(secrets, output / "signing-receipts.json")
    runner.home = private / "home"
    keychain = private / "release.keychain-db"
    p12 = private / "identity.p12"
    team = secrets["NOTARYTOOL_TEAM_ID"]
    signatures = {}
    submissions = {}
    payload_notarization = {}
    cli_assessments = {}
    cleanup_ok = False
    global_state = {}
    try:
        (runner.home / "Library/Keychains").mkdir(parents=True)
        (runner.home / "Library/Preferences").mkdir(parents=True)
        for operation in ("list-keychains", "default-keychain", "login-keychain"):
            global_state[operation] = runner.run(
                f"snapshot global {operation}", ["/usr/bin/security", operation], isolate=False)
        archive = source / "hash.zip"
        original = source / "provenance.json"
        provenance = json.loads(original.read_text())
        shutil.copyfile(original, output / "pre-sign-provenance.json")
        revision, _ = runner.run("resolve source revision", ["git", "-C", ROOT, "rev-parse", "HEAD"])
        component = extract_component(archive, output / "component")
        validate_input(archive, provenance, component, revision.strip())
        native_proof_path = source / "native-verification.json"
        native_proof = json.loads(native_proof_path.read_text())
        if (native_proof.get("source_revision") != revision.strip()
                or native_proof.get("pre_sign_archive_sha256") != provenance["archive_sha256"]
                or set(native_proof.get("native_execution", {})) != NATIVE_HOSTS):
            raise GateError("Native CI proof does not match the pre-sign release")
        shutil.copyfile(native_proof_path, output / "pre-sign-native-verification.json")
        for relative, expected in CODE.items():
            stdout, _ = runner.run("inspect code architectures", [
                "/usr/bin/lipo", "-archs", component / relative])
            if set(stdout.split()) != expected:
                raise GateError(f"Unexpected code architectures: {relative}")
        try:
            certificate = base64.b64decode(secrets["APPLE_DEVELOPER_ID_CERTIFICATE"], validate=True)
        except (ValueError, TypeError):
            raise GateError("Certificate is not valid base64") from None
        if not certificate:
            raise GateError("Certificate is empty")
        descriptor = os.open(p12, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(certificate)
        runner.run("create ephemeral keychain", [
            "/usr/bin/security", "create-keychain", "-p", secrets["KEYCHAIN_PASSWORD"], keychain])
        runner.run("set ephemeral keychain timeout", [
            "/usr/bin/security", "set-keychain-settings", "-lut", "21600", keychain])
        runner.run("unlock ephemeral keychain", [
            "/usr/bin/security", "unlock-keychain", "-p", secrets["KEYCHAIN_PASSWORD"], keychain])
        runner.run("import signing certificate", [
            "/usr/bin/security", "import", p12, "-k", keychain, "-P",
            secrets["APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD"],
            "-T", "/usr/bin/codesign", "-T", "/usr/bin/security"])
        p12.unlink()
        runner.run("authorize ephemeral private key", [
            "/usr/bin/security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
            "-s", "-k", secrets["KEYCHAIN_PASSWORD"], keychain])
        # codesign's private-key lookup still requires a search-list entry even
        # with --keychain; only the isolated HOME/CFPreferences domain is changed.
        runner.run("configure isolated keychain search list", [
            "/usr/bin/security", "list-keychains", "-d", "user", "-s",
            keychain, "/Library/Keychains/System.keychain"])
        identities, _ = runner.run("select signing identity", [
            "/usr/bin/security", "find-identity", "-v", "-p", "codesigning", keychain])
        fingerprint, identity = select_identity(identities, team)
        for relative in (DYLIB, CLI):
            path = component / relative
            runner.run(f"sign {relative}", [
                "/usr/bin/codesign", "--force", "--sign", fingerprint,
                "--keychain", keychain, "--options", "runtime", "--timestamp", path])
            signatures[relative] = verify_signature(runner, path, team, identity, CODE[relative])
        before = provenance["component_files"]
        after = inventory(component)
        if (set(before) != set(after)
                or {p for p in before if before[p] != after[p]} != set(CODE)):
            raise GateError("Signing must change exactly the two expected code objects")
        standalone = output / "standalone"
        standalone.mkdir()
        shutil.copy2(component / CLI, standalone / "hash")
        signatures["standalone/hash"] = verify_signature(
            runner, standalone / "hash", team, identity, CODE[CLI])
        runner.run("store ephemeral notarization profile", [
            "/usr/bin/xcrun", "notarytool", "store-credentials", "hash-release-notary",
            "--keychain", keychain, "--validate",
            "--apple-id", secrets["NOTARYTOOL_APPLE_ID"],
            "--password", secrets["NOTARYTOOL_PASSWORD"],
            "--team-id", team], timeout=120)
        make_zip(output / "component", output / "hash.zip")
        make_zip(standalone, output / "hash-cli-macOS.zip")
        component_payload = {f"hash.4dbase/{relative}": signatures[relative] for relative in CODE}
        standalone_payload = {"hash": signatures["standalone/hash"]}
        for name, payload in (("hash.zip", component_payload),
                              ("hash-cli-macOS.zip", standalone_payload)):
            submissions[name] = notarize(
                runner, output / name, keychain, notary_timeout, expected_ticket_contents(name, payload))
        for folder, name in ((output / "component", "hash.dmg"),
                             (standalone, "hash-cli-macOS.dmg")):
            dmg = output / name
            runner.run(f"create {name}", [
                "/usr/bin/hdiutil", "create", "-srcfolder", folder,
                "-volname", name.removesuffix(".dmg"), "-fs", "HFS+", "-format", "UDZO", dmg],
                timeout=300)
            runner.run(f"sign {name}", [
                "/usr/bin/codesign", "--force", "--sign", fingerprint,
                "--keychain", keychain, "--timestamp", dmg])
            signatures[name] = verify_signature(runner, dmg, team, identity)
            payload = component_payload if folder == output / "component" else standalone_payload
            submissions[name] = notarize(runner, dmg, keychain, notary_timeout,
                                        expected_ticket_contents(name, payload, signatures[name]))
            staple(runner, dmg)
            runner.run(f"validate staple {name}", ["/usr/bin/xcrun", "stapler", "validate", dmg])
            stapled_signature = verify_signature(runner, dmg, team, identity)
            if stapled_signature != signatures[name]:
                raise GateError("DMG signature/CDHash changed while stapling")
            runner.run(f"Gatekeeper {name}", [
                "/usr/sbin/spctl", "--assess", "--verbose=4", "--type", "open",
                "--context", "context:primary-signature", dmg])
        # Apple DTS, Testing a Notarised Product, "Other code":
        # https://developer.apple.com/forums/thread/130560
        for path in (component / DYLIB, component / CLI, standalone / "hash"):
            relative = path.relative_to(output).as_posix()
            runner.run(f"require notarized code {relative}", [
                "/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
                "--check-notarization", "-R=notarized", path])
            payload_notarization[relative] = {
                "strict_all_architectures": True, "notarized_requirement": True,
                "receipt_event": len(runner.events) - 1}
        for cli in (component / CLI, standalone / "hash"):
            cli_assessments[cli.relative_to(output).as_posix()] = assess_cli(runner, cli)
        cli_execution = smoke_cli(runner, standalone / "hash", provenance["version"], private)
        if inventory(component) != after or inventory(standalone) != {"hash": after[CLI]}:
            raise GateError("Payload changed after signature verification")
    finally:
        try:
            if keychain.exists():
                runner.run("delete ephemeral keychain", ["/usr/bin/security", "delete-keychain", keychain])
            for operation, expected in global_state.items():
                actual = runner.run(f"verify global {operation} unchanged",
                                    ["/usr/bin/security", operation], isolate=False)
                if actual != expected:
                    raise GateError("Global keychain settings changed during signing")
            cleanup_ok = True
        finally:
            p12.unlink(missing_ok=True)
            # Do not silently leave a private key behind if security cleanup failed.
            shutil.rmtree(private)
        if not cleanup_ok:
            raise GateError("Ephemeral keychain cleanup failed")
    manifest = {
        "version": provenance["version"], "source_revision": revision.strip(),
        "pre_sign_provenance": {"path": "pre-sign-provenance.json",
                                "sha256": sha256(output / "pre-sign-provenance.json")},
        "pre_sign_native_verification": {
            "path": "pre-sign-native-verification.json",
            "sha256": sha256(output / "pre-sign-native-verification.json")},
        "component_files": inventory(component), "standalone_files": inventory(standalone),
        "signatures": signatures, "notarization": submissions,
        "payload_notarization": payload_notarization,
        "cli_execute_assessments": cli_assessments,
        "signed_cli_execution": cli_execution,
        "distribution_sha256": {name: sha256(output / name) for name in submissions},
        "signing_receipts_sha256": sha256(output / "signing-receipts.json"),
        "coverage": {
            "zip_tickets": "Both ZIPs separately Accepted; ZIPs and raw CLI cannot be stapled.",
            "offline_tickets": "Both DMGs signed, separately Accepted, stapled and validated.",
            "ticket_coverage": "Downloaded logs bind every payload slice CDHash and both DMG signatures.",
            "gatekeeper": "Both DMG open assessments passed; raw CLI execute outcomes recorded separately.",
            "non_app_code": "Both CLI copies and dylib require strict all-architecture notarized code checks.",
            "runtime": "Signed-component real-4D execution is a separate required downstream gate.",
            "standalone_runtime": "Signed CLI contract tested natively and under Rosetta when available.",
            "native_provenance": "Embedded native provenance describes pre-sign bytes; use final inventories.",
        },
    }
    write_json(output / "provenance.json", manifest)
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest}  {path}\n" for path, digest in inventory(output).items()), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "build/release")
    parser.add_argument("--output", type=Path, default=ROOT / "build/signed-release")
    parser.add_argument("--cleanup", action="store_true",
                        help="Remove fixed RUNNER_TEMP private state; no secrets required")
    parser.add_argument("--notary-timeout", type=int, default=1200,
                        help="Seconds per submission, 60..3600 (four submissions)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Developer ID signing requires macOS")
    if args.cleanup:
        try:
            cleanup_release(args.output.resolve())
        except Exception:
            print("Private signing cleanup failed; no credentials or command arguments are logged.",
                  file=sys.stderr)
            return 1
        print("Private signing cleanup complete")
        return 0
    if not 60 <= args.notary_timeout <= 3600:
        parser.error("--notary-timeout must be between 60 and 3600 seconds")
    secrets = {name: os.environ.get(name, "") for name in SECRET_NAMES}
    if not all(secrets.values()) or not re.fullmatch(r"[A-Z0-9]{10}", secrets["NOTARYTOOL_TEAM_ID"]):
        parser.error("All six signing environment variables and a valid team ID are required")
    if not os.environ.get("RUNNER_TEMP") or not Path(os.environ["RUNNER_TEMP"]).is_dir():
        parser.error("RUNNER_TEMP must name an existing runner-owned directory")
    source, output = args.input.resolve(), args.output.resolve()
    if output == source or output in source.parents or source in output.parents:
        parser.error("Input and output directories must be disjoint")
    def terminate(signum, frame):
        raise GateError("Release signing interrupted")

    handlers = {sig: signal.signal(sig, terminate) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        try:
            sign_release(source, output, secrets, args.notary_timeout)
        except Exception:
            # No raw exception: subprocess arguments or malformed input can contain credentials.
            print("Release signing failed; inspect redacted signing-receipts.json. No release is complete.",
                  file=sys.stderr)
            return 1
    finally:
        for sig, previous in handlers.items():
            signal.signal(sig, previous)
    print(f"Signed release verified: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
