import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sign_release", ROOT / "scripts/sign-release.py")
SIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGN)
TEAM = "ABCD123456"
IDENTITY = f"Developer ID Application: Example Developer ({TEAM})"
FINGERPRINT = "A" * 40
REVISION = "b" * 40
SUBMISSION = "12345678-1234-1234-1234-123456789abc"
CDHASHES = {"arm64": "1" * 40, "x86_64": "2" * 40, "dylib": "3" * 40,
            "hash.dmg": "4" * 40, "hash-cli-macOS.dmg": "5" * 40}
SECRETS = dict(zip(SIGN.SECRET_NAMES, (
    base64.b64encode(b"dummy P12 fixture").decode(), "certificate-password",
    "keychain-password", "notary@example.invalid", "app-specific-password", TEAM,
)))


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / "build" / f"sign-tests-{uuid.uuid4().hex}"
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir()
        self.private = self.runner_temp / "hash-release-signing"
        environment = patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner_temp)})
        environment.start()
        self.addCleanup(environment.stop)
        self.component = self.root / "payload/hash.4dbase"
        self.component.mkdir(parents=True)
        for path, content in (
            (SIGN.CLI, bytes.fromhex("cafebabe") + b"universal CLI"),
            (SIGN.DYLIB, bytes.fromhex("cffaedfe") + b"4D arm64 dylib"),
            ("Resources/bin/Windows/hash.exe", b"MZwindows"),
            ("Resources/bin/WindowsARM/hash.exe", b"MZwindows-arm"),
            ("hash.4DZ", b"PKcompiled-project"),
            ("LICENSE", b"license"),
        ):
            target = self.component / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        (self.component / SIGN.CLI).chmod(0o755)
        native = {"source_revision": REVISION, "source_input_status": [],
                  "artifacts": {p: {"sha256": SIGN.sha256(self.component / "Resources" / p)}
                                for p in SIGN.NATIVE}}
        SIGN.write_json(self.component / "Resources/native-provenance.json", native)
        self.source = self.root / "release"
        self.source.mkdir()
        self.output = self.root / "signed"
        self.repackage()
        self.commands = []
        self.notary_status = "Accepted"
        self.fail_operation = None
        self.bad_architecture = False
        self.last_submission = None
        self.signature_details = (
            f"Authority={IDENTITY}\nAuthority=Developer ID Certification Authority\n"
            f"TeamIdentifier={TEAM}\nTimestamp=Nov 3, 2026 at 3:00:00 PM\n"
            "CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=123\n"
            f"Hash type=sha256 size=32\nCDHash={CDHASHES['arm64']}\n")
        self.entitlements = ""

    def repackage(self):
        archive = self.source / "hash.zip"
        archive.unlink(missing_ok=True)
        SIGN.make_zip(self.component.parent, archive)
        files = SIGN.inventory(self.component)
        self.provenance = {
            "version": "20.0.1", "source_revision": REVISION,
            "archive_sha256": SIGN.sha256(archive), "component_files": files,
            "verification": {"sourceRevision": REVISION, "sourceDirty": False,
                             "installed": {"success": True}, "componentFiles": files},
        }
        SIGN.write_json(self.source / "provenance.json", self.provenance)
        SIGN.write_json(self.source / "native-verification.json", {
            "source_revision": REVISION, "pre_sign_archive_sha256": SIGN.sha256(archive),
            "native_execution": {host: {"source_revision": REVISION} for host in SIGN.NATIVE_HOSTS},
        })

    def fake_run(self, command, **kwargs):
        self.commands.append((command, kwargs))
        stdout, stderr, status = "", "", 0
        if self.fail_operation and self.fail_operation(command):
            return subprocess.CompletedProcess(command, 1, "", SECRETS["NOTARYTOOL_PASSWORD"])
        if command[0] == "git":
            stdout = REVISION + "\n"
        elif command[0] == "/usr/bin/security":
            if command[1] == "create-keychain":
                Path(command[-1]).write_bytes(b"dummy keychain")
                if os.name != "nt":
                    self.assertEqual(
                        stat.S_IMODE((Path(command[-1]).parent / "identity.p12").stat().st_mode),
                        0o600)
            elif command[1] == "delete-keychain":
                Path(command[-1]).unlink()
            elif command[1] == "find-identity":
                stdout = f'  1) {FINGERPRINT} "{IDENTITY}"\n  1 valid identities found\n'
            elif command[1] in {"list-keychains", "default-keychain", "login-keychain"}:
                stdout = '"login.keychain-db"\n'
        elif command[0] == "/usr/bin/lipo":
            stdout = "arm64 x86_64" if command[-1].endswith(SIGN.CLI) else "arm64"
            if self.bad_architecture:
                stdout = "x86_64"
        elif command[0] == "/usr/bin/codesign":
            if "--sign" in command:
                path = Path(command[-1])
                path.write_bytes(path.read_bytes() + b"-developer-id-signed")
            elif "--entitlements" in command:
                stdout = self.entitlements
            elif "--display" in command:
                stderr = self.signature_details
                if command[-1].endswith(".dmg"):
                    cdhash = CDHASHES[Path(command[-1]).name]
                elif command[-1].endswith(SIGN.DYLIB):
                    cdhash = CDHASHES["dylib"]
                else:
                    cdhash = CDHASHES[command[command.index("--arch") + 1]]
                stderr = stderr.replace("CDHash=" + CDHASHES["arm64"], "CDHash=" + cdhash)
        elif command[0] == "/usr/bin/hdiutil":
            Path(command[-1]).write_bytes(b"DMG fixture")
        elif command[0] == "/usr/bin/arch" and command[-1] != "/usr/bin/true":
            stdout, stderr = b"", b""
            if command[-1] == "--version":
                stdout = b"20.0.1\n"
            elif command[-1] == "--architecture":
                stdout = b"arm64\n" if command[1] == "-arm64" else b"amd64\n"
            elif command[-1] == "--help":
                stdout = b"Usage: hash\n"
            else:
                try:
                    request = json.loads(kwargs["input"])
                except ValueError:
                    stderr, status = b"hash: invalid JSON request: fixture\n", 1
                else:
                    path = request["path"]
                    if not path:
                        stderr, status = b"hash: JSON request requires a nonempty path string\n", 1
                    elif not Path(path).exists():
                        stderr, status = b"hash: open file: fixture missing\n", 1
                    else:
                        stdout = (SIGN.sha256(Path(path)) + "\n").encode()
        elif command[0] == "/usr/bin/xcrun":
            if command[1:3] == ["notarytool", "submit"]:
                self.last_submission = Path(command[3])
                stdout = json.dumps({"id": SUBMISSION, "status": self.notary_status})
            elif command[1:3] == ["notarytool", "log"]:
                if self.notary_status != "Accepted":
                    stdout = json.dumps({"status": "Invalid", "issues": [SECRETS["NOTARYTOOL_PASSWORD"]]})
                else:
                    stdout = json.dumps(self.accepted_log(self.last_submission))
            elif command[1:3] == ["stapler", "staple"]:
                path = Path(command[-1])
                path.write_bytes(path.read_bytes() + b"-stapled")
        return subprocess.CompletedProcess(command, status, stdout, stderr)

    def accepted_log(self, archive):
        name = archive.name
        if name.startswith("hash-cli-macOS"):
            payload = {("hash", arch): CDHASHES[arch] for arch in ("arm64", "x86_64")}
        else:
            payload = {("hash.4dbase/" + SIGN.CLI, arch): CDHASHES[arch]
                       for arch in ("arm64", "x86_64")}
            payload[("hash.4dbase/" + SIGN.DYLIB, "arm64")] = CDHASHES["dylib"]
        tickets = [{"path": name + "/" + path, "arch": arch,
                    "digestAlgorithm": "SHA-256", "cdhash": cdhash}
                   for (path, arch), cdhash in payload.items()]
        if name.endswith(".dmg"):
            tickets.append({"path": name, "digestAlgorithm": "SHA-256", "cdhash": CDHASHES[name]})
        return {"logFormatVersion": 1, "jobId": SUBMISSION, "status": "Accepted", "statusCode": 0,
                "archiveFilename": name, "sha256": SIGN.sha256(archive),
                "issues": None, "ticketContents": tickets}

    def sign(self):
        with patch.object(SIGN.os, "open", wraps=os.open) as open_file:
            with patch.object(SIGN.subprocess, "run", side_effect=self.fake_run):
                result = SIGN.sign_release(self.source, self.output, SECRETS, 60)
            self.assertTrue(any(str(call.args[0]).endswith("identity.p12")
                                and call.args[2] == 0o600 for call in open_file.call_args_list))
            return result

    def test_complete_release_has_four_accepted_submissions_and_final_checksums(self):
        original = SIGN.inventory(self.source)
        manifest = self.sign()
        self.assertEqual(SIGN.inventory(self.source), original)
        self.assertEqual((self.output / "pre-sign-provenance.json").read_bytes(),
                         (self.source / "provenance.json").read_bytes())
        self.assertEqual((self.output / "pre-sign-native-verification.json").read_bytes(),
                         (self.source / "native-verification.json").read_bytes())
        self.assertEqual(manifest["pre_sign_native_verification"], {
            "path": "pre-sign-native-verification.json",
            "sha256": SIGN.sha256(self.output / "pre-sign-native-verification.json")})
        self.assertEqual(set(manifest["notarization"]),
                         {"hash.zip", "hash-cli-macOS.zip", "hash.dmg", "hash-cli-macOS.dmg"})
        self.assertTrue(all(r["status"] == "Accepted" for r in manifest["notarization"].values()))
        self.assertEqual(len(manifest["payload_notarization"]), 3)
        self.assertTrue(all(r["notarized_requirement"] for r in manifest["payload_notarization"].values()))
        self.assertTrue(all(r["result"] == "accepted"
                            for r in manifest["cli_execute_assessments"].values()))
        self.assertFalse(self.private.exists())
        for path, digest in manifest["distribution_sha256"].items():
            self.assertEqual(digest, SIGN.sha256(self.output / path))
            submitted = manifest["notarization"][path]["submitted_sha256"]
            self.assertEqual(submitted == digest, path.endswith(".zip"))
            log = manifest["notarization"][path]["log"]
            self.assertEqual(log["sha256"], SIGN.sha256(self.output / log["path"]))
            contents = manifest["notarization"][path]["ticket_contents"]
            self.assertEqual(len(contents), {"hash.zip": 3, "hash-cli-macOS.zip": 2,
                                             "hash.dmg": 4, "hash-cli-macOS.dmg": 3}[path])
        with zipfile.ZipFile(self.output / "hash.zip") as archive:
            for path, digest in manifest["component_files"].items():
                self.assertEqual(SIGN.hashlib.sha256(archive.read("hash.4dbase/" + path)).hexdigest(),
                                 digest)
            info = archive.getinfo("hash.4dbase/" + SIGN.CLI)
            if os.name != "nt":
                self.assertTrue((info.external_attr >> 16) & 0o111)
        with zipfile.ZipFile(self.output / "hash-cli-macOS.zip") as archive:
            self.assertEqual(archive.namelist(), ["hash"])
            self.assertEqual(SIGN.hashlib.sha256(archive.read("hash")).hexdigest(),
                             manifest["standalone_files"]["hash"])
        self.assertNotEqual(manifest["component_files"][SIGN.CLI],
                            self.provenance["component_files"][SIGN.CLI])
        self.assertNotEqual(manifest["component_files"][SIGN.DYLIB],
                            self.provenance["component_files"][SIGN.DYLIB])
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            digest, path = line.split("  ", 1)
            self.assertEqual(digest, SIGN.sha256(self.output / path))
        self.assertNotIn("SHA256SUMS", (self.output / "SHA256SUMS").read_text())

    def test_commands_use_explicit_isolated_keychain_and_no_entitlements_or_deep(self):
        self.sign()
        signing = [c for c, _ in self.commands if c[0] == "/usr/bin/codesign" and "--sign" in c]
        self.assertEqual(len(signing), 4)
        self.assertTrue(signing[0][-1].endswith(SIGN.DYLIB))
        self.assertTrue(signing[1][-1].endswith(SIGN.CLI))
        for command in signing:
            self.assertIn("--keychain", command)
            self.assertIn("--timestamp", command)
            self.assertNotIn("--deep", command)
            self.assertNotIn("--entitlements", command)
        for command, options in self.commands:
            self.assertGreater(options["timeout"], 0)
            self.assertTrue(all(name not in options["env"] for name in SIGN.SECRET_NAMES))
            if command[0] == "/usr/bin/security":
                if len(command) != 2:
                    self.assertEqual(options["env"]["HOME"], str(self.private / "home"))
                    self.assertEqual(options["env"]["HOME"], options["env"]["CFFIXED_USER_HOME"])
            if command[0] == "/usr/bin/xcrun" and command[1:3] == ["notarytool", "submit"]:
                self.assertIn("--wait", command)
                self.assertEqual(command[command.index("--timeout") + 1], "60s")
                self.assertEqual(options["timeout"], 120)
            if command[1:3] in (["notarytool", "submit"], ["notarytool", "log"]):
                self.assertIn("--keychain-profile", command)
                self.assertIn("--keychain", command)
                self.assertNotIn("--password", command)
                self.assertNotIn("--apple-id", command)
                self.assertNotIn("--team-id", command)
        staplers = [c for c, _ in self.commands if c[1:2] == ["stapler"]]
        self.assertEqual(len(staplers), 4)

        self.assertTrue(all(c[-1].endswith(".dmg") for c in staplers))
        assess = [c for c, _ in self.commands if c[0] == "/usr/sbin/spctl"]
        self.assertEqual(len(assess), 4)
        self.assertTrue(all(not c[-1].endswith(".dylib") for c in assess))
        for command in assess:
            if command[-1].endswith(".dmg"):
                self.assertIn("open", command)
                self.assertIn("context:primary-signature", command)
            else:
                self.assertIn("execute", command)
        ticket_checks = [c for c, _ in self.commands if "--check-notarization" in c]
        self.assertEqual(len(ticket_checks), 3)
        for command in ticket_checks:
            for flag in ("--verify", "--strict", "--all-architectures", "-R=notarized"):
                self.assertIn(flag, command)
        accepted_logs = [(c, options) for c, options in self.commands
                         if c[1:3] == ["notarytool", "log"]]
        self.assertEqual(len(accepted_logs), 4)
        self.assertTrue(all(options["timeout"] == 120 for _, options in accepted_logs))

    def test_private_key_search_list_is_configured_only_in_isolated_home(self):
        self.sign()
        changes = [(command, options) for command, options in self.commands
                   if command[1:2] == ["list-keychains"] and "-s" in command]
        self.assertEqual(len(changes), 1)
        command, options = changes[0]
        self.assertEqual(command[2:5], ["-d", "user", "-s"])
        self.assertEqual(command[5:], [str(self.private / "release.keychain-db"),
                                      "/Library/Keychains/System.keychain"])
        self.assertEqual(options["env"]["HOME"], str(self.private / "home"))
        self.assertEqual(options["env"]["CFFIXED_USER_HOME"], str(self.private / "home"))

    def test_accepted_containers_without_every_nested_slice_ticket_are_rejected(self):
        original = self.fake_run
        cases = [
            ("hash.zip", SIGN.CLI, "arm64"),
            ("hash.zip", SIGN.CLI, "x86_64"),
            ("hash.zip", SIGN.DYLIB, "arm64"),
            ("hash-cli-macOS.zip", "/hash", "arm64"),
            ("hash-cli-macOS.zip", "/hash", "x86_64"),
            ("hash.dmg", "hash.dmg", None),
            ("hash.dmg", SIGN.CLI, "x86_64"),
            ("hash.dmg", SIGN.DYLIB, "arm64"),
            ("hash-cli-macOS.dmg", "hash-cli-macOS.dmg", None),
            ("hash-cli-macOS.dmg", "/hash", "arm64"),
        ]
        for index, (archive_name, suffix, architecture) in enumerate(cases):
            self.output = self.root / f"omitted-ticket-{index}"

            def omitted(command, **kwargs):
                result = original(command, **kwargs)
                if command[1:3] == ["notarytool", "log"] and self.last_submission.name == archive_name:
                    log = json.loads(result.stdout)
                    log["ticketContents"] = [
                        ticket for ticket in log["ticketContents"]
                        if not (ticket["path"].endswith(suffix) and ticket.get("arch") == architecture)]
                    result.stdout = json.dumps(log)
                return result

            with self.subTest(archive=archive_name, suffix=suffix, arch=architecture):
                with patch.object(SIGN.subprocess, "run", side_effect=omitted):
                    with self.assertRaisesRegex(SIGN.GateError, "ticket coverage"):
                        SIGN.sign_release(self.source, self.output, SECRETS, 60)
                self.assertFalse((self.output / "provenance.json").exists())
                self.assertTrue((self.output / f"notary-{archive_name}.json").exists())
                self.assertFalse(self.private.exists())

    def test_notary_log_requires_exact_identity_hash_status_and_ticket_records(self):
        archive = self.source / "hash.zip"
        baseline = self.accepted_log(archive)
        expected = {(ticket["path"], ticket.get("arch")): ticket["cdhash"]
                    for ticket in baseline["ticketContents"]}
        mutations = [
            lambda log: log.update(jobId="0" * 36),
            lambda log: log.update(archiveFilename="other.zip"),
            lambda log: log.update(sha256="0" * 64),
            lambda log: log.update(status="Invalid"),
            lambda log: log.update(statusCode=1),
            lambda log: log.update(statusCode=False),
            lambda log: log.update(logFormatVersion=True),
            lambda log: log.update(issues=[{"severity": "warning", "message": "review required"}]),
            lambda log: log.update(ticketContents=None),
            lambda log: log["ticketContents"][0].update(cdhash="f" * 40),
            lambda log: log["ticketContents"][0].update(arch="x86_64"),
            lambda log: log["ticketContents"][0].update(arch=[]),
            lambda log: log["ticketContents"][0].update(path="other/path"),
            lambda log: log["ticketContents"][0].update(digestAlgorithm="SHA-1"),
            lambda log: log["ticketContents"][0].update(cdhash=1234567890123456789012345678901234567890),
        ]
        for index, mutate in enumerate(mutations):
            log = json.loads(json.dumps(baseline))
            mutate(log)
            with self.subTest(mutation=index), self.assertRaises(SIGN.GateError):
                SIGN.validate_ticket_log(log, archive, SUBMISSION, expected)

    def test_identical_duplicate_ticket_records_are_allowed_but_conflicts_are_not(self):
        archive = self.source / "hash.zip"
        log = self.accepted_log(archive)
        expected = {(ticket["path"], ticket.get("arch")): ticket["cdhash"]
                    for ticket in log["ticketContents"]}
        log["ticketContents"].append(dict(log["ticketContents"][0]))
        self.assertEqual(len(SIGN.validate_ticket_log(log, archive, SUBMISSION, expected)), 3)
        log["ticketContents"][-1]["cdhash"] = "e" * 40
        with self.assertRaisesRegex(SIGN.GateError, "Conflicting"):
            SIGN.validate_ticket_log(log, archive, SUBMISSION, expected)

    def test_accepted_log_download_failure_still_blocks_release(self):
        self.fail_operation = lambda command: command[1:3] == ["notarytool", "log"]
        with self.assertRaises(SIGN.GateError):
            self.sign()
        self.assertFalse((self.output / "provenance.json").exists())
        self.assertFalse(self.private.exists())

    def test_accepted_logs_are_saved_sanitized_even_when_json_is_malformed(self):
        original = self.fake_run

        def malformed(command, **kwargs):
            result = original(command, **kwargs)
            if command[1:3] == ["notarytool", "log"]:
                result.stdout = "not JSON " + SECRETS["NOTARYTOOL_PASSWORD"]
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=malformed):
            with self.assertRaisesRegex(SIGN.GateError, "malformed log"):
                SIGN.sign_release(self.source, self.output, SECRETS, 60)
        saved = (self.output / "notary-hash.zip.json").read_text()
        self.assertIn("[REDACTED]", saved)
        self.assertNotIn(SECRETS["NOTARYTOOL_PASSWORD"], saved)

    def test_valid_accepted_logs_ship_without_credential_values(self):
        original = self.fake_run

        def with_credentials(command, **kwargs):
            result = original(command, **kwargs)
            if command[1:3] == ["notarytool", "log"]:
                log = json.loads(result.stdout)
                log["diagnosticContext"] = SECRETS
                result.stdout = json.dumps(log)
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=with_credentials):
            manifest = SIGN.sign_release(self.source, self.output, SECRETS, 60)
        for record in manifest["notarization"].values():
            saved = (self.output / record["log"]["path"]).read_text()
            self.assertTrue(json.loads(saved))
            for secret in SECRETS.values():
                self.assertNotIn(secret, saved)

    def test_sentinel_credentials_absent_from_complete_output_and_evidence_tree(self):
        original = self.fake_run
        certificate = b"SENTINEL-PRIVATE-P12-CONTENT-c1d73588"
        sentinel_secrets = {
            "APPLE_DEVELOPER_ID_CERTIFICATE": base64.b64encode(certificate).decode(),
            "APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD": 'SENTINEL-P12-password-"quoted"-日本語',
            "KEYCHAIN_PASSWORD": "SENTINEL-keychain-password-ae14ed5f",
            "NOTARYTOOL_APPLE_ID": "SENTINEL-apple-id@example.invalid",
            "NOTARYTOOL_PASSWORD": "SENTINEL-app-specific-password-dd934bd6",
            "NOTARYTOOL_TEAM_ID": TEAM,
        }

        def noisy(command, **kwargs):
            result = original(command, **kwargs)
            if command[1:2] == ["import"] or command[1:3] == ["notarytool", "store-credentials"]:
                result.stdout = json.dumps(sentinel_secrets)
            elif command[1:3] == ["notarytool", "log"]:
                log = json.loads(result.stdout)
                log["diagnosticContext"] = sentinel_secrets
                result.stdout = json.dumps(log)
            return result

        with patch.dict(SECRETS, sentinel_secrets):
            with patch.object(SIGN.subprocess, "run", side_effect=noisy):
                SIGN.sign_release(self.source, self.output, SECRETS, 60)
        forbidden = {certificate}
        for name, value in sentinel_secrets.items():
            if name != "NOTARYTOOL_TEAM_ID":  # Public signing identity, not a credential.
                forbidden.update(encoded.encode("utf-8") for encoded in (
                    value, json.dumps(value)[1:-1], SIGN.quote(value, safe=""),
                    SIGN.quote_plus(value, safe="")))
        for path in self.output.rglob("*"):
            if not path.is_file():
                continue
            contents = [path.read_bytes()]
            if path.suffix == ".zip":
                with zipfile.ZipFile(path) as archive:
                    contents.extend(archive.read(info) for info in archive.infolist() if not info.is_dir())
            for content in contents:
                for secret in forbidden:
                    self.assertNotIn(secret, content, str(path))
        events = json.loads((self.output / "signing-receipts.json").read_text())
        self.assertTrue(all("command" not in event and "args" not in event for event in events))
        self.assertFalse(self.private.exists())
        stores = [c for c, _ in self.commands if c[1:3] == ["notarytool", "store-credentials"]]
        self.assertEqual(len(stores), 1)
        self.assertIn("--keychain", stores[0])
        self.assertIn("--validate", stores[0])
        self.assertNotIn("--sync", stores[0])

    def test_stapling_cannot_change_the_notarized_dmg_code_directory(self):
        original = self.fake_run
        stapled = set()

        def changed(command, **kwargs):
            result = original(command, **kwargs)
            if command[1:3] == ["stapler", "staple"]:
                stapled.add(command[-1])
            if command[0] == "/usr/bin/codesign" and "--display" in command and command[-1] in stapled:
                result.stderr = result.stderr.replace("CDHash=" + CDHASHES["hash.dmg"],
                                                      "CDHash=" + "e" * 40)
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=changed):
            with self.assertRaisesRegex(SIGN.GateError, "CDHash changed"):
                SIGN.sign_release(self.source, self.output, SECRETS, 60)
        self.assertFalse((self.output / "provenance.json").exists())

    def fail_cli_staples(self, failures):
        original = self.fake_run
        pending = iter(failures)
        attempts = []

        def flaky(command, **kwargs):
            if (command[1:3] == ["stapler", "staple"]
                    and command[-1].endswith("hash-cli-macOS.dmg")):
                attempts.append((command[-1], SIGN.sha256(Path(command[-1])), kwargs["timeout"]))
                failure = next(pending, None)
                if failure:
                    self.commands.append((command, kwargs))
                    return subprocess.CompletedProcess(command, *failure)
            return original(command, **kwargs)

        self.fake_run = flaky
        return attempts

    def test_transient_stapling_retries_same_accepted_dmg_without_resigning_or_resubmission(self):
        attempts = self.fail_cli_staples([
            (68, 'Error Domain=NSURLErrorDomain Code=-1005 "The network connection was lost."',
             SECRETS["NOTARYTOOL_PASSWORD"]),
        ])
        with patch.object(SIGN.time, "sleep") as sleep, patch.object(sys, "stdout", io.StringIO()) as output:
            manifest = self.sign()
        sleep.assert_called_once_with(5)
        self.assertIn("attempt 2/3", output.getvalue())
        self.assertIn("transient network failure", output.getvalue())
        self.assertEqual(len(attempts), 2)
        submitted = manifest["notarization"]["hash-cli-macOS.dmg"]["submitted_sha256"]
        self.assertTrue(all(path == attempts[0][0] and digest == submitted and timeout == 60
                            for path, digest, timeout in attempts))
        submissions = [command for command, _ in self.commands
                       if command[1:3] == ["notarytool", "submit"]]
        self.assertEqual(len(submissions), 4)
        self.assertEqual(len({command[3] for command in submissions}), 4)
        self.assertEqual(sum("--sign" in command for command, _ in self.commands), 4)
        self.assertTrue(any(command[1:3] == ["stapler", "validate"]
                            and command[-1] == attempts[0][0] for command, _ in self.commands))
        self.assertTrue(any(command[0] == "/usr/sbin/spctl" and command[-1] == attempts[0][0]
                            for command, _ in self.commands))
        receipts = (self.output / "signing-receipts.json").read_text()
        self.assertNotIn(SECRETS["NOTARYTOOL_PASSWORD"], receipts)
        events = [event for event in json.loads(receipts)
                  if event["operation"].startswith("staple hash-cli-macOS.dmg")]
        self.assertEqual([event["returncode"] for event in events], [68, 0])
        self.assertIn("NSURLErrorDomain Code=-1005", events[0]["stdout"])

    def test_transient_stapling_exhaustion_blocks_release_and_retains_all_attempts(self):
        attempts = self.fail_cli_staples([
            (68, "Error Domain=NSURLErrorDomain Code=-1005", "")] * 3)
        with patch.object(SIGN.time, "sleep") as sleep:
            with self.assertRaisesRegex(SIGN.GateError, "exhausted 3"):
                self.sign()
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 15])
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len({(path, digest) for path, digest, _ in attempts}), 1)
        self.assertEqual(sum(command[1:3] == ["notarytool", "submit"]
                             for command, _ in self.commands), 4)
        self.assertFalse(any(command[1:3] == ["stapler", "validate"]
                             and command[-1] == attempts[0][0] for command, _ in self.commands))
        self.assertFalse((self.output / "provenance.json").exists())
        events = json.loads((self.output / "signing-receipts.json").read_text())
        self.assertEqual(sum(event["operation"].startswith("staple hash-cli-macOS.dmg")
                             for event in events), 3)

    def test_permanent_stapling_error_aborts_immediately_even_with_exit_68(self):
        attempts = self.fail_cli_staples([(68, "No ticket was found for this code.", "")])
        with patch.object(SIGN.time, "sleep") as sleep:
            with self.assertRaises(SIGN.GateError):
                self.sign()
        sleep.assert_not_called()
        self.assertEqual(len(attempts), 1)
        self.assertFalse((self.output / "provenance.json").exists())

    def test_successful_stapling_never_sleeps_or_retries(self):
        with patch.object(SIGN.time, "sleep") as sleep:
            self.sign()
        sleep.assert_not_called()
        self.assertEqual(sum(command[1:3] == ["stapler", "staple"]
                             for command, _ in self.commands), 2)

    def test_retry_success_does_not_bypass_or_retry_staple_validation(self):
        attempts = self.fail_cli_staples([(68, "Error Domain=NSURLErrorDomain Code=-1005", "")])
        self.fail_operation = lambda command: (
            command[1:3] == ["stapler", "validate"] and command[-1].endswith("hash-cli-macOS.dmg"))
        with patch.object(SIGN.time, "sleep") as sleep:
            with self.assertRaisesRegex(SIGN.GateError, "validate staple"):
                self.sign()
        sleep.assert_called_once_with(5)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(sum(command[1:3] == ["stapler", "validate"]
                             and command[-1] == attempts[0][0] for command, _ in self.commands), 1)
        self.assertFalse(any(command[0] == "/usr/sbin/spctl" and command[-1] == attempts[0][0]
                             for command, _ in self.commands))
        self.assertFalse((self.output / "provenance.json").exists())

    def test_stapling_network_classification_excludes_tls_unknown_and_other_failures(self):
        for code in (-1001, -1003, -1004, -1005, -1006, -1009):
            with self.subTest(transient=code):
                self.assertTrue(SIGN.transient_staple_network_error({
                    "returncode": 68, "stderr": f"Error Domain=NSURLErrorDomain Code={code}"}))
        for event in (
            {"returncode": 68, "stdout": "Error 68: ticket missing"},
            {"returncode": 68, "stdout": "Error Domain=OtherDomain Code=-1005"},
            {"returncode": 68, "stdout": "Error Domain=NSURLErrorDomain Code=-1202"},
            {"returncode": 68, "stdout": "Error Domain=NSURLErrorDomain Code=-1200"},
            {"returncode": 68, "stdout": "Error Domain=NSURLErrorDomain Code=-999"},
            {"returncode": 68, "stdout": "Error Domain=NSURLErrorDomain Code=-1005 "
             "Error Domain=NSURLErrorDomain Code=-1202"},
            {"returncode": 1, "stdout": "Error Domain=NSURLErrorDomain Code=-1005"},
            {"timed_out": True, "stdout": "Error Domain=NSURLErrorDomain Code=-1005"},
        ):
            with self.subTest(event=event):
                self.assertFalse(SIGN.transient_staple_network_error(event))

    def test_stapling_total_deadline_caps_last_attempt_timeout(self):
        clock = [0]
        timeouts = []
        runner = SIGN.Runner({}, self.root / "staple-bounds.json")

        def failed(command, **kwargs):
            timeouts.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            return subprocess.CompletedProcess(
                command, 68, "Error Domain=NSURLErrorDomain Code=-1005", "")

        def sleep(delay):
            clock[0] += delay

        with patch.object(SIGN.time, "monotonic", side_effect=lambda: clock[0]):
            with patch.object(SIGN.time, "sleep", side_effect=sleep):
                with patch.object(SIGN.subprocess, "run", side_effect=failed):
                    with self.assertRaisesRegex(SIGN.GateError, "exhausted 3"):
                        SIGN.staple(runner, self.root / "accepted.dmg")
        self.assertEqual(timeouts, [60, 60, 40])
        self.assertEqual(clock[0], 180)

    def test_stapling_subprocess_timeout_without_network_result_is_not_retried(self):
        runner = SIGN.Runner({}, self.root / "staple-timeout.json")
        with patch.object(SIGN.time, "sleep") as sleep:
            with patch.object(SIGN.subprocess, "run",
                              side_effect=subprocess.TimeoutExpired("stapler", 60)) as run:
                with self.assertRaisesRegex(SIGN.GateError, "timed out"):
                    SIGN.staple(runner, self.root / "accepted.dmg")
        run.assert_called_once()
        sleep.assert_not_called()
        self.assertTrue(runner.events[0]["timed_out"])

    def test_raw_cli_non_app_assessment_is_recorded_honestly_after_real_ticket_checks(self):
        original = self.fake_run

        def non_app(command, **kwargs):
            result = original(command, **kwargs)
            if command[0] == "/usr/sbin/spctl" and "execute" in command:
                return subprocess.CompletedProcess(command, 3, "", (
                    "hash: rejected (the code is valid but does not seem to be an app)\n"
                    f"origin={IDENTITY}\n"))
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=non_app):
            manifest = SIGN.sign_release(self.source, self.output, SECRETS, 60)
        self.assertTrue(all(r["result"] == "unsupported_non_app_tool"
                            for r in manifest["cli_execute_assessments"].values()))
        self.assertEqual(len(manifest["payload_notarization"]), 3)
        events = json.loads((self.output / "signing-receipts.json").read_text())
        for assessment in manifest["cli_execute_assessments"].values():
            event = events[assessment["receipt_event"]]
            self.assertEqual(event["returncode"], 3)
            self.assertIn("does not seem to be an app", event["stderr"])

    def test_non_app_diagnostic_does_not_waive_unnotarized_or_other_policy_errors(self):
        original = self.fake_run
        unsupported = "hash: rejected (the code is valid but does not seem to be an app)\n"
        for index, diagnostic in enumerate((
                "hash: rejected\nsource=Unnotarized Developer ID",
                unsupported + "source=Unnotarized Developer ID",
                unsupported + "certificate revoked",
                "operation timed out", "unknown error")):
            self.output = self.root / f"denied-cli-{index}"

            def denied(command, **kwargs):
                result = original(command, **kwargs)
                if command[0] == "/usr/sbin/spctl" and "execute" in command:
                    return subprocess.CompletedProcess(command, 3, "", diagnostic)
                return result

            with self.subTest(diagnostic=diagnostic):
                with patch.object(SIGN.subprocess, "run", side_effect=denied):
                    with self.assertRaises(SIGN.GateError):
                        SIGN.sign_release(self.source, self.output, SECRETS, 60)
                self.assertFalse((self.output / "provenance.json").exists())

    def test_notarized_code_requirement_failure_blocks_both_cli_and_library(self):
        for index, suffix in enumerate((SIGN.CLI, SIGN.DYLIB, "standalone/hash")):
            self.output = self.root / f"missing-ticket-{index}"
            self.fail_operation = lambda command: (
                "--check-notarization" in command and command[-1].endswith(suffix))
            with self.subTest(path=suffix), self.assertRaises(SIGN.GateError):
                self.sign()
            self.assertFalse((self.output / "provenance.json").exists())
            self.assertFalse(self.private.exists())

    def test_signed_standalone_smoke_runs_arm64_and_rosetta_contracts(self):
        with patch.object(SIGN.platform, "machine", return_value="arm64"):
            manifest = self.sign()
        execution = manifest["signed_cli_execution"]
        self.assertEqual([(r["architecture"], r["mode"], r["status"]) for r in execution],
                         [("arm64", "native", "passed"), ("x86_64", "Rosetta", "passed")])
        for result in execution:
            self.assertEqual(result["binary_sha256"], manifest["standalone_files"]["hash"])
            self.assertEqual(result["fixture_sha256"]["empty"], SIGN.hashlib.sha256(b"").hexdigest())
            self.assertEqual(result["fixture_sha256"]["binary"],
                             SIGN.hashlib.sha256(bytes(range(256)) * 257).hexdigest())
            self.assertIn("empty_digest", result["checks"])
            self.assertIn("malformed_error", result["checks"])
        smoke_commands = [(c, options) for c, options in self.commands
                          if c[0] == "/usr/bin/arch" and c[-1] != "/usr/bin/true"]
        self.assertEqual(len(smoke_commands), 16)
        self.assertTrue(all(not options["text"] for _, options in smoke_commands))
        self.assertTrue(all(options["timeout"] == 30 for _, options in smoke_commands))
        self.assertTrue(all(str(self.output / "standalone/hash") in c for c, _ in smoke_commands))

    def test_rosetta_unavailable_only_skips_explicit_system_bad_cpu_probe(self):
        original = self.fake_run

        def unavailable(command, **kwargs):
            result = original(command, **kwargs)
            if command[-1] == "/usr/bin/true":
                return subprocess.CompletedProcess(command, 1, "",
                                                   "arch: Bad CPU type in executable\n")
            return result

        with patch.object(SIGN.platform, "machine", return_value="arm64"):
            with patch.object(SIGN.subprocess, "run", side_effect=unavailable):
                manifest = SIGN.sign_release(self.source, self.output, SECRETS, 60)
        self.assertEqual(manifest["signed_cli_execution"][0]["status"], "passed")
        self.assertEqual(manifest["signed_cli_execution"][1]["status"], "not-run")
        self.assertEqual(manifest["signed_cli_execution"][1]["mode"], "Rosetta")
        self.assertFalse(any(c[0] == "/usr/bin/arch" and c[1] == "-x86_64"
                             and c[-1] != "/usr/bin/true" for c, _ in self.commands))

    def test_rosetta_unknown_probe_or_signed_cli_failure_is_not_skipped(self):
        original = self.fake_run
        for index, fail_probe in enumerate((True, False)):
            self.output = self.root / f"rosetta-failed-{index}"

            def failure(command, **kwargs):
                result = original(command, **kwargs)
                if command[0] == "/usr/bin/arch" and command[1] == "-x86_64":
                    if fail_probe and command[-1] == "/usr/bin/true":
                        return subprocess.CompletedProcess(command, 1, "", "unexpected probe error\n")
                    if not fail_probe and command[-1] != "/usr/bin/true":
                        return subprocess.CompletedProcess(command, 1, b"", b"Bad CPU type in executable\n")
                return result

            with self.subTest(fail_probe=fail_probe):
                with patch.object(SIGN.platform, "machine", return_value="arm64"):
                    with patch.object(SIGN.subprocess, "run", side_effect=failure):
                        with self.assertRaises(SIGN.GateError):
                            SIGN.sign_release(self.source, self.output, SECRETS, 60)
                self.assertFalse((self.output / "provenance.json").exists())

    def test_smoke_rejects_wrong_version_architecture_digest_bytes_and_error_contract(self):
        original = self.fake_run
        for index, defect in enumerate(("version", "architecture", "binary", "empty",
                                        "error_stdout", "error_exit")):
            private = self.root / f"smoke-defect-{index}"
            private.mkdir()
            runner = SIGN.Runner(SECRETS, private / "receipts.json")

            def broken(command, **kwargs):
                result = original(command, **kwargs)
                request = kwargs.get("input", b"")
                if defect == "version" and command[-1] == "--version":
                    result.stdout = b"wrong\n"
                elif defect == "architecture" and command[-1] == "--architecture":
                    result.stdout = b"amd64\n"
                elif defect == "binary" and b"binary-" in request:
                    result.stdout = result.stdout.replace(b"\n", b"\r\n")
                elif defect == "empty" and b"empty.bin" in request:
                    result.stdout = b"0" * 64 + b"\n"
                elif request == b'{"path":""}':
                    if defect == "error_stdout":
                        result.stdout = b"must be empty"
                    elif defect == "error_exit":
                        result.returncode = 0
                return result

            with self.subTest(defect=defect):
                with patch.object(SIGN.platform, "machine", return_value="arm64"):
                    with patch.object(SIGN.subprocess, "run", side_effect=broken):
                        with self.assertRaises(SIGN.GateError):
                            SIGN.smoke_cli(runner, self.component / SIGN.CLI, "20.0.1", private)

    def test_intel_smoke_does_not_claim_arm_execution(self):
        with patch.object(SIGN.platform, "machine", return_value="x86_64"):
            manifest = self.sign()
        execution = manifest["signed_cli_execution"]
        self.assertEqual(execution[0]["architecture"], "x86_64")
        self.assertEqual(execution[0]["status"], "passed")
        self.assertEqual(execution[1]["architecture"], "arm64")
        self.assertEqual(execution[1]["status"], "not-run")
        self.assertFalse(any(c[-1] == "/usr/bin/true" for c, _ in self.commands))

    def test_rejects_notary_invalid_and_retains_redacted_log(self):
        self.notary_status = "Invalid"
        with self.assertRaisesRegex(SIGN.GateError, "not Accepted"):
            self.sign()
        receipts = (self.output / "signing-receipts.json").read_text()
        self.assertIn("notarization failure log hash.zip", receipts)
        self.assertIn("[REDACTED]", receipts)
        for secret in SECRETS.values():
            self.assertNotIn(secret, receipts)
        self.assertFalse(self.private.exists())
        self.assertFalse((self.output / "provenance.json").exists())
        self.assertFalse((self.output / "SHA256SUMS").exists())

    def test_cleanup_after_sign_failure_does_not_emit_success(self):
        self.fail_operation = lambda command: "--sign" in command
        with self.assertRaises(SIGN.GateError):
            self.sign()
        self.assertTrue(any(c[1:2] == ["delete-keychain"] for c, _ in self.commands))
        self.assertFalse(self.private.exists())
        self.assertFalse((self.output / "provenance.json").exists())

    def test_cleanup_failure_blocks_success_and_removes_private_files(self):
        self.fail_operation = lambda command: command[1:2] == ["delete-keychain"]
        with self.assertRaises(SIGN.GateError):
            self.sign()
        self.assertFalse(self.private.exists())
        self.assertFalse((self.output / "provenance.json").exists())

    def test_gatekeeper_rejection_blocks_success(self):
        self.fail_operation = lambda command: command[0] == "/usr/sbin/spctl"
        with self.assertRaises(SIGN.GateError):
            self.sign()
        self.assertFalse((self.output / "provenance.json").exists())

    def test_wrong_architecture_rejected_before_key_import(self):
        self.bad_architecture = True
        with self.assertRaisesRegex(SIGN.GateError, "architectures"):
            self.sign()
        self.assertFalse(any(c[1:2] == ["import"] for c, _ in self.commands))

    def test_presign_archive_tampering_is_rejected(self):
        with zipfile.ZipFile(self.source / "hash.zip", "a") as archive:
            archive.writestr("hash.4dbase/tampered", b"changed")
        with self.assertRaisesRegex(SIGN.GateError, "archive checksum"):
            self.sign()

    def test_unexpected_macho_rejected_even_when_provenance_matches(self):
        (self.component / "extra").write_bytes(bytes.fromhex("feedfacf") + b"unexpected")
        self.repackage()
        with self.assertRaisesRegex(SIGN.GateError, "exactly"):
            self.sign()

    def test_missing_dylib_rejected(self):
        (self.component / SIGN.DYLIB).unlink()
        with self.assertRaisesRegex(SIGN.GateError, "exactly"):
            SIGN.validate_code_inventory(self.component)

    def test_presign_native_byte_mismatch_rejected(self):
        (self.component / SIGN.CLI).write_bytes(bytes.fromhex("cafebabe") + b"tampered")
        self.repackage()
        with self.assertRaisesRegex(SIGN.GateError, "native checksum"):
            self.sign()

    def test_input_inventory_and_dirty_verification_rejected(self):
        for mutate in (
            lambda data: data["component_files"].update({"extra": "0" * 64}),
            lambda data: data["verification"].update({"sourceDirty": True}),
            lambda data: data["verification"]["installed"].update({"success": False}),
        ):
            self.repackage()
            mutate(self.provenance)
            with self.assertRaises(SIGN.GateError):
                SIGN.validate_input(self.source / "hash.zip", self.provenance,
                                    self.component, REVISION)

    def test_existing_output_cannot_be_reused(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            self.sign()
        self.assertFalse(self.private.exists())

    def test_existing_private_directory_is_not_reused_or_removed(self):
        self.private.mkdir()
        marker = self.private / "belongs-to-another-run"
        marker.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            self.sign()
        self.assertEqual(marker.read_bytes(), b"untouched")
        self.assertFalse(self.output.exists())

    def test_requires_existing_runner_temp(self):
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root / "missing")}):
            with self.assertRaisesRegex(SIGN.GateError, "RUNNER_TEMP"):
                self.sign()
        self.assertFalse(self.output.exists())

    def test_native_ci_proof_must_ship_and_match_source_archive_and_four_hosts(self):
        proof_path = self.source / "native-verification.json"
        proof = json.loads(proof_path.read_text())
        for field, invalid in (("source_revision", "c" * 40),
                               ("pre_sign_archive_sha256", "0" * 64),
                               ("native_execution", {})):
            self.output = self.root / ("signed-bad-native-" + field)
            SIGN.write_json(proof_path, {**proof, field: invalid})
            with self.assertRaisesRegex(SIGN.GateError, "Native CI proof"):
                self.sign()
            self.assertFalse(self.private.exists())
            self.assertFalse((self.output / "provenance.json").exists())

    def test_external_cleanup_needs_no_secrets_and_is_idempotent(self):
        self.private.mkdir()
        (self.private / "release.keychain-db").write_bytes(b"dummy keychain")
        (self.private / "identity.p12").write_bytes(b"dummy P12")
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.runner_temp)}, clear=True):
            with patch.object(sys, "platform", "darwin"), patch.object(
                    sys, "argv", ["sign-release.py", "--cleanup", "--output", str(self.output)]):
                with patch.object(SIGN.subprocess, "run", side_effect=self.fake_run):
                    with patch("builtins.print"):
                        self.assertEqual(SIGN.main(), 0)
                        self.assertEqual(SIGN.main(), 0)
        self.assertFalse(self.private.exists())
        self.assertEqual(len(self.commands), 1)
        command, options = self.commands[0]
        self.assertEqual(command[1], "delete-keychain")
        self.assertEqual(options["env"]["HOME"], str(self.private / "home"))
        self.assertEqual(options["env"]["HOME"], options["env"]["CFFIXED_USER_HOME"])

    def test_external_cleanup_removes_files_even_if_security_fails(self):
        self.private.mkdir()
        (self.private / "release.keychain-db").write_bytes(b"dummy keychain")
        (self.private / "identity.p12").write_bytes(b"dummy P12")
        self.fail_operation = lambda command: command[1:2] == ["delete-keychain"]
        with patch.dict(os.environ, SECRETS):
            with patch.object(SIGN.subprocess, "run", side_effect=self.fake_run):
                with self.assertRaises(SIGN.GateError):
                    SIGN.cleanup_release(self.output)
        self.assertFalse(self.private.exists())
        self.assertNotIn(SECRETS["NOTARYTOOL_PASSWORD"],
                         (self.output / "cleanup-receipts.json").read_text())

    @unittest.skipIf(os.name == "nt", "Symlink creation requires special Windows privileges")
    def test_external_cleanup_refuses_symlinked_private_state(self):
        target = self.root / "unrelated"
        target.mkdir()
        (target / "identity.p12").write_bytes(b"must not touch")
        self.private.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(SIGN.GateError, "symlink"):
            SIGN.cleanup_release(self.output)
        self.assertEqual((target / "identity.p12").read_bytes(), b"must not touch")

    def test_sigterm_runs_private_cleanup_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        original = self.fake_run

        def terminate(command, **kwargs):
            if command[0] == "/usr/bin/codesign" and "--sign" in command:
                signal.raise_signal(signal.SIGTERM)
            return original(command, **kwargs)

        with patch.dict(os.environ, SECRETS), patch.object(sys, "platform", "darwin"):
            with patch.object(sys, "argv", [
                    "sign-release.py", "--input", str(self.source), "--output", str(self.output)]):
                with patch.object(SIGN.subprocess, "run", side_effect=terminate):
                    with patch.object(sys, "stderr", io.StringIO()):
                        self.assertEqual(SIGN.main(), 1)
        self.assertFalse(self.private.exists())
        self.assertFalse((self.output / "provenance.json").exists())
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_unsafe_duplicate_and_symlink_archive_entries(self):
        for index, name in enumerate((
                "../escape", "/hash.4dbase/escape", "hash.4dbase/../escape",
                "hash.4dbase\\escape", "other/file", "hash.4dbase/./file",
                "hash.4dbase/link", "hash.4dbase/duplicate")):
            with self.subTest(name=name):
                archive = self.root / f"unsafe-{index}.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    info = zipfile.ZipInfo(name)
                    if name.endswith("/link"):
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    if name.endswith("/duplicate"):
                        output.writestr("hash.4dbase/duplicate/", b"")
                    output.writestr(info, b"target")
                with self.assertRaises(SIGN.GateError):
                    SIGN.extract_component(archive, self.root / f"extract-{index}")

    def test_identity_requires_exactly_one_valid_application_for_team(self):
        line = f'  1) {FINGERPRINT} "{IDENTITY}"\n'
        self.assertEqual(SIGN.select_identity(line, TEAM), (FINGERPRINT, IDENTITY))
        for invalid in (
            "", line + line, line.replace("Application:", "Installer:"),
            line.replace(TEAM, "WRONG12345"),
            line.rstrip() + " (CSSMERR_TP_CERT_EXPIRED)\n",
        ):
            with self.subTest(output=invalid), self.assertRaises(SIGN.GateError):
                SIGN.select_identity(invalid, TEAM)

    def test_signature_requires_exact_team_authority_timestamp_and_runtime(self):
        for bad in (
            self.signature_details.replace(TEAM, "WRONG12345"),
            self.signature_details.replace("Application:", "Installer:"),
            self.signature_details.replace("Timestamp=", "Signed Time="),
            self.signature_details.replace("flags=0x10000(runtime)", "flags=0x0(none)"),
            self.signature_details.replace("Hash type=sha256", "Hash type=sha1"),
            self.signature_details.replace("CDHash=" + CDHASHES["arm64"], "CDHash=invalid"),
            self.signature_details + "Signature=adhoc\n",
        ):
            with self.subTest(details=bad):
                runner = SIGN.Runner(SECRETS, self.root / "receipts.json")
                with patch.object(SIGN.subprocess, "run", return_value=subprocess.CompletedProcess(
                        [], 0, "", bad)):
                    with self.assertRaises(SIGN.GateError):
                        SIGN.verify_signature(runner, self.component / SIGN.CLI, TEAM,
                                              IDENTITY, SIGN.CODE[SIGN.CLI])

    def test_no_special_entitlements(self):
        self.entitlements = plistlib.dumps({"com.apple.security.cs.allow-jit": True}).decode()
        with self.assertRaisesRegex(SIGN.GateError, "special entitlements"):
            self.sign()
        self.assertFalse(self.private.exists())

    def test_subprocess_timeout_is_bounded_redacted_and_does_not_echo_command(self):
        runner = SIGN.Runner(SECRETS, self.root / "timeout-receipts.json")
        password = SECRETS["NOTARYTOOL_PASSWORD"]
        with patch.object(SIGN.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                ["tool", password], 10, output=password.encode(), stderr=password)):
            with self.assertRaises(SIGN.GateError) as error:
                runner.run("bounded test", ["tool", password], timeout=10)
        self.assertNotIn(password, str(error.exception))
        receipts = runner.receipts.read_text()
        self.assertNotIn(password, receipts)
        self.assertIn('"timed_out": true', receipts)

    def test_notary_requires_json_accepted_uuid_and_successful_exit(self):
        path = self.source / "hash.zip"
        for result in (
            subprocess.CompletedProcess([], 0, "not JSON", ""),
            subprocess.CompletedProcess([], 0, '["Accepted"]', ""),
            subprocess.CompletedProcess([], 0, '{"status": "Accepted"}', ""),
            subprocess.CompletedProcess([], 0, json.dumps({"id": SUBMISSION, "status": "In Progress"}), ""),
            subprocess.CompletedProcess([], 1, json.dumps({"id": SUBMISSION, "status": "Accepted"}), ""),
        ):
            with self.subTest(result=result):
                runner = SIGN.Runner(SECRETS, self.root / "notary-receipts.json")
                with patch.object(SIGN.subprocess, "run", return_value=result):
                    with self.assertRaises(SIGN.GateError):
                        SIGN.notarize(runner, path, self.private / "release.keychain-db", 60, {})

    def test_notary_timeout_with_submission_id_retrieves_failure_log(self):
        runner = SIGN.Runner(SECRETS, self.root / "notary-timeout.json")
        with patch.object(SIGN.subprocess, "run", side_effect=[
                subprocess.TimeoutExpired(["do not log credentials"], 120,
                                          output=json.dumps({"id": SUBMISSION}).encode()),
                subprocess.CompletedProcess([], 0, '{"status": "In Progress"}', "")]):
            with self.assertRaisesRegex(SIGN.GateError, "not Accepted"):
                SIGN.notarize(runner, self.source / "hash.zip",
                              self.private / "release.keychain-db", 60, {})
        self.assertIn("notarization failure log", runner.receipts.read_text())

    def test_redacts_escaped_credentials_in_json_and_urls(self):
        secret = 'password "quoted" & 日本'
        runner = SIGN.Runner({"password": secret}, self.root / "escaped.json")
        for encoded in (secret, json.dumps(secret)[1:-1],
                        json.dumps(secret, ensure_ascii=False)[1:-1],
                        SIGN.quote(secret, safe=""), SIGN.quote_plus(secret, safe="")):
            self.assertEqual(runner.redact(encoded), "[REDACTED]")

    def test_each_code_slice_is_verified_and_inspected(self):
        self.sign()
        inspections = [c for c, _ in self.commands if "--verbose=4" in c and c[0] == "/usr/bin/codesign"]
        for suffix, architectures in ((SIGN.CLI, {"arm64", "x86_64"}),
                                      (SIGN.DYLIB, {"arm64"}), ("standalone/hash", {"arm64", "x86_64"})):
            found = {c[c.index("--arch") + 1] for c in inspections
                     if c[-1].endswith(suffix) and "--arch" in c}
            self.assertEqual(found, architectures)
        verifies = [c for c, _ in self.commands if c[0] == "/usr/bin/codesign" and "--verify" in c]
        self.assertTrue(all("--strict" in c and "--all-architectures" in c for c in verifies))

    def test_changed_global_keychain_state_blocks_completion(self):
        original = self.fake_run
        reads = 0

        def mutate(command, **kwargs):
            nonlocal reads
            result = original(command, **kwargs)
            if command[1:2] == ["list-keychains"]:
                reads += 1
                if reads > 1:
                    return subprocess.CompletedProcess(command, 0, "unexpected keychain", "")
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=mutate):
            with self.assertRaises(SIGN.GateError):
                SIGN.sign_release(self.source, self.output, SECRETS, 60)
        self.assertFalse((self.output / "provenance.json").exists())

    def test_signing_cannot_change_unrelated_component_bytes(self):
        original = self.fake_run

        def mutate(command, **kwargs):
            result = original(command, **kwargs)
            if command[0] == "/usr/bin/codesign" and "--sign" in command:
                (self.output / "component/hash.4dbase/LICENSE").write_bytes(b"unrelated mutation")
            return result

        with patch.object(SIGN.subprocess, "run", side_effect=mutate):
            with self.assertRaisesRegex(SIGN.GateError, "exactly the two"):
                SIGN.sign_release(self.source, self.output, SECRETS, 60)


if __name__ == "__main__":
    unittest.main()
