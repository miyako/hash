import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish-release.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)
REVISION = "a" * 40
VERSION = "20.0.2"


class FakeGitHub:
    def __init__(self):
        self.calls = []
        self.release = None
        self.tag = None
        self.assets = []
        self.data = {}
        self.corrupt_download = False
        self.fail_upload = False
        self.race_tag = False
        self.extra_release = None

    def request(self, method, endpoint, data=None, missing_ok=False):
        self.calls.append((method, endpoint, copy.deepcopy(data)))
        if "/git/ref/tags/" in endpoint:
            return self.tag
        if "/releases?per_page=" in endpoint:
            return ([self.release] if self.release else []) + (
                [self.extra_release] if self.extra_release else [])
        if method == "POST" and endpoint.endswith("/releases"):
            self.release = dict(data, id=1, html_url="https://github.com/miyako/hash/releases/tag/20.0.2")
            return self.release
        if method == "POST" and "uploads.github.com" in endpoint:
            if self.fail_upload:
                raise RuntimeError("Upload failed")
            name = unquote(endpoint.split("?name=")[1])
            asset_id = len(self.assets) + 1
            self.assets.append({"name": name, "id": asset_id, "state": "uploaded", "size": len(data)})
            self.data[asset_id] = data
            return self.assets[-1]
        if endpoint.endswith("/assets?per_page=100"):
            return self.assets
        if method == "POST" and endpoint.endswith("/git/refs"):
            if self.race_tag:
                raise RuntimeError("GitHub HTTP 422: ref already exists")
            self.tag = {"object": {"type": "commit", "sha": data["sha"]}}
            return self.tag
        if method == "GET" and endpoint.endswith("/releases/1"):
            return self.release
        if method == "PATCH":
            self.release.update({k: v for k, v in data.items() if k != "make_latest"})
            return self.release
        raise AssertionError((method, endpoint))

    def download(self, asset_id):
        self.calls.append(("DOWNLOAD", asset_id, None))
        return b"corrupted" if self.corrupt_download else self.data[asset_id]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.assets = {name: name.encode() for name in PUBLISH.ASSETS if name != "SHA256SUMS"}
        self.component_files = {"hash.4DZ": "compiled fixture digest"}
        pre_sign = {"version": VERSION, "source_revision": REVISION, "archive_sha256": "pre-sign hash"}
        self.put("pre-sign-provenance.json", pre_sign)
        self.put("pre-sign-native-verification.json", {
            "source_revision": REVISION, "pre_sign_archive_sha256": pre_sign["archive_sha256"],
            "native_execution": {host: {"source_revision": REVISION} for host in PUBLISH.HOSTS},
        })
        self.put("signed-runtime-verification.json", {
            "sourceRevision": REVISION, "sourceDirty": False, "installed": {"success": True},
            "componentFiles": self.component_files,
        })
        self.put("signed-host-compile.json", {"success": True, "errors": []})
        self.manifest = {
            "version": VERSION, "source_revision": REVISION, "component_files": self.component_files,
            "distribution_sha256": {name: PUBLISH.digest(self.assets[name]) for name in PUBLISH.DISTRIBUTIONS},
            "signing_receipts_sha256": PUBLISH.digest(self.assets["signing-receipts.json"]),
            "pre_sign_provenance": self.reference("pre-sign-provenance.json"),
            "pre_sign_native_verification": self.reference("pre-sign-native-verification.json"),
            "signed_runtime_verification": dict(self.reference("signed-runtime-verification.json"),
                                               host_compile=self.reference("signed-host-compile.json")),
            "notarization": {},
        }
        for name in PUBLISH.DISTRIBUTIONS:
            log_name = f"notary-{name}.json"
            self.put(log_name, {"jobId": name, "status": "Accepted", "issues": None})
            self.manifest["notarization"][name] = {
                "id": name, "status": "Accepted", "log": self.reference(log_name),
            }
        self.save()
        self.api = FakeGitHub()

    def put(self, name, data):
        self.assets[name] = json.dumps(data).encode()

    def reference(self, name):
        return {"path": name, "sha256": PUBLISH.digest(self.assets[name])}

    def save(self):
        self.put("provenance.json", self.manifest)
        self.assets["SHA256SUMS"] = "".join(
            f"{PUBLISH.digest(data)}  {name}\n" for name, data in sorted(self.assets.items())
            if name != "SHA256SUMS").encode()
        for name, data in self.assets.items():
            (self.folder / name).write_bytes(data)

    def validate(self):
        return PUBLISH.validate_assets(self.folder, VERSION, REVISION)

    def publish(self):
        return PUBLISH.publish(self.api, VERSION, REVISION, self.assets, "1234", "2")

    def test_exact_fifteen_asset_contract(self):
        self.assertEqual(len(self.validate()), 15)
        self.assertEqual(set(self.validate()), PUBLISH.ASSETS)

    def test_missing_extra_nested_and_symlink_assets_rejected(self):
        (self.folder / "hash.zip").unlink()
        with self.assertRaisesRegex(RuntimeError, "exactly the 15"):
            self.validate()
        self.save()
        extra = self.folder / "unexpected.json"
        extra.write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "exactly the 15"):
            self.validate()
        extra.unlink()
        extra.mkdir()
        with self.assertRaisesRegex(RuntimeError, "exactly the 15"):
            self.validate()
        extra.rmdir()
        target = self.folder / "hash.zip"
        target.unlink()
        target.symlink_to(self.folder / "hash.dmg")
        with self.assertRaisesRegex(RuntimeError, "no links"):
            self.validate()

    def test_final_byte_changes_rejected(self):
        (self.folder / "hash.zip").write_bytes(b"modified")
        with self.assertRaisesRegex(RuntimeError, "SHA256SUMS"):
            self.validate()

    def test_checksum_missing_duplicate_extra_and_path_entries_rejected(self):
        for content in (b"", self.assets["SHA256SUMS"] * 2,
                        self.assets["SHA256SUMS"] + b"0" * 64 + b"  extra.json\n",
                        b"0" * 64 + b"  ../hash.zip\n"):
            with self.subTest(content=content[:60]):
                (self.folder / "SHA256SUMS").write_bytes(content)
                with self.assertRaises(RuntimeError):
                    self.validate()

    def test_source_version_and_distribution_hash_mismatch_rejected(self):
        for key, value in (("source_revision", "b" * 40), ("version", "20.0.1"),
                           ("distribution_sha256", {})):
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = value
                self.save()
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.manifest[key] = original

    def test_evidence_hash_mismatch_rejected_even_with_updated_checksums(self):
        self.assets["signed-runtime-verification.json"] = b"{}"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "hash/path mismatch"):
            self.validate()

    def test_rejects_failed_signed_runtime_and_diagnostics(self):
        runtime = json.loads(self.assets["signed-runtime-verification.json"])
        for key, value in (("sourceRevision", "b" * 40), ("sourceDirty", True),
                           ("installed", {"success": False}), ("componentFiles", {})):
            with self.subTest(key=key):
                changed = dict(runtime, **{key: value})
                self.put("signed-runtime-verification.json", changed)
                self.manifest["signed_runtime_verification"].update(
                    self.reference("signed-runtime-verification.json"))
                self.save()
                with self.assertRaisesRegex(RuntimeError, "real-4D"):
                    self.validate()
        self.put("signed-runtime-verification.json", runtime)
        self.manifest["signed_runtime_verification"].update(self.reference("signed-runtime-verification.json"))
        self.put("signed-host-compile.json", {"success": True, "errors": [{"message": "warning"}]})
        self.manifest["signed_runtime_verification"]["host_compile"] = self.reference("signed-host-compile.json")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "real-4D"):
            self.validate()

    def test_incomplete_native_and_unaccepted_notarization_rejected(self):
        native = json.loads(self.assets["pre-sign-native-verification.json"])
        native["native_execution"].pop(next(iter(PUBLISH.HOSTS)))
        self.put("pre-sign-native-verification.json", native)
        self.manifest["pre_sign_native_verification"] = self.reference("pre-sign-native-verification.json")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Four-host"):
            self.validate()
        self.setUp_notary_failure()
        with self.assertRaisesRegex(RuntimeError, "not explicitly Accepted"):
            self.validate()

    def setUp_notary_failure(self):
        native = json.loads(self.assets["pre-sign-native-verification.json"])
        native["native_execution"] = {host: {"source_revision": REVISION} for host in PUBLISH.HOSTS}
        self.put("pre-sign-native-verification.json", native)
        self.manifest["pre_sign_native_verification"] = self.reference("pre-sign-native-verification.json")
        name = "hash.zip"
        self.put(f"notary-{name}.json", {"jobId": name, "status": "Invalid"})
        self.manifest["notarization"][name]["log"] = self.reference(f"notary-{name}.json")
        self.save()

    def test_draft_round_trip_before_tag_and_publication_then_public_round_trip(self):
        result = self.publish()
        self.assertIs(result["draft"], False)
        calls = self.api.calls
        tag_index = next(i for i, c in enumerate(calls) if c[0] == "POST" and c[1].endswith("/git/refs"))
        patch_index = next(i for i, c in enumerate(calls) if c[0] == "PATCH")
        self.assertEqual(sum(c[0] == "DOWNLOAD" for c in calls[:tag_index]), 15)
        self.assertEqual(sum(c[0] == "DOWNLOAD" for c in calls[patch_index:]), 15)
        self.assertLess(tag_index, patch_index)
        create = next(c[2] for c in calls if c[0] == "POST" and c[1].endswith("/releases"))
        self.assertTrue(create["draft"])
        self.assertEqual(create["target_commitish"], REVISION)
        self.assertEqual(create["tag_name"], VERSION)
        self.assertIn("/actions/runs/1234/attempts/2", create["body"])
        self.assertIn(REVISION, create["body"])
        self.assertEqual(calls[patch_index][2], {"draft": False, "make_latest": "true"})

    def test_existing_tag_and_public_or_draft_release_never_mutated(self):
        for existing in ("tag", "public", "draft"):
            with self.subTest(existing=existing):
                self.api = FakeGitHub()
                if existing == "tag":
                    self.api.tag = {"object": {"type": "commit", "sha": "b" * 40}}
                else:
                    self.api.release = {"id": 2, "tag_name": VERSION, "draft": existing == "draft"}
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    self.publish()
                self.assertTrue(all(c[0] == "GET" for c in self.api.calls))

    def test_upload_and_draft_download_failure_never_tag_or_publish(self):
        for option in ("fail_upload", "corrupt_download"):
            with self.subTest(option=option):
                self.api = FakeGitHub()
                setattr(self.api, option, True)
                with self.assertRaises(RuntimeError):
                    self.publish()
                self.assertTrue(self.api.release["draft"])
                self.assertIsNone(self.api.tag)
                self.assertFalse(any(c[0] in {"PATCH", "DELETE"} for c in self.api.calls))

    def test_tag_creation_race_fails_without_publication_or_overwrite(self):
        self.api.race_tag = True
        with self.assertRaisesRegex(RuntimeError, "422"):
            self.publish()
        self.assertTrue(self.api.release["draft"])
        self.assertFalse(any(c[0] in {"PATCH", "DELETE"} for c in self.api.calls))

    def test_tag_must_be_a_direct_ref_to_tested_commit(self):
        for value in ({"type": "commit", "sha": "b" * 40},
                      {"type": "tag", "sha": REVISION}):
            with self.subTest(value=value):
                self.api.tag = {"object": value}
                with self.assertRaisesRegex(RuntimeError, "exact tested commit"):
                    PUBLISH.require_tag(self.api, VERSION, REVISION)

    def test_candidate_cli_never_calls_remote_and_invalid_assets_block_publish(self):
        arguments = ["publish-release.py", "--version", VERSION, "--revision", REVISION,
                     "--input", str(self.folder)]
        for extra in ([], ["--preflight"]):
            with patch.object(sys, "argv", arguments + extra), \
                    patch.object(PUBLISH, "require_context"), \
                    patch.object(PUBLISH, "release_identity", return_value=VERSION), \
                    patch.object(PUBLISH, "GitHub") as client:
                PUBLISH.main()
                client.return_value.request.assert_not_called()
                client.return_value.download.assert_not_called()
        (self.folder / "hash.zip").write_bytes(b"corrupt")
        with patch.object(sys, "argv", arguments + ["--publish"]), \
                patch.object(PUBLISH, "require_context"), \
                patch.object(PUBLISH, "release_identity", return_value=VERSION), \
                patch.object(PUBLISH, "GitHub") as client:
            with self.assertRaisesRegex(RuntimeError, "SHA256SUMS"):
                PUBLISH.main()
            client.return_value.request.assert_not_called()

    def test_remote_asset_set_state_size_and_release_identity_rejected(self):
        self.publish()
        for key, value in (("target_commitish", "b" * 40), ("tag_name", "wrong"),
                           ("draft", True), ("prerelease", True)):
            with self.subTest(key=key):
                original = self.api.release[key]
                self.api.release[key] = value
                with self.assertRaisesRegex(RuntimeError, "identity/state"):
                    PUBLISH.verify_remote(self.api, 1, VERSION, REVISION, self.assets, draft=False)
                self.api.release[key] = original
        self.api.assets.append(self.api.assets[0])
        with self.assertRaisesRegex(RuntimeError, "asset set"):
            PUBLISH.verify_remote(self.api, 1, VERSION, REVISION, self.assets, draft=False)
        self.api.assets.pop()
        for key, value in (("size", 0), ("state", "starter")):
            with self.subTest(key=key):
                original = self.api.assets[0][key]
                self.api.assets[0][key] = value
                with self.assertRaisesRegex(RuntimeError, "Downloaded release bytes"):
                    PUBLISH.verify_remote(self.api, 1, VERSION, REVISION, self.assets, draft=False)
                self.api.assets[0][key] = original

    def test_duplicate_release_pagination_and_new_competing_draft(self):
        with patch.object(self.api, "request", side_effect=[
                [{"id": n, "tag_name": str(n)} for n in range(100)],
                [{"id": 101, "tag_name": VERSION}]]):
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                PUBLISH.require_release_slot(self.api, VERSION)
        self.api.extra_release = {"id": 2, "tag_name": VERSION, "draft": True}
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.publish()

    def test_version_persistence_happens_after_slot_check_before_draft(self):
        calls = []

        def persist():
            calls.append("persist")
            self.assertTrue(all(call[0] == "GET" for call in self.api.calls))

        PUBLISH.publish(self.api, VERSION, REVISION, self.assets, "1234", "2", persist=persist)
        self.assertEqual(calls, ["persist"])
        self.api = FakeGitHub()
        self.api.tag = {"object": {"type": "commit", "sha": REVISION}}
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            PUBLISH.publish(self.api, VERSION, REVISION, self.assets, "1234", "2", persist=persist)
        self.assertEqual(calls, ["persist"])

    def test_persistence_failure_prevents_draft_or_tag(self):
        def fail():
            raise RuntimeError("Branch protection denied version push")

        with self.assertRaisesRegex(RuntimeError, "Branch protection"):
            PUBLISH.publish(self.api, VERSION, REVISION, self.assets, "1234", "2", persist=fail)
        self.assertTrue(all(call[0] == "GET" for call in self.api.calls))


class IdentityAndTransportTests(unittest.TestCase):
    def version_fixture(self, root):
        (root / "package.json").write_text(json.dumps({"version": VERSION}))
        (root / "scripts").mkdir()
        (root / "scripts/build-native.py").write_text(f'VERSION = "{VERSION}"\n')
        (root / "cli").mkdir()
        (root / "cli/main.go").write_text(
            f'const version = "{VERSION}"\nconst usage = `hash {VERSION}\nhelp\n`\n')

    def test_trusted_dispatch_and_main_only_publication(self):
        good = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "miyako/hash",
                "GITHUB_REF": "refs/heads/main"}
        with patch.dict(os.environ, good, clear=True):
            PUBLISH.require_context(True)
        for key, value in (("GITHUB_EVENT_NAME", "pull_request"),
                           ("GITHUB_EVENT_NAME", "pull_request_target"),
                           ("GITHUB_REPOSITORY", "fork/hash"), ("GITHUB_REF", "refs/heads/feature")):
            with self.subTest(key=key, value=value), patch.dict(os.environ, dict(good, **{key: value}), clear=True):
                with self.assertRaises(RuntimeError):
                    PUBLISH.require_context(True)
                if key == "GITHUB_REF":
                    PUBLISH.require_context(False)

    def test_numeric_version_clean_exact_commit_and_no_implicit_bump(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.version_fixture(root)
            with patch.object(PUBLISH.subprocess, "check_output", side_effect=[REVISION + "\n", ""]):
                self.assertEqual(PUBLISH.release_identity(root, VERSION, REVISION), VERSION)
            for version in ("release20.0.2", "v20.0.2", "20.0.02", "20.0.1", "20.0.2\nbad"):
                with self.subTest(version=version), self.assertRaises(RuntimeError):
                    PUBLISH.release_identity(root, version, REVISION)
            for head, dirty in (("b" * 40, ""), (REVISION, " M package.json")):
                with patch.object(PUBLISH.subprocess, "check_output", side_effect=[head, dirty]):
                    with self.assertRaisesRegex(RuntimeError, "clean checkout"):
                        PUBLISH.release_identity(root, VERSION, REVISION)

    def test_real_git_checkout_and_source_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.version_fixture(root)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

            git("init", "--quiet")
            git("add", ".")
            git("-c", "user.name=Release Test", "-c", "user.email=release@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Version fixture")
            revision = git("rev-parse", "HEAD")
            self.assertEqual(PUBLISH.release_identity(root, VERSION, revision), VERSION)
            with self.assertRaisesRegex(RuntimeError, "exact prepared SHA"):
                PUBLISH.release_identity(root, VERSION, "b" * 40)
            (root / "untracked").write_text("dirty source")
            with self.assertRaisesRegex(RuntimeError, "clean checkout"):
                PUBLISH.release_identity(root, VERSION, revision)
            (root / "untracked").unlink()
            for name in ("scripts/build-native.py", "cli/main.go"):
                path = root / name
                original = path.read_text()
                path.write_text(original.replace(VERSION, "20.0.3"))
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "clean checkout"):
                    PUBLISH.release_identity(root, VERSION, revision)
                path.write_text(original)

    def test_binary_upload_declares_exact_byte_length_without_changing_payload(self):
        response = subprocess.CompletedProcess(
            [], 0, b'HTTP/2.0 201 Created\r\n\r\n{"id":123}', b"")
        for payload in (b"", b"\x00\xffbinary\r\n", "日本語".encode("utf-8")):
            with self.subTest(payload=payload):
                with patch.object(PUBLISH.subprocess, "run", return_value=response) as run:
                    self.assertEqual(PUBLISH.GitHub().request(
                        "POST", "https://uploads.github.com/example", payload), {"id": 123})
                command = run.call_args.args[0]
                self.assertIn(f"Content-Length: {len(payload)}", command)
                self.assertIn("Content-Type: application/octet-stream", command)
                self.assertEqual(command[command.index("--input") + 1], "-")
                self.assertEqual(run.call_args.kwargs["input"], payload)
                self.assertTrue(run.call_args.kwargs["capture_output"])
                self.assertEqual(run.call_args.kwargs["timeout"], 300)
                self.assertFalse(any("Authorization:" in part for part in command))

    def test_json_transport_keeps_json_content_type_and_existing_failure_behavior(self):
        response = subprocess.CompletedProcess([], 0, b'HTTP/2.0 201 Created\r\n\r\n{}', b"")
        with patch.object(PUBLISH.subprocess, "run", return_value=response) as run:
            PUBLISH.GitHub().request("POST", "endpoint", {"draft": True})
        command = run.call_args.args[0]
        self.assertIn("Content-Type: application/json", command)
        self.assertFalse(any(part.startswith("Content-Length:") for part in command))
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"draft": True})

    def test_transport_only_404_is_absence_all_other_failures_stop(self):
        for code in (200, 201, 404, 403, 429, 500):
            with self.subTest(code=code):
                response = subprocess.CompletedProcess([], int(code >= 400),
                    f'HTTP/2.0 {code} Status\nHeader: value\r\n\r\n{{"value":1}}\n'.encode(), b"")
                with patch.object(PUBLISH.subprocess, "run", return_value=response):
                    if code in (200, 201):
                        self.assertEqual(PUBLISH.GitHub().request("GET", "endpoint", missing_ok=True), {"value": 1})
                    elif code == 404:
                        self.assertIsNone(PUBLISH.GitHub().request("GET", "endpoint", missing_ok=True))
                    else:
                        with self.assertRaisesRegex(RuntimeError, f"HTTP {code}"):
                            PUBLISH.GitHub().request("GET", "endpoint", missing_ok=True)
        with patch.object(PUBLISH.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"offline")):
            with self.assertRaisesRegex(RuntimeError, "transport failed"):
                PUBLISH.GitHub().request("GET", "endpoint", missing_ok=True)


class WorkflowGates(unittest.TestCase):
    def test_publication_is_manual_opt_in_read_only_until_all_gates_pass(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("group: signed-release\n  cancel-in-progress: false", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertEqual(workflow.count("contents: write"), 1)
        jobs = workflow.split("\njobs:\n", 1)[1]
        sign = jobs.split("\n  sign:\n", 1)[1].split("\n  publish:\n", 1)[0]
        publish = jobs.split("\n  publish:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", publish)
        self.assertIn("github.repository == 'miyako/hash'", publish)
        self.assertIn("github.ref == 'refs/heads/main'", publish)
        self.assertIn("inputs.publish", publish)
        self.assertIn("needs: [preflight, native, component, sign]", publish)
        self.assertNotIn("always()", publish)
        self.assertNotIn("continue-on-error", workflow)
        self.assertIn("name: release-publish-files", publish)
        self.assertNotIn("signed-release-candidate", publish)
        self.assertNotIn("run-id:", publish)
        self.assertIn("ref: ${{ github.sha }}", publish)
        self.assertIn("persist-credentials: true", publish)
        self.assertIn('--revision "$SOURCE_REVISION" --base-revision "$BASE_REVISION"', publish)
        self.assertIn("git checkout --detach", publish)
        for gate in ("verify-release-inputs.py", "sign-release.py --input",
                     "scripts/test-4d.py", "scripts/finalize-release.py"):
            self.assertIn(gate, sign)
        handoff = sign.split("- name: Handoff only", 1)[1]
        self.assertNotIn("if: always()", handoff)
        self.assertIn("name: release-publish-files", handoff)
        self.assertLess(sign.index("sign-release.py --cleanup"), sign.index("publish-release.py"))
        self.assertLess(sign.index("publish-release.py"), sign.index("- name: Handoff only"))


if __name__ == "__main__":
    unittest.main()
