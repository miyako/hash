import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_release", ROOT / "scripts/prepare-release.py")
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)
PUBLISH = PREPARE.publisher


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.git("init", "--quiet", "-b", "main")
        (self.root / ".gitignore").write_text("/build/\n")
        # Deliberately model the package-only 20.0.2 edit; stale pins do not
        # participate in the new production version source.
        (self.root / "package.json").write_text('{\n  "version": "20.0.2"\n}\n')
        (self.root / "old-pin.txt").write_text("20.0.1")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Base")
        self.base = self.git("rev-parse", "HEAD")
        self.bundle = self.root / "build/release-source/source.bundle"

    def git(self, *args, root=None):
        root = root or self.root
        if (root / "HEAD").is_file() and not (root / ".git").exists():
            return PREPARE.git(root, f"--git-dir={root}", *args)
        return PREPARE.git(root, *args)

    def prepare(self, increment="patch"):
        return PREPARE.prepare(self.root, self.base, increment, "1234", self.bundle)

    def remote(self):
        remote = Path(self.temp.name) / "remote.git"
        self.git("clone", "--bare", str(self.root), str(remote))
        self.git("remote", "add", "origin", str(remote))
        return remote

    def test_semver_and_package_only_discrepancy_policy(self):
        for increment, expected in (("patch", "20.0.3"), ("minor", "20.1.0"), ("major", "21.0.0")):
            self.assertEqual(PREPARE.bump("20.0.2", increment), expected)
        self.assertEqual(PREPARE.bump("0.9.9", "major"), "1.0.0")
        self.assertEqual(PREPARE.bump("20.9.9", "minor"), "20.10.0")
        for bad in ("v20.0.2", "20.00.2", "20.0.2-rc.1", "20.0.2+meta", "", "1.2"):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                PREPARE.bump(bad, "patch")
        with self.assertRaises(RuntimeError):
            PREPARE.bump("20.0.2", "custom")

    def test_clean_commit_bundle_restore_and_deterministic_rerun(self):
        current, version, revision = self.prepare()
        self.assertEqual((current, version), ("20.0.2", "20.0.3"))
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(self.git("rev-parse", "HEAD^"), self.base)
        self.assertEqual(self.git("diff", "--name-only", self.base, revision), "package.json")
        clone = Path(self.temp.name) / "consumer"
        self.git("clone", "--quiet", "--branch", "release-prepared", str(self.bundle), str(clone))
        self.assertEqual(self.git("rev-parse", "HEAD", root=clone), revision)
        self.assertEqual(self.git("status", "--porcelain", root=clone), "")
        self.assertEqual(json.loads((clone / "package.json").read_text())["version"], version)
        # Cached checkout / rerun restores exactly the same SHA, not another bump.
        self.git("checkout", "--detach", self.base)
        self.assertEqual(self.prepare(), (current, version, revision))
        self.git("fetch", str(self.bundle), "refs/heads/release-prepared", root=clone)
        self.git("checkout", "--detach", revision, root=clone)
        PUBLISH.release_identity(clone, version, revision)

    def test_wrong_base_dirty_tracked_and_untracked_source_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "clean checkout"):
            PREPARE.prepare(self.root, "b" * 40, "patch", "1234", self.bundle)
        for name in ("package.json", "untracked"):
            path = self.root / name
            original = path.read_bytes() if path.exists() else None
            path.write_bytes((original or b"") + b"\n")
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "clean checkout"):
                self.prepare()
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)

    def test_persistence_updates_main_to_exact_tested_commit_and_not_tag(self):
        remote = self.remote()
        _, version, revision = self.prepare()
        api = Mock()
        api.request.side_effect = [
            {"object": {"sha": self.base}}, {"object": {"sha": revision}},
        ]
        PUBLISH.persist_version(api, self.root, self.base, revision)
        self.assertEqual(self.git("rev-parse", "main", root=remote), revision)
        self.assertEqual(self.git("tag", root=remote), "")
        self.assertEqual(self.git("show", "main:package.json", root=remote),
                         '{\n  "version": "20.0.3"\n}')
        self.assertEqual(version, "20.0.3")
        api.request.side_effect = None
        api.request.return_value = {"object": {"sha": revision}}
        with self.assertRaisesRegex(RuntimeError, "main moved"):
            PUBLISH.persist_version(api, self.root, self.base, revision)

    def test_moving_main_race_and_branch_protection_fail_closed(self):
        remote = self.remote()
        _, _, revision = self.prepare()
        api = Mock()
        api.request.return_value = {"object": {"sha": "b" * 40}}
        with self.assertRaisesRegex(RuntimeError, "main moved"):
            PUBLISH.persist_version(api, self.root, self.base, revision)
        # Remote advances after API read: the push lease must refuse it.
        other = self.git("rev-parse", f"{self.base}^{{tree}}")
        competing = self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                             "commit-tree", other, "-p", self.base, "-m", "Concurrent commit")
        self.git("push", "origin", f"{competing}:refs/heads/main")
        api.request.return_value = {"object": {"sha": self.base}}
        with self.assertRaises(subprocess.CalledProcessError):
            PUBLISH.persist_version(api, self.root, self.base, revision)
        self.git("update-ref", "refs/heads/main", self.base, root=remote)
        hook = remote / "hooks/pre-receive"
        hook.write_bytes(b"#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        with self.assertRaises(subprocess.CalledProcessError):
            PUBLISH.persist_version(api, self.root, self.base, revision)
        self.assertEqual(self.git("rev-parse", "main", root=remote), self.base)

    def test_dispatch_branch_checks_and_candidate_has_no_remote_writes(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "miyako/hash",
               "GITHUB_REF": "refs/heads/feature", "GITHUB_RUN_ID": "1234",
               "GITHUB_OUTPUT": str(self.root / "build/output"),
               "GITHUB_STEP_SUMMARY": str(self.root / "build/summary")}
        with patch.dict(os.environ, env, clear=True), patch.object(PREPARE, "ROOT", self.root), \
                patch.object(PUBLISH, "GitHub") as client, \
                patch("sys.argv", ["prepare-release.py", "--base", self.base, "--increment", "patch"]):
            client.return_value.request.side_effect = [None, []]
            PREPARE.main()
            self.assertTrue(all(call.args[0] == "GET" for call in client.return_value.request.call_args_list))
            self.assertIn("version=20.0.3", Path(env["GITHUB_OUTPUT"]).read_text())
        with patch.dict(os.environ, dict(env, GITHUB_REF="refs/tags/20.0.1"), clear=True), \
                patch("sys.argv", ["prepare-release.py", "--base", self.base, "--increment", "patch"]):
            with self.assertRaisesRegex(RuntimeError, "branch, not a tag"):
                PREPARE.main()

    def test_publication_requires_main_and_fresh_dispatch(self):
        env = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "miyako/hash",
               "GITHUB_REF": "refs/heads/feature", "GITHUB_RUN_ID": "1234"}
        arguments = ["prepare-release.py", "--base", self.base, "--increment", "patch", "--publish"]
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", arguments):
            with self.assertRaisesRegex(RuntimeError, "from main"):
                PREPARE.main()
        env["GITHUB_REF"] = "refs/heads/main"
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", arguments), \
                patch.object(PUBLISH, "GitHub") as client, patch.object(PREPARE, "prepare") as prepare:
            client.return_value.request.return_value = {"object": {"sha": "b" * 40}}
            with self.assertRaisesRegex(RuntimeError, "main moved"):
                PREPARE.main()
            prepare.assert_not_called()

    def test_persistence_rejects_non_version_commit(self):
        _, _, revision = self.prepare()
        api = Mock()
        with self.assertRaisesRegex(RuntimeError, "full immutable base"):
            PUBLISH.persist_version(api, self.root, "main", revision)
        with self.assertRaisesRegex(RuntimeError, "change only package.json"):
            PUBLISH.persist_version(api, self.root, self.base, self.base)
        api.request.assert_not_called()

    def test_pr_handoff_validation_never_calls_release_apis(self):
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "miyako/hash",
               "GITHUB_REF": "refs/pull/2/merge", "GITHUB_RUN_ID": "1234",
               "GITHUB_OUTPUT": str(self.root / "build/output"),
               "GITHUB_STEP_SUMMARY": str(self.root / "build/summary")}
        arguments = ["prepare-release.py", "--base", self.base, "--increment", "patch",
                     "--validate-preparation"]
        with patch.dict(os.environ, env, clear=True), patch.object(PREPARE, "ROOT", self.root), \
                patch.object(PUBLISH, "GitHub") as client, patch("sys.argv", arguments):
            PREPARE.main()
            client.return_value.request.assert_not_called()
        for event, publish in (("workflow_dispatch", []), ("pull_request", ["--publish"])):
            with patch.dict(os.environ, dict(env, GITHUB_EVENT_NAME=event), clear=True), \
                    patch("sys.argv", arguments + publish):
                with self.assertRaisesRegex(RuntimeError, "read-only PR"):
                    PREPARE.main()


class WorkflowSourceTests(unittest.TestCase):
    def test_all_consumers_restore_bundle_and_use_prepared_revision(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("type: choice", workflow)
        self.assertIn("default: patch", workflow)
        self.assertNotIn("inputs.version", workflow)
        self.assertEqual(workflow.count("source-revision: ${{ needs.preflight.outputs.revision }}"), 2)
        for name in ("native.yml", "component.yml", "release.yml"):
            content = (ROOT / ".github/workflows" / name).read_text()
            self.assertIn("name: release-source", content)
            self.assertIn('git checkout --detach "$SOURCE_REVISION"', content)
        native = (ROOT / ".github/workflows/native.yml").read_text()
        self.assertNotIn('--source-revision "${{ github.sha }}"', native)

    def test_pr_handoff_exercises_reusable_workflows_without_production_jobs(self):
        validation = (ROOT / ".github/workflows/release-validation.yml").read_text()
        self.assertIn("pull_request:", validation)
        self.assertIn("contents: read", validation)
        for forbidden in ("contents: write", "secrets:", "sign-release.py", "--publish"):
            self.assertNotIn(forbidden, validation)
        self.assertIn("--validate-preparation", validation)
        self.assertIn("uses: ./.github/workflows/native.yml", validation)
        self.assertIn("uses: ./.github/workflows/component.yml", validation)
        self.assertEqual(validation.count("source-revision: ${{ needs.prepare.outputs.revision }}"), 2)


if __name__ == "__main__":
    unittest.main()
