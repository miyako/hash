#!/usr/bin/env python3
"""Prepare a deterministic local version commit and portable same-run Git bundle."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publisher", ROOT / "scripts/publish-release.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


def git(root, *args, env=None):
    return subprocess.check_output(["git", *args], cwd=root, env=env, text=True).strip()


def bump(version, increment):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise RuntimeError("package.json requires a numeric major.minor.patch version")
    major, minor, patch = map(int, version.split("."))
    if increment == "major":
        return f"{major + 1}.0.0"
    if increment == "minor":
        return f"{major}.{minor + 1}.0"
    if increment == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise RuntimeError("Increment must be patch, minor or major")


def prepare(root, base, increment, run_id, bundle):
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise RuntimeError("Preparation requires an Actions run ID")
    manifest = root / "package.json"
    original = manifest.read_text()
    current = json.loads(original)["version"]
    publisher.release_identity(root, current, base)
    version = bump(current, increment)
    updated, count = re.subn(r'("version"\s*:\s*")' + re.escape(current) + r'"',
                             lambda match: match[1] + version + '"', original)
    if count != 1:
        raise RuntimeError("package.json must contain exactly one version field")
    manifest.write_text(updated)
    git(root, "add", "--", "package.json")
    tree = git(root, "write-tree")
    # Stable across reruns, independent of runner identity, clock and Git defaults.
    timestamp = git(root, "show", "-s", "--format=%ct", base) + " +0000"
    env = dict(os.environ, GIT_AUTHOR_NAME="github-actions[bot]",
               GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
               GIT_COMMITTER_NAME="github-actions[bot]",
               GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com",
               GIT_AUTHOR_DATE=timestamp, GIT_COMMITTER_DATE=timestamp)
    revision = git(root, "-c", "commit.gpgsign=false", "commit-tree", tree, "-p", base,
                   "-m", f"Release {version} ({increment}; Actions run {run_id})",
                   "-m", "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>",
                   env=env)
    git(root, "checkout", "--detach", revision)
    publisher.release_identity(root, version, revision)
    git(root, "update-ref", "refs/heads/release-prepared", revision)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    git(root, "bundle", "create", str(bundle), "refs/heads/release-prepared")
    return current, version, revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--increment", required=True, choices=["patch", "minor", "major"])
    parser.add_argument("--base", required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--validate-preparation", action="store_true",
                        help="read-only PR exercise of the same bundle handoff; no release APIs")
    args = parser.parse_args()
    if args.validate_preparation:
        if (args.publish or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
                or os.environ.get("GITHUB_REPOSITORY") != publisher.REPOSITORY):
            raise RuntimeError("Preparation validation requires a read-only PR, never publication")
    else:
        publisher.require_context(args.publish)
        if not os.environ.get("GITHUB_REF", "").startswith("refs/heads/"):
            raise RuntimeError("Dispatch from a branch, not a tag")
    api = publisher.GitHub()
    if args.publish:
        main_ref = api.request("GET", "repos/miyako/hash/git/ref/heads/main")
        if main_ref["object"]["sha"] != args.base:
            raise RuntimeError("main moved since dispatch; start a new run from current main")
    current, version, revision = prepare(
        ROOT, args.base, args.increment, os.environ.get("GITHUB_RUN_ID", ""),
        ROOT / "build/release-source/source.bundle")
    if not args.validate_preparation:
        publisher.require_unused(api, version)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"version={version}\nrevision={revision}\nbase={args.base}\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"Prepared **{current} → {version}** ({args.increment}) at `{revision}` "
                      f"from `{args.base}`. Source is a same-run bundle; no remote refs changed.\n")


if __name__ == "__main__":
    main()
