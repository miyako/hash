#!/usr/bin/env python3
"""Publish only a complete, same-run signed candidate; never replace remote objects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "miyako/hash"
DISTRIBUTIONS = {"hash.zip", "hash.dmg", "hash-cli-macOS.zip", "hash-cli-macOS.dmg"}
ASSETS = DISTRIBUTIONS | {
    f"notary-{name}.json" for name in DISTRIBUTIONS
} | {
    "SHA256SUMS", "provenance.json", "pre-sign-provenance.json",
    "pre-sign-native-verification.json", "signing-receipts.json",
    "signed-host-compile.json", "signed-runtime-verification.json",
}
HOSTS = {"native-macos-15-intel", "native-macos-15",
         "native-windows-2025", "native-windows-11-arm"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GitHub:
    """Use gh's authenticated transport, including authenticated draft downloads."""

    def request(self, method, endpoint, data=None, missing_ok=False):
        command = ["gh", "api", "--include", "--method", method, endpoint,
                   "-H", "X-GitHub-Api-Version: 2022-11-28"]
        payload = None
        if data is not None:
            binary = isinstance(data, bytes)
            payload = data if binary else json.dumps(data).encode()
            command += ["--input", "-", "-H", "Content-Type: " + (
                "application/octet-stream" if binary else "application/json")]
            if binary:
                # uploads.github.com rejects unknown-length stdin bodies.
                command += ["-H", f"Content-Length: {len(payload)}"]
        result = subprocess.run(command, input=payload, capture_output=True, timeout=300)
        header, separator, body = result.stdout.partition(b"\r\n\r\n")
        if not separator:
            header, separator, body = result.stdout.partition(b"\n\n")
        status = re.match(rb"HTTP/\S+ (\d{3})", header)
        if not separator or not status:
            raise RuntimeError(f"GitHub transport failed: {method} {endpoint}")
        code = int(status[1])
        if code == 404 and missing_ok:
            return None
        if result.returncode or not 200 <= code < 300:
            raise RuntimeError(f"GitHub HTTP {code}: {method} {endpoint}")
        return json.loads(body) if body.strip() else None

    def download(self, asset_id):
        return subprocess.check_output([
            "gh", "api", f"repos/{REPOSITORY}/releases/assets/{asset_id}",
            "-H", "Accept: application/octet-stream",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
        ], timeout=300)


def release_identity(root, version, revision):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise RuntimeError("Version must be a numeric major.minor.patch without a tag prefix")
    if json.loads((root / "package.json").read_text())["version"] != version:
        raise RuntimeError("Requested version differs from committed package.json")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("Release source must be a full immutable commit SHA")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output([
        "git", "status", "--porcelain", "--untracked-files=normal",
    ], cwd=root, text=True).strip()
    if head != revision or dirty:
        raise RuntimeError("Release requires a clean checkout of the exact prepared SHA")
    return version


def require_context(publish):
    if (os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY):
        raise RuntimeError("Releases require a manual dispatch in miyako/hash, never PRs or forks")
    if publish and os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise RuntimeError("Public releases must be dispatched from main")


def require_release_slot(api, tag, owned_id=None):
    # Listing also finds drafts, which the by-tag endpoint may not return.
    page = 1
    while True:
        releases = api.request("GET", f"repos/{REPOSITORY}/releases?per_page=100&page={page}")
        if any(release["tag_name"] == tag and release["id"] != owned_id for release in releases):
            raise RuntimeError(f"Release or draft {tag} already exists; never resume or replace it")
        if len(releases) < 100:
            break
        page += 1


def require_unused(api, tag, owned_id=None):
    if api.request("GET", f"repos/{REPOSITORY}/git/ref/tags/{tag}", missing_ok=True) is not None:
        raise RuntimeError(f"Tag {tag} already exists; never overwrite it")
    require_release_slot(api, tag, owned_id)


def validate_assets(folder, version, revision):
    paths = list(folder.iterdir())
    if ({p.name for p in paths} != ASSETS
            or any(p.is_symlink() or not p.is_file() for p in paths)):
        raise RuntimeError("Final release must contain exactly the 15 public assets, no links or directories")
    assets = {p.name: p.read_bytes() for p in paths}
    checksums = {}
    for line in assets["SHA256SUMS"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in checksums:
            raise RuntimeError("Malformed or duplicate SHA256SUMS entry")
        checksums[match[2]] = match[1]
    if checksums != {name: digest(data) for name, data in assets.items() if name != "SHA256SUMS"}:
        raise RuntimeError("SHA256SUMS must cover every final asset exactly, with matching bytes")
    manifest = json.loads(assets["provenance.json"])
    pre_sign = json.loads(assets["pre-sign-provenance.json"])
    for evidence in (manifest, pre_sign):
        if evidence["version"] != version or evidence["source_revision"] != revision:
            raise RuntimeError("Version/source provenance does not match the dispatch")
    if manifest["distribution_sha256"] != {name: digest(assets[name]) for name in DISTRIBUTIONS}:
        raise RuntimeError("Final distribution hashes do not match provenance")

    def require_reference(reference, name):
        if reference != {"path": name, "sha256": digest(assets[name])}:
            raise RuntimeError(f"Provenance evidence hash/path mismatch: {name}")

    require_reference(manifest["pre_sign_provenance"], "pre-sign-provenance.json")
    require_reference(manifest["pre_sign_native_verification"], "pre-sign-native-verification.json")
    runtime_reference = dict(manifest["signed_runtime_verification"])
    require_reference(runtime_reference.pop("host_compile"), "signed-host-compile.json")
    require_reference(runtime_reference, "signed-runtime-verification.json")
    if manifest["signing_receipts_sha256"] != digest(assets["signing-receipts.json"]):
        raise RuntimeError("Signing receipts hash mismatch")
    native = json.loads(assets["pre-sign-native-verification.json"])
    if (native["source_revision"] != revision
            or native["pre_sign_archive_sha256"] != pre_sign["archive_sha256"]
            or set(native["native_execution"]) != HOSTS
            or any(item["source_revision"] != revision for item in native["native_execution"].values())):
        raise RuntimeError("Four-host native evidence must bind the same pre-sign source/archive")
    runtime = json.loads(assets["signed-runtime-verification.json"])
    report = json.loads(assets["signed-host-compile.json"])
    if (runtime["sourceRevision"] != revision or runtime["sourceDirty"]
            or runtime["installed"].get("success") is not True
            or runtime["componentFiles"] != manifest["component_files"]
            or report.get("success") is not True or report.get("errors")):
        raise RuntimeError("Signed real-4D execution/compilation evidence is incomplete")
    if set(manifest["notarization"]) != DISTRIBUTIONS:
        raise RuntimeError("Both ZIPs and both DMGs require notarization evidence")
    for name in DISTRIBUTIONS:
        receipt = manifest["notarization"][name]
        log_name = f"notary-{name}.json"
        require_reference(receipt["log"], log_name)
        log = json.loads(assets[log_name])
        if (receipt["status"] != "Accepted" or log["status"] != "Accepted"
                or log["jobId"] != receipt["id"] or log.get("issues")):
            raise RuntimeError(f"Notarization was not explicitly Accepted: {name}")
    return assets


def verify_remote(api, release_id, tag, revision, assets, draft):
    release = api.request("GET", f"repos/{REPOSITORY}/releases/{release_id}")
    if (release["id"] != release_id or release["tag_name"] != tag
            or release["target_commitish"] != revision or release["draft"] is not draft
            or release["prerelease"] is not False):
        raise RuntimeError("Remote release identity/state changed")
    remote = api.request("GET", f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100")
    if len(remote) != len(assets) or {a["name"] for a in remote} != set(assets):
        raise RuntimeError("Remote release asset set differs from finalized candidate")
    for asset in remote:
        expected = assets[asset["name"]]
        if (asset["state"] != "uploaded" or asset["size"] != len(expected)
                or api.download(asset["id"]) != expected):
            raise RuntimeError(f"Downloaded release bytes differ: {asset['name']}")
    return release


def require_tag(api, tag, revision):
    ref = api.request("GET", f"repos/{REPOSITORY}/git/ref/tags/{tag}")
    if ref["object"]["type"] != "commit" or ref["object"]["sha"] != revision:
        raise RuntimeError("Release tag does not point directly to the exact tested commit")


def persist_version(api, root, base, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise RuntimeError("Publication requires a full immutable base SHA")
    parents = subprocess.check_output(
        ["git", "rev-list", "--parents", "-n", "1", revision], cwd=root, text=True).split()
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", base, revision], cwd=root, text=True).splitlines()
    if parents != [revision, base] or changed != ["package.json"]:
        raise RuntimeError("Prepared commit must change only package.json directly on the dispatch base")
    remote = api.request("GET", f"repos/{REPOSITORY}/git/ref/heads/main")
    if remote["object"]["sha"] != base:
        raise RuntimeError("main moved during release; start a new dispatch, never rebase tested bytes")
    # This lease is a compare-and-swap, not permission to rewrite history: the
    # checked commit is exactly one child of base. Branch protection still applies.
    subprocess.run([
        "git", "push", "--porcelain", f"--force-with-lease=refs/heads/main:{base}",
        "origin", f"{revision}:refs/heads/main",
    ], cwd=root, check=True, timeout=120)
    persisted = api.request("GET", f"repos/{REPOSITORY}/git/ref/heads/main")
    if persisted["object"]["sha"] != revision:
        raise RuntimeError("main changed after persisting the tested version commit")


def publish(api, tag, revision, assets, run_id, attempt, persist=None):
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
        raise RuntimeError("Publication requires a valid Actions run ID and attempt")
    require_unused(api, tag)
    if persist is not None:
        persist()
    run_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
    notes = (
        f"hash {tag}: signed and notarized component and standalone macOS CLI.\n\n"
        f"Source: https://github.com/{REPOSITORY}/commit/{revision}\n"
        f"Verification/signing run: {run_url}\n\n"
        "Install `hash.zip` as the normal 4D dependency component. Standalone CLI "
        "ZIP/DMG assets are part of this same release. Both DMGs carry stapled "
        "offline notarization tickets; ZIPs use online ticket lookup. Windows "
        "helpers are not Apple-signed. See `SHA256SUMS` for final-byte hashes and "
        "`provenance.json` plus the accompanying native, 4D, signing and "
        "notarization evidence. Exact 4D 20.7 execution remains unverified.\n"
    )
    release = api.request("POST", f"repos/{REPOSITORY}/releases", {
        "tag_name": tag, "target_commitish": revision, "name": f"hash {tag}",
        "body": notes, "draft": True, "prerelease": False,
    })
    release_id = release["id"]
    # No automatic deletion or retry: an ambiguous API failure must not mutate
    # someone else's objects or accidentally publish a partially uploaded draft.
    print(f"Created draft {release_id}; failures leave it private for inspection", flush=True)
    for name, data in sorted(assets.items()):
        api.request("POST", f"https://uploads.github.com/repos/{REPOSITORY}/releases/"
                    f"{release_id}/assets?name={quote(name)}", data)
    verify_remote(api, release_id, tag, revision, assets, draft=True)
    require_unused(api, tag, owned_id=release_id)
    # Create-only ref API is the no-overwrite guard, including races outside Actions.
    api.request("POST", f"repos/{REPOSITORY}/git/refs",
                {"ref": f"refs/tags/{tag}", "sha": revision})
    require_tag(api, tag, revision)
    require_release_slot(api, tag, owned_id=release_id)
    api.request("PATCH", f"repos/{REPOSITORY}/releases/{release_id}",
                {"draft": False, "make_latest": "true"})
    require_tag(api, tag, revision)
    published = verify_remote(api, release_id, tag, revision, assets, draft=False)
    print(f"Published and verified {published['html_url']}")
    return published


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--base-revision", help="dispatch parent of the prepared version commit")
    parser.add_argument("--input", type=Path, default=ROOT / "build/publish-files")
    args = parser.parse_args()
    require_context(args.publish)
    tag = release_identity(ROOT, args.version, args.revision)
    api = GitHub()
    if args.preflight:
        if args.publish:
            require_unused(api, tag)
        print(f"Confirmed prepared version/tag {tag} at {args.revision}")
        return
    assets = validate_assets(args.input, args.version, args.revision)
    if args.publish:
        if not args.base_revision:
            raise RuntimeError("Publication requires the prepared commit's --base-revision")
        result = publish(api, tag, args.revision, assets,
                         os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                         persist=lambda: persist_version(api, ROOT, args.base_revision, args.revision))
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
            summary.write(f"Published [{tag}]({result['html_url']}) from `{args.revision}`.\n")
    else:
        print(f"Validated {len(assets)} final assets; candidate only, no remote mutation")


if __name__ == "__main__":
    main()
