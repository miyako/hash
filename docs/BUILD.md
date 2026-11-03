# Building and verification

## Prerequisites

Use Go **1.25.1**, Python 3.11 or newer, Xcode command-line tooling for `lipo`, and
a locally installed 4D/tool4d engine. Do not install tools globally or mutate a
consumer repository or shared component cache.

The 4D project uses plain untokenized code, a `hash` component class-store name,
and no dependencies. The error handler saves/restores the component's previous
process-local handler. Same-project constructor-failure fixtures deliberately stay
inside a copy of the owning component; no class inherits across component boundaries.

```sh
GOTOOLCHAIN=local CGO_ENABLED=0 go test ./...
python3 scripts/build-native.py
python3 scripts/test-4d.py --engine /absolute/path/to/tool4d
python3 scripts/package-release.py
```

See `python3 scripts/build-native.py --help` for native build controls. Builds
record actual source inputs, toolchain, flags, targets, licenses, and executable
checksums in `Resources/native-provenance.json`, including exact Go driver,
compiler, linker, assembler, and VERSION-file checksums. A cross build does **not** prove
native execution. `.github/workflows/native.yml` retains native macOS Intel/ARM
and Windows x64/ARM runner jobs; queued runners are not failed or passed tests.

The 4D harness creates isolated projects under `build/4d/`, copies all inputs
there, and passes explicit compiled components to `Compile project`. Each compiler
invocation has a separate driver project. No dependency installation cache is used.
The source fixture, production component, and installed host must each produce
`success: true` and **no diagnostics**. Process exit status, a newly written result,
and self-termination are independently required. A report written before an engine
crash does not satisfy the exit-status gate.

The installed-host suite checks empty/abc/binary vectors, same-size byte changes,
missing/unreadable files, Unicode/quotes/metacharacters in input paths, and packaged
resource lookup. The release source directory is renamed away while the host
executes. Source fixtures exercise timeout termination, malformed digest output,
missing executable, invalid options, a null constructor result, and actual
`4D.SystemWorker.new` exceptions (nonexistent working directory and invalid callback).
Only tiny test fixtures use 4D `Generate digest` as an independent oracle.

The `.4DZ` is a standard ZIP with an explicit `Project/` root, directory entries,
`Sources/catalog.4DCatalog`, project/settings metadata, and compiled
`DerivedData/CompiledCode`. Source classes and methods are excluded. Copy native
`Libraries/` and `Resources/` adjacent to `hash.4DZ` within `hash.4dbase`.

## Engines and evidence

Available installed engine: tool4d **21 R4 build 21R4.100208**, ARM64. The installed
licensed full 20.8 application is a separate engine and is not a substitute for
headless-engine evidence.

A near-target headless engine was provisioned through the documented 4D endpoint:

```
https://resources-download.4d.com/release/20.x/20.8/latest/mac/tool4d_arm64.tar.xz
SHA-256 da9c977dd85d4ee506a5d0c115f17d9f27ea487f402f0d642f4f2e1b186b560d
20.8 build 20.102083, ARM64
```

Its strict code-signature verification passed (4D team `37UG5W39Z2`). Downloaded
tooling remains ignored under `tools/4dcli/`. Exact 20.7 remains untested.

Initial 21 R4 runs produced diagnostic-free component and installed-host
compilation and executed the bundled helper successfully from the installed
component for empty/abc/binary/Unicode-path and read-failure cases. Subsequent
runs exposed an engine shutdown failure across 20.8, 21.1 and 21 R4: process signal
11 after writing successful reports, reproducible even with the standalone
`tests/compiler/.../ping.4dm` method (no compilation, component, or helper).
The harness deliberately rejects these local runs. A fresh hosted macOS 15 ARM64
runner with the checksum-pinned 20.8 engine passed source error fixtures,
diagnostic-free component/host compilation, installed execution, packaging, and
execution again after extracting the final ZIP. The hostile runtime host is compiled
at a safe path and then moved: 4D's clang invocation itself cannot compile a source
path containing literal quotes. This does not relax executable or input-path tests.
Publication still requires the complete CI workflow, portable evidence upload,
and native target verification to pass at the exact release source revision.

## Publication gates

Commit source before rebuilding release artifacts so native provenance identifies
the exact immutable source revision. Verify native binaries on actual target hosts.
Require the complete 4D harness, then package with `scripts/package-release.py`.
The latter requires diagnostic-free compiler reports, successful installed-host
verification, matching native source revision, and a clean source tree.

`package-release.py` produces a **pre-sign candidate**, not a publishable release.
Its native checksums describe bytes after local ad-hoc signing but before
Developer ID signing. Keep these records separate from final distribution hashes.

Run the manually dispatched **Signed notarized release** workflow from a
reviewed branch. It prepares one immutable version commit, then calls both native and component workflows in
the same run, checks every native execution receipt against the bundled bytes,
and requires diagnostic-free real compilation and installed execution. Only its
trusted dispatch signing job receives these six repository secrets:

```
APPLE_DEVELOPER_ID_CERTIFICATE
APPLE_DEVELOPER_ID_CERTIFICATE_PASSWORD
KEYCHAIN_PASSWORD
NOTARYTOOL_APPLE_ID
NOTARYTOOL_PASSWORD
NOTARYTOOL_TEAM_ID
```

The certificate is a base64-encoded PKCS#12 bundle. The signing identity must be
a Developer ID Application certificate belonging to `NOTARYTOOL_TEAM_ID`; no
additional identity secret or personal access token is required. Credentials
are imported only into an ephemeral hosted-runner keychain and removed in both
normal cleanup and an always-run workflow step. Pull requests never receive them.

The release signer explicitly signs the actual compiled component library and
the universal embedded CLI, using hardened runtime and secure timestamps.
It does not sign `.4DZ`, JSON, or other resources as executable code. Neither this
compute-only Go CLI nor the ahead-of-time compiled component library needs
JIT/unsigned-executable-memory/disable-library-validation entitlements; host
application permissions are not granted to these payloads.
The checksum-pinned vendor tool4d host already carries
`com.apple.security.cs.disable-library-validation`, allowing separately
Developer-ID-signed component libraries. The release fixture verifies actual
loading after re-signing rather than inferring compatibility from entitlements.

Both `hash.zip` (normal dependency component) and `hash-cli-macOS.zip` (standalone
CLI) must receive explicit notarization `Accepted` results. Accompanying DMGs are
separately signed, notarized, stapled and validated for offline ticket carriage.
ZIPs and raw CLIs cannot be stapled: notarized ZIP distribution relies on Apple's
online ticket lookup. Payload signatures and DMG container signatures/assessments
are checked separately. Windows binaries are not Apple-signed or notarized.

Stapling retries only exit 68 accompanied by a transient `NSURLErrorDomain`
code: timeout (-1001), host lookup/connectivity (-1003/-1004/-1006), connection
lost (-1005), or offline (-1009). Each already Accepted DMG gets at most three
staple attempts, with 5- and 15-second backoffs, at most 60 seconds per attempt,
and a 180-second overall deadline (the last attempt is shortened if necessary).
Retries reuse the same signed DMG without re-signing or resubmitting notarization.
Every attempt retains redacted diagnostics in `signing-receipts.json`; CI progress
identifies the attempt and backoff without printing credentials. Other exit-68
failures, TLS/certificate errors, subprocess timeouts without an explicit
transient network result, and exhausted retries fail closed. Staple validation,
unchanged signatures/CDHashes, Gatekeeper assessment and publication gates remain
mandatory; retrying does not bypass any of them.

After signing/stapling, final file inventories and `SHA256SUMS` are regenerated.
The workflow extracts final `hash.zip`, compiles a clean host against it, and
runs the installed-component suite again. Pre-sign source/build provenance and
final-byte provenance remain distinct; embedded and standalone CLI signatures
can legitimately produce different bytes.

### Manual release interface

Choose `increment`: **patch** (default), **minor**, or **major**. No version typing
or hand-editing of pins is needed. `package.json` is the authoritative numeric
`major.minor.patch` source; the Go CLI embeds that manifest (including its help
banner), and the native builder reads it directly. Minor resets patch; major
resets minor and patch. Prerelease/build-metadata versions are rejected.

The starting version is the manifest in the **dispatch commit**, not the latest
release or a later branch HEAD. The already committed package-only **20.0.2**
edit is preserved as the baseline, not interpreted as an unpublished reservation
or silently changed back to 20.0.1: patch prepares **20.0.3**, minor **20.1.0**,
major **21.0.0**. It does not publish 20.0.2 unchanged. The tag is exactly the
prepared numeric version, with no `v` prefix. Existing tags, public releases and
drafts (including 20.0.1) are never changed; any collision fails, rather than
silently choosing another version.

Preflight creates one clean local commit, changing only `package.json`, directly
on the dispatch SHA. Its identity and timestamp are deterministic for the run,
so rerunning preparation does not bump twice or produce a different source SHA.
A full Git bundle is handed to every native runner, the component job, signing
and publication through the same run's `release-source` artifact. Each consumer
checks out the prepared SHA before executing tests/build scripts. All CLI output,
source inventories, compilation/runtime receipts, provenance, assets and the
eventual tag identify that SHA, **not** `github.sha` (the dispatch parent).
The run summary records both revisions and the version transition.

The read-only **Prepared release source validation** PR workflow exercises this
same preparation, bundle artifact and reusable four-host/component workflow
handoff on a local patch commit. It never calls release APIs, persists a source
ref or runs signing/publication. This is separate from the manual production
workflow, whose signing and publication jobs still exclude PR events.

In GitHub's **Actions** tab, select **Signed notarized release**, then **Run
workflow**. For publication, select branch **main**, choose the increment and
enable **Publish a NEW version from main after all gates**. For a
candidate-only rehearsal, leave that checkbox off (the default); feature branches
are allowed for candidates, but tags are not dispatch sources. Candidates prepare
the same bump and check version availability, but push no commit, branch or tag
and create no GitHub release or draft. The workflow must exist on the default
branch before GitHub exposes manual dispatch in the UI.

Equivalent commands, after checking out the intended reviewed source locally:

```sh
# Candidate only; --ref may instead name the feature branch being rehearsed.
gh workflow run release.yml --repo miyako/hash --ref main \
  -f increment=patch -F publish=false
# Deliberate NEW public release of reviewed main, only after all gates.
gh workflow run release.yml --repo miyako/hash --ref main \
  -f increment=patch -F publish=true
gh run list --repo miyako/hash --workflow release.yml --limit 5
```

These are dispatch instructions, not a request to publish the current version.
The source is the prepared immutable commit, never a moving branch. Publication
requires `main` still equal the dispatch parent both at preflight and after
all signing/runtime gates. If `main` advances, start a new dispatch: never rebase
already tested artifacts onto different source. The workflow accepts only manual dispatch in `miyako/hash`;
publications additionally require `refs/heads/main`. PRs and forks cannot publish.
The existing six Apple secrets above are sufficient; no new secret or personal
access token is needed. All build, preflight and signing jobs have `contents: read`;
only the final publication job receives the built-in token's `contents: write`
and persisted checkout credentials for the guarded fast-forward version push.
Branch protection/rulesets must permit that token to push this commit to `main`
and create a version tag; required PRs or other restrictions can block it. No
PAT, bypass, force rewrite or protection change is provided.
One repository-wide `signed-release` concurrency group serializes candidates and
publications without cancelling an in-progress run. Pending Actions runs can
still be superseded by newer pending runs; this is not an unlimited release queue.
Queued publication dispatches from a now-stale `main` fail rather than consuming
an unexpected version. Full reruns reproduce the same prepared commit and
replace same-run artifacts; partial reruns use the original outputs/bundle.
Once publication has persisted the version commit, rerunning that publication
fails its old-parent check (or an existing-object guard), never bumps again or
resumes remote objects. Start a new dispatch for a new increment.

### Publication, outputs and failure handling

The existing four-host native, real-4D compilation/runtime, Developer ID,
notarization, stapling and extracted signed-component gates remain mandatory.
Only a successful signing job uploads `release-publish-files`, containing the
exact public files. The always-uploaded `signed-release-candidate` artifact is
diagnostic evidence and may be incomplete on failure; it is **never** publication
input. Publication downloads only the named successful artifact from the same
run, validates its exact 15-file set, all final-byte `SHA256SUMS` entries and
source/version/evidence links, then repeats the duplicate tag/release check.

The public asset contract is:

| Assets | Purpose |
|---|---|
| `hash.zip`, `hash.dmg` | Normal 4D dependency component; DMG carries an offline ticket |
| `hash-cli-macOS.zip`, `hash-cli-macOS.dmg` | Standalone macOS CLI in the same component release |
| `SHA256SUMS`, `provenance.json` | Complete final-byte checksums and signed provenance |
| `pre-sign-provenance.json`, `pre-sign-native-verification.json` | Original component/build and four-host native evidence |
| `signing-receipts.json` | Redacted signing/verification command receipts |
| `signed-host-compile.json`, `signed-runtime-verification.json` | Diagnostic-free real-4D signed-component execution |
| `notary-hash.zip.json`, `notary-hash.dmg.json`, `notary-hash-cli-macOS.zip.json`, `notary-hash-cli-macOS.dmg.json` | Four Accepted notarization logs |

After validating all final assets and refusing existing remote objects, the
publisher persists the tested version commit to `main` using an exact-parent
compare-and-swap lease. It independently verifies that the commit is one child
of the dispatch base and changes only `package.json`; the push is fast-forward
only by construction. A concurrent branch update or denied write fails closed.
Only after this post-gate push does it create a **new draft**, uploading all 15 assets without replacement,
checks the remote asset set, uploaded state and sizes, and downloads each asset
through the authenticated API to compare its exact bytes with the validated
candidate. Only then does it create a lightweight version tag at the tested SHA
with the create-only Git ref API, verify that ref, and make the draft public and
GitHub's Latest release. Notes link the exact source and Actions run/attempt.
It rechecks the tag, public release and all downloaded public asset bytes afterward.
The successful run summary links the release. Candidate-only runs stop after
validation and artifact upload without any remote mutation.

No signing or runtime failure can persist a version or reach publication, and no unsigned fallback is
provided. An existing tag, public release **or draft** blocks publication; tags,
releases and assets are never overwritten, resumed, force-pushed or deleted.
API/authentication errors other than an explicit missing-ref 404 fail closed.
Failures after the version push can consume the version on `main` without a
release; it is not rolled back. The next fresh dispatch increments that persisted
baseline. Draft uploads and exact-byte verification precede tag creation, so the
branch push and tag are deliberately separate operations. Upload, checksum,
download or pre-publication API failures can leave an unpublished draft for
inspection, not a partial public release. A failure/cancellation after
tag creation may also leave a tag; after the final public-state transition it may
leave a complete public release even if the post-publication verification fails.
Inspect the run, draft/tag and downloaded evidence before any explicit operator
cleanup; a rerun deliberately refuses those existing objects. The workflow does
not automatically delete them or roll back a public release. Repository rulesets
must allow the publication token to create the new version tag; if they do not,
the run fails rather than bypassing protection.
