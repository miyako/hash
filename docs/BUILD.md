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
GOTOOLCHAIN=local CGO_ENABLED=0 go test ./cli
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

Do not tag/publish after a failed gate. When all gates pass, upload `hash.zip`,
`provenance.json`, and `SHA256SUMS` to an independently versioned `20.0.1` release.
Download uploaded draft bytes, compare checksums, extract and rerun the installed
fixture before publishing. Never overwrite an existing version or tag.

No Developer ID signing/notarization is claimed. Go's required macOS ad-hoc
signatures are not Developer ID signatures, notarization, or Gatekeeper approval.
If signing is added, generate checksums again **after** every byte-changing step.
