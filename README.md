# hash

Compute-only 4D dependency component, namespace **`cs.hash`**, with its own
streaming SHA-256 executable. No event, worker, provider, model, or cache component
dependencies. File contents never pass through 4D memory.

```4d
var $result : Object
$result:=cs.hash.hash.new().sha256($file)
If ($result.success)
    // $result.digest is exactly 64 lowercase hexadecimal characters.
Else
    // The caller decides how to present or log $result.message.
End if
```

`$file` is a `4D.File`. Optional second argument `{timeout: 300}` sets the hash
process deadline in seconds (greater than zero, maximum 86400). Default: 300.
Execution is synchronous, suitable for a caller's existing background worker.
On Windows an additional bounded architecture probe (at most two seconds) selects
the ARM64 helper when running on Windows ARM. No shell or PowerShell is used.
The x64 bootstrap uses Windows `IsWow64Process2`, not CPU-name or environment-variable
heuristics. Windows ARM requires x64 emulation for this bootstrap (also needed by
an x64 4D host). Older x64 Windows versions predating that API keep their native
x64 target.

Every result contains `success`, `digest`, `algorithm` (`"sha256"`), `message`,
`code`, `stderr`, `stdout`, `timedOut`, and `errors`. `exitCode` is present when
available. Failures always have `success=False` and an empty digest. Constructor
exceptions, missing resources, native read errors, nonzero exits, malformed output,
and deadlines are failures, never success-shaped fallbacks. Original CLI diagnostics
remain in `stderr`; 4D error objects remain in `errors`.

The component does not cache digests, compare expected values, or decide integrity
policy. A digest describes bytes read during the call, not a filesystem snapshot;
callers must prevent concurrent changes when a stable-file guarantee is required.

## Installation

The initial intended version is **20.0.1**. A release must pass the native and 4D
gates described in [BUILD.md](docs/BUILD.md) before publication. Do not treat a
source tag or an archive's existence as proof of a released, verified component.

For manual installation, extract `hash.zip` and place `hash.4dbase` in the host
project's `Components/` directory. It contains `hash.4DZ`, `Libraries/`, and
`Resources/` together; do not install the `.4DZ` alone. For the 4D dependency
manager, pin repository `miyako/hash` to the exact published release tag in
`Project/Sources/dependencies.json`; do not use a moving `latest` tag.

Declared source compatibility: **4D 20.7 LTS** (`compatibilityVersion: 2007`).
Exact 20.7 execution is not available on the build host; this remains a documented
compatibility gap. Engine-specific verification evidence accompanies release
artifacts rather than being inferred from this declaration.

## Bundled helper

| Resource | Target |
|---|---|
| `Resources/bin/macOS/hash` | Universal macOS ARM64 + x86-64 |
| `Resources/bin/Windows/hash.exe` | Windows x64 |
| `Resources/bin/WindowsARM/hash.exe` | Windows ARM64 |

The macOS helper requires **macOS 12 Monterey or newer** (Go 1.25 minimum;
both Mach-O slices declare minimum OS 12.0).

The Go standard library performs streaming SHA-256 with a fixed-size buffer.
CGO is disabled. A JSON object `{"path":"native filesystem path"}` is sent over
UTF-8 stdin; file paths never appear in command-line arguments. Only regular files
are accepted. Successful stdout is **64 lowercase hex characters plus LF**;
errors go to stderr with a nonzero exit code.

`--version`, `--help`, and `--architecture` are the only helper arguments. The
architecture probe is a fixed argument, not a shell command. Bundled resource
lookup never falls back to `PATH` or a separately installed executable.
