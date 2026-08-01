# Cpp2IL CLI Contract (probed 2026-07-31)

## Executable Under Test

| Item | Value |
|---|---|
| Published exe | `D:\VSCode\Cpp2IL\Cpp2IL\Cpp2IL\bin\Release\net10.0\Cpp2IL.exe` |
| Published version | `2022.1.0+bb7fbddc4a806c6fa06a4154cbf46eac669f8434` |
| Working exe | `D:\Temp\opencode\cpp2il-build\Cpp2IL.exe` (local `dotnet build`, non-trimmed) |
| Plugin | `Cpp2IL.Plugin.Mfuscator.dll` (deployed; auto-loads from `<cwd>/Plugins`) |
| .NET | 10.0.302 SDK / net10.0 runtime |

## Plugin Discovery

Cpp2IL loads plugins from **`<current-working-directory>/Plugins`** (probe
logged `Loading plugins from D:\Temp\opencode\rt-probe\Plugins...`). The
adapter must therefore run Cpp2IL with `cwd` set to the parent of a
`Plugins/` directory containing `Cpp2IL.Plugin.Mfuscator.dll`.

## Exact Working argv (method-map export)

```
Cpp2IL.exe
  --force-binary-path   <game>\GameAssembly.dll
  --force-metadata-path <game>\global-metadata.dat
  --force-unity-version 6000.1.4f1
  --export-method-map
  --output-to           <workspace>\out
```

- `--export-method-map` writes `method-pointer-map.json` to the output dir
  and exits; it does NOT continue to normal processing.
- No JSON output *format* exists (`--list-output-formats` shows only
  dummydll / dll_* / diffable-cs / isil / wasm*). Mappings JSON file is the
  only JSON artifact; stdout is colored prose and must never be parsed.

## Historical Go/No-Go

- **NO-GO**: the shipped published build is `PublishTrimmed=true` with
  `System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault=false` in its
  runtimeconfig. `--export-method-map` crashes with
  `System.InvalidOperationException: Reflection-based serialization has been
  disabled for this application` at `Program.cs:707`, exit code `0xE0434352`
  (unhandled .NET exception), no output file.
- **GO**: a local non-trimmed build of the same source
  (`dotnet build ... -c Release -f net10.0`; no source modification) with the
  build's `Cpp2IL.runtimeconfig.json` flag flipped to `true` succeeds:
  exit 0, ~11.5s, 206,366 entries, 70.8 MB JSON.
- Adapter must detect the crash signature (exit `0xE0434352` + log text
  "Reflection-based serialization has been disabled") and report an
  actionable validation error pointing at the documented build fix, not a raw
  internal failure.

## Current gate (2026-08-01)

The method-map exporter now projects methods into the concrete
`MethodPointerMapEntry` type and serializes through a generated
`JsonSerializerContext`. The Debug net10.0 runtime still has
`System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault=false`.

Verified against the protected Everlusting metadata with the Mfuscator plugin:

- exit code `0`;
- metadata version `31.1`;
- `Processed 206366 OK`;
- `Wrote 206366 method pointers`;
- method-map SHA-256 `d47e61d4a3d47f18e3fe5e25d225aecaa1fa9188ece18d9e14415370185586f7`.

## Output Shape (`method-pointer-map.json`)

```json
[
  {
    "assembly": "Assembly-CSharp",
    "type": "<>f__AnonymousType0`2",
    "method": "get_groupData",
    "signature": "<groupData>j__TPar <>f__AnonymousType0`2::get_groupData()",
    "pointer": "0x1805CAFA0",
    "rva": "0x5CAFA0"
  }
]
```

- Keys: `assembly`, `type`, `method`, `signature`, `pointer`, `rva`.
- `type` = `Type.FullName` (namespace-qualified; generic arity as `` `N ``).
- `signature` = full identity incl. declaring type + generic params.
- `rva` / `pointer` = hex strings, `0x`-prefixed.

## Exit Codes Observed

| Case | Exit |
|---|---|
| `--version`, `--help`, `--list-*` | 0 |
| Successful method-map export | 0 |
| Unhandled .NET exception | -532462766 (0xE0434352) |

## Runtime

Method-map export of Everlusting (206k methods, 105 MB binary): ~11.5 s on
this machine. Adapter timeout default of 600 s is comfortable.
