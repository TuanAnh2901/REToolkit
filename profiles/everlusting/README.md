# Everlusting Life reference profile

Portable profile for the Everlusting Life game (`Unity 6000.1.4f1`, IL2CPP,
Mfuscator-obfuscated metadata). No machine-specific paths are committed; every
path resolves from environment variables at runtime.

## Required environment

| Variable | Meaning |
|---|---|
| `RETOOLKIT_GAME_ROOT` | directory containing `GameAssembly.dll` and the `Everlusting Life_Data` folder |
| `RETOOLKIT_WORKSPACE` | writable toolkit workspace (evidence/state/outputs live here) |
| `RETOOLKIT_CPP2IL` | Cpp2IL executable (see `research/cpp2il-contract.md` for the required non-trimmed build) |
| `RETOOLKIT_CPP2IL_PLUGINS` | directory containing `Plugins/Cpp2IL.Plugin.Mfuscator.dll` (the adapter runs Cpp2IL with cwd = its parent so the plugin auto-loads) |
| `RETOOLKIT_GHIDRA` | extracted Ghidra root (optional; Ghidra stage disabled in this profile) |

## What the profile contains

- **Game paths** (env-resolved): assembly + metadata.
- **Fixup rules** (`metadata_fixup`): the verified Mfuscator rebuild contract
  (XXTEA key, mutations, 31-section field map, XOR transforms). Derived from
  `Analysis/metadata_v31_section_map.json` + `CustomMetadataHeaderDecoder.cs`.
  `known_good_hash` = SHA-256 of the rebuilt metadata that Cpp2IL loads
  successfully (206,366 methods).
- **Collision policy**: `keep_all` (the real map has 12 generic-instantiation
  signature collisions that Cpp2IL cannot distinguish textually).
- **Analysis**: `image_base` 0x180000000 for RVA→address conversion; two
  example `ghidra_targets`.

## Provenance / fixtures

- `tests/fixtures/everlusting/header-transform-input.dat` /
  `header-transform-output.dat`: 676-byte XXTEA header vectors from
  `Analysis/global-metadata.custom-header-transform-*.dat`.
- `tests/fixtures/everlusting/fixup-config.json`: identical copy of
  `metadata_fixup` (kept in sync by the acceptance suite).
- Full game binaries/metadata are NOT committed. `global-metadata.dat` is
  ~26 MB proprietary game data; only bounded header fragments are shipped.

## Manual verification

```powershell
py -3.13 -m retoolkit profile validate profiles/everlusting/profile.json --fixture
$env:RETOOLKIT_GAME_ROOT="..."; $env:RETOOLKIT_WORKSPACE="..."
$env:RETOOLKIT_CPP2IL="..."; $env:RETOOLKIT_CPP2IL_PLUGINS="..."
py -3.13 -m retoolkit pipeline plan profiles/everlusting/profile.json
```
