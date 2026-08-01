# Mfuscator metadata recovery

## Prerequisites

- Python 3.13 with REToolkit installed from this workspace.
- A matching game binary/metadata pair and the Unity version recorded by the game.
- A current Cpp2IL build with the Mfuscator plugin deployed beside the executable.

## Output isolation

Never use an existing directory named `Analysis`. For Everlusting Life, put new reverse-engineering output below:

```text
D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2
```

Temporary Cpp2IL and pipeline output belongs under `D:\Temp\opencode`.

## Source-assisted inspection

```powershell
py -3.13 -m retoolkit mfuscator inspect `
  --metadata 'D:\SteamLibrary\steamapps\common\Everlusting Life\Everlusting Life_Data\il2cpp_data\Metadata\global-metadata.dat' `
  --profile 'profiles\everlusting\profile.json' `
  --modified-header 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\vm\GlobalMetadataFileInternals.h' `
  --modified-runtime 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\vm\GlobalMetadata.cpp' `
  --original-api 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\il2cpp-api-functions.ho' `
  --modified-api 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\il2cpp-api-functions.h' `
  --output-dir 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\mfuscator-20260801'
```

The command writes atomically:

- **mfuscator-contract.json**;
- **mfuscator-analysis.json**;
- **global-metadata.rebuilt.dat**.

## Evidence interpretation

- `source_bias` reports the repeated bias found in runtime metadata accesses.
- `header_layout_match` means source field locations match the known-build contract.
- `header_layout_mismatch` means the supplied generated source uses a different randomized layout. The known-build layout remains active; the source layout is evidence, not an override.
- `export_aliases` records signature-preserving API renames.
- `validation.accepted` must be true before the rebuilt file is passed to Cpp2IL.

Mfuscator randomizes the header per protected build. A libil2cpp source leak can confirm the loader family and algorithms while still carrying a different field permutation.

## Direct Cpp2IL gate

Place the current **Cpp2IL.Plugin.Mfuscator.dll** in `<Cpp2IL cwd>\Plugins`, then run:

```powershell
Cpp2IL.exe `
  --force-binary-path '<game>\GameAssembly.dll' `
  --force-metadata-path '<game>\Everlusting Life_Data\il2cpp_data\Metadata\global-metadata.dat' `
  --force-unity-version 6000.1.4f1 `
  --export-method-map `
  --output-to '<scratch>\cpp2il-output'
```

Expected Everlusting gate:

- custom XXTEA header length: `676`;
- actual metadata version: `31.1`;
- processed/exported method count: `206366`;
- rebuilt metadata SHA-256: `ad9c4ec9b62682c6f6380759c090632469ac932e90ee3668015558d0f6d65dc7`.

## Failure diagnosis

- `metadata.signature`: header prefix or encrypted-header dimensions differ from the selected contract.
- `header.field`: a randomized field offset exceeds the decrypted header.
- `section.bounds`: wrong key, mutation, field permutation, source bias, or corrupt input.
- `section.overlap`: a decoy permutation was selected or descriptor fields conflict.
- source layout mismatch with an accepted known contract: keep the exact contract and treat the source as family-level evidence.
- metadata v38+ / 12-byte descriptors: the plugin reports the detected `Offset/Size/Count` layout and skips the legacy pair-only reconstruction. Capture that protected fixture under `Analysis2` before adding a Count mapper.

## Stop conditions

- Stop before Cpp2IL when `validation.accepted` is false or any section is out of bounds/overlapping.
- Stop source-layout promotion when it disagrees with an exact known-build contract; retain it only as family evidence.
- Stop 12-byte reconstruction after detection until an actual protected v38+ fixture supplies a verifiable Count mapping.

## Verification

```powershell
$out = 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\mfuscator-20260801'
$required = @('mfuscator-contract.json', 'mfuscator-analysis.json', 'global-metadata.rebuilt.dat')
$missing = $required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $out $_) -PathType Leaf) }
if ($missing) { Write-Error ("Missing: " + ($missing -join ', ')); exit 1 }
$analysis = Get-Content -LiteralPath (Join-Path $out 'mfuscator-analysis.json') -Raw | ConvertFrom-Json
if (-not $analysis.validation.accepted) { Write-Error 'Validation rejected'; exit 1 }
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out 'global-metadata.rebuilt.dat')
exit 0
```
