# Mfuscator Deobfuscation Design

**Date:** 2026-08-01  
**Scope:** `D:\VSCode\REToolkit`, `D:\VSCode\Cpp2IL\Cpp2IL`  
**Primary fixture:** `D:\SteamLibrary\steamapps\common\Everlusting Life`

## Goal

Improve Mfuscator metadata recovery by making the verified Everlusting Life loader contract deterministic first, then using the same contract model for source-assisted and structural fallback detection on other Mfuscator 2.x builds.

## Evidence baseline

- The current protected metadata uses a 676-byte randomized header beginning at file offset 4.
- Runtime metadata accesses apply a source bias of 484 bytes.
- The real metadata header fields are interleaved with decoy fields.
- The string-literal-data and strings sections use distinct sequential XOR transforms.
- The protected runtime renames at least one libil2cpp export, including the domain-assembly enumeration export.
- REToolkit already reconstructs the known fixture with a hand-authored profile.
- Cpp2IL already has an exact custom decoder plus a legacy layout search, but its custom path is fixed to one layout and its legacy path accepts the first plausible layout.
- The live Cpp2IL export reaches 206,366 methods before JSON serialization fails when reflection serialization is disabled.

## Architecture

### Shared contract model

Both tools will represent the following concepts explicitly:

- detector evidence and confidence;
- metadata magic and version;
- encrypted-header offset and length;
- header prefix and decryption parameters;
- mutations applied after header decryption;
- canonical section name, randomized offset-field position, randomized size-field position, and descriptor width;
- source bias;
- per-section payload transform;
- export aliases;
- structural validation findings.

The two implementations use language-native types but serialize compatible JSON field names.

### Detection order

1. Match a known-build contract by stable structural evidence.
2. If modified/generated libil2cpp source is supplied, derive the header-field map, source bias, and export aliases from that source.
3. Use binary/static inference only for fields supported by repeatable evidence.
4. Score the rebuilt candidate structurally and reject decoy layouts.

The known-build path remains the fastest path, while successful recovery is no longer accepted on prefix or in-bounds offsets alone.

### REToolkit responsibilities

- Parse randomized `Il2CppGlobalMetadataHeader` declarations.
- Compare modified/original API declaration files to recover export aliases by ordinal and signature.
- Infer a source bias only when the same value is supported by multiple runtime access sites.
- Merge inferred evidence with the exact Everlusting contract.
- Validate reconstructed sections and emit a machine-readable analysis report.
- Add an inspection CLI that writes generated reports/contracts only to a caller-selected output directory.
- Keep the existing profile-driven rebuild interface compatible.

### Cpp2IL responsibilities

- Refactor the exact decoder to consume a contract instead of private layout constants.
- Validate every exact or brute-force candidate before installation.
- Correct Unity-version-to-metadata-version ordering.
- Model both 8-byte and 12-byte section descriptors for newer metadata variants. The scored fallback reconstructs verified 8-byte Offset/Size descriptors; 12-byte Offset/Size/Count layouts are detected and reported until a matching protected fixture proves the shuffled Count mapping.
- Preserve the legacy decoder as a scored fallback.
- Serialize the method pointer map through a source-generated JSON context so trimmed/reflection-disabled builds work.

## Validation rules

A candidate receives findings for:

- metadata magic/version;
- header and section bounds;
- monotonically non-overlapping section ranges where required;
- section alignment;
- byte-size divisibility for sections with known record sizes;
- valid null-terminated string-table samples;
- image, assembly, type-definition, and method-definition index relationships;
- agreement between inferred and known source bias;
- duplicate or contradictory randomized field mappings.

Hard structural failures reject the candidate. Soft findings lower confidence and remain visible in the report.

## Test strategy

All behavior changes follow red-green-refactor.

- Synthetic randomized-header fixtures prove field mapping and decoy rejection.
- Modified/original API fixtures prove export-alias recovery.
- Repeated and conflicting bias fixtures prove majority evidence handling.
- Descriptor fixtures cover 8-byte reconstruction and 12-byte detection/routing without claiming an unverified Count mapping.
- Corrupt metadata fixtures prove candidate rejection.
- The Everlusting fixture proves the known contract, reconstructed metadata hash, Cpp2IL metadata version 31.1, and 206,366 exported methods.
- Existing REToolkit and Cpp2IL tests remain green.

## Output and preservation constraints

- Do not read, write, rename, or delete anything inside any existing `Analysis` directory.
- Any new game dump or reverse-engineering output goes under `D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2`.
- Build/test scratch data may use a timestamped directory under `D:\Temp\opencode`.
- Preserve all pre-existing tracked, modified, and untracked files.
- Store source backups outside `Tools Before` and outside every existing `Analysis` directory.
- Final delivery includes modified artifacts, a patch/diff, an exact verification record, and runnable rollback.

## Non-goals for this pass

- Reimplementing the native Mfuscator protector.
- Blindly accepting layouts based only on offsets being in range.
- Running full-analysis Ghidra CLI.
- Changing or cleaning unrelated Cpp2IL dump/output directories.
