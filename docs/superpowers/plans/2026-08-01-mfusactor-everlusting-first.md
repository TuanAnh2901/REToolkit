# Mfuscator Everlusting-First Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the Everlusting Life Mfuscator metadata deterministically, validate candidates structurally, reuse source-derived loader evidence, and export a complete Cpp2IL method map from reflection-disabled builds.

**Architecture:** REToolkit owns source-assisted contract generation, reporting, and orchestration. Cpp2IL consumes an equivalent contract for exact recovery and validates legacy-search candidates before accepting them. The verified Everlusting contract is the fast path; inference adds evidence rather than weakening acceptance rules.

**Tech Stack:** Python 3.13, pytest, C#/.NET, NUnit, System.Text.Json source generation, Cpp2IL/LibCpp2IL.

## Global Constraints

- Do not read, write, rename, or delete anything inside an existing directory named `Analysis`.
- Put every new game dump or reverse-engineering output under `D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2`.
- Put timestamped backups under `D:\Temp\opencode\mfuscator-upgrade-<timestamp>` and outside `Tools Before`.
- Preserve every pre-existing tracked modification and untracked artifact in both repositories.
- REToolkit currently has no commits and its source tree is untracked; Cpp2IL has active Mfuscator modifications. Work in place with byte-for-byte backups instead of creating worktrees that omit this baseline.
- Use TDD for every behavior change: add one failing test, run it and record the expected failure, add minimal production code, rerun the focused test, then rerun the relevant suite.
- Do not run full-analysis Ghidra CLI.
- Use deterministic static analysis only; no game process launch is required for metadata reconstruction.

---

## File map

### REToolkit

- Create `src/retoolkit/metadata/mfuscator_contract.py`: immutable contract/evidence types and JSON conversion.
- Create `src/retoolkit/metadata/mfuscator_source.py`: randomized-header, source-bias, and export-alias parsers.
- Create `src/retoolkit/metadata/mfuscator_validate.py`: structural validation and candidate scoring.
- Modify `src/retoolkit/metadata/mfuscator.py`: rebuild through `MfuscatorContract`, keep `FixupConfig` compatibility, return an optional report.
- Modify `src/retoolkit/cli.py`: add `mfuscator inspect` command.
- Create `tests/test_mfuscator_contract.py`.
- Create `tests/test_mfuscator_source.py`.
- Create `tests/test_mfuscator_validate.py`.
- Modify `tests/test_mfuscator.py` and `tests/test_cli_contract.py`.
- Create `docs/runbooks/mfuscator-recovery.md`.

### Cpp2IL

- Create `Cpp2IL.Plugin.Mfuscator/MfuscatorMetadataContract.cs`: contract and Everlusting fast-path definition.
- Create `Cpp2IL.Plugin.Mfuscator/MfuscatorMetadataValidator.cs`: validation findings and score.
- Modify `Cpp2IL.Plugin.Mfuscator/CustomMetadataHeaderDecoder.cs`: contract-driven exact decode/rebuild.
- Modify `Cpp2IL.Plugin.Mfuscator/MfuscatorSupportPlugin.cs`: corrected version mapping and validated candidate selection.
- Create `Cpp2IL.Plugin.Mfuscator.Tests/MfuscatorMetadataContractTests.cs`.
- Create `Cpp2IL.Plugin.Mfuscator.Tests/MfuscatorMetadataValidatorTests.cs`.
- Modify `Cpp2IL.Plugin.Mfuscator.Tests/CustomMetadataHeaderDecoderTests.cs`.
- Create `Cpp2IL/MethodPointerMapEntry.cs`.
- Create `Cpp2IL/Cpp2IlJsonSerializerContext.cs`.
- Modify `Cpp2IL/Program.cs`: serialize typed entries with source-generated metadata.
- Create `Cpp2IL.Core.Tests/MethodPointerMapSerializationTests.cs`.

---

### Task 1: Preserve the baseline and create verification roots

**Files:**
- Create outside repositories: `D:\Temp\opencode\mfuscator-upgrade-<timestamp>\baseline\...`
- Create if absent: `D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2`

**Interfaces:**
- Produces: `$BackupRoot`, SHA-256 manifests, baseline test logs, and baseline repository status.

- [ ] **Step 1: Resolve safe absolute paths and copy source baselines**

```powershell
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupRoot = "D:\Temp\opencode\mfuscator-upgrade-$Stamp"
$Analysis2 = 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2'
New-Item -ItemType Directory -Force -Path "$BackupRoot\baseline", $Analysis2 | Out-Null
Copy-Item -LiteralPath 'D:\VSCode\REToolkit' -Destination "$BackupRoot\baseline\REToolkit" -Recurse
Copy-Item -LiteralPath 'D:\VSCode\Cpp2IL\Cpp2IL\Cpp2IL.Plugin.Mfuscator' -Destination "$BackupRoot\baseline\Cpp2IL.Plugin.Mfuscator" -Recurse
Copy-Item -LiteralPath 'D:\VSCode\Cpp2IL\Cpp2IL\Cpp2IL.Plugin.Mfuscator.Tests' -Destination "$BackupRoot\baseline\Cpp2IL.Plugin.Mfuscator.Tests" -Recurse
```

Expected: all resolved backup targets begin with `D:\Temp\opencode\mfuscator-upgrade-`; none contains `Tools Before` or ends in `\Analysis`.

- [ ] **Step 2: Record hashes and repository state**

```powershell
Get-ChildItem "$BackupRoot\baseline" -File -Recurse |
  Get-FileHash -Algorithm SHA256 |
  Sort-Object Path |
  ConvertTo-Json -Depth 3 |
  Set-Content "$BackupRoot\baseline-sha256.json" -Encoding UTF8
git -C 'D:\VSCode\REToolkit' status --short | Set-Content "$BackupRoot\retoolkit-status.txt"
git -C 'D:\VSCode\Cpp2IL\Cpp2IL' status --short | Set-Content "$BackupRoot\cpp2il-status.txt"
```

- [ ] **Step 3: Run and capture the existing suites**

```powershell
py -3.13 -m pytest -q 2>&1 | Tee-Object "$BackupRoot\retoolkit-baseline-tests.log"
dotnet test 'Cpp2IL.Plugin.Mfuscator.Tests\Cpp2IL.Plugin.Mfuscator.Tests.csproj' -c Debug --no-restore 2>&1 |
  Tee-Object "$BackupRoot\cpp2il-mfusactor-baseline-tests.log"
```

Expected: REToolkit `119 passed, 5 skipped`; plugin tests `4 passed, 0 failed`.

---

### Task 2: Add the REToolkit contract and source-evidence parser

**Files:**
- Create: `src/retoolkit/metadata/mfuscator_contract.py`
- Create: `src/retoolkit/metadata/mfuscator_source.py`
- Test: `tests/test_mfuscator_contract.py`
- Test: `tests/test_mfuscator_source.py`

**Interfaces:**
- Produces: `MfuscatorContract`, `SectionContract`, `PayloadTransformContract`, `Evidence`, `parse_randomized_header`, `infer_source_bias`, and `infer_export_aliases`.

- [ ] **Step 1: Write failing contract round-trip and randomized-header tests**

```python
def test_contract_json_round_trip_preserves_field_offsets() -> None:
    contract = MfuscatorContract(
        name="fixture", metadata_magic=0xFAB11BAF, metadata_version=31,
        header_prefix=bytes.fromhex("e1b06cfe"), header_offset=4,
        header_length=676, payload_start=684, preserved_tail_start=256,
        source_bias=484, xxtea_key=b"fc48e86b730833ef",
        sections=(SectionContract("methods", 44, 144),),
    )
    assert MfuscatorContract.from_json(contract.to_json()) == contract

def test_parse_randomized_header_ignores_decoys_and_returns_byte_offsets() -> None:
    source = """typedef struct Il2CppGlobalMetadataHeader {
      int32_t fakeA; int32_t methodsOffset; int32_t fakeB;
      int32_t methodsSize; int32_t sanity; int32_t version;
    } Il2CppGlobalMetadataHeader;"""
    result = parse_randomized_header(source, {"methodsOffset", "methodsSize", "sanity", "version"})
    assert result == {"methodsOffset": 4, "methodsSize": 12, "sanity": 16, "version": 20}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `py -3.13 -m pytest tests/test_mfuscator_contract.py tests/test_mfuscator_source.py -q`

Expected: import failure for `retoolkit.metadata.mfuscator_contract` and `retoolkit.metadata.mfuscator_source`.

- [ ] **Step 3: Implement immutable contract types and field parsing**

```python
@dataclass(frozen=True)
class SectionContract:
    name: str
    custom_offset_field: int
    custom_size_field: int
    record_size: int | None = None
    alignment: int = 4
    payload_transform: PayloadTransformContract | None = None

@dataclass(frozen=True)
class MfuscatorContract:
    name: str
    metadata_magic: int
    metadata_version: int
    header_prefix: bytes
    header_offset: int
    header_length: int
    payload_start: int
    preserved_tail_start: int
    source_bias: int
    xxtea_key: bytes
    sections: tuple[SectionContract, ...]
    mutations: tuple[MutationContract, ...] = ()
    export_aliases: tuple[ExportAlias, ...] = ()
    evidence: tuple[Evidence, ...] = ()
```

`parse_randomized_header` tokenizes only `int32_t <identifier>;` declarations inside the named struct and returns `field_index * 4` for canonical names.

- [ ] **Step 4: Add failing repeated-bias and export-alias tests**

```python
def test_infer_source_bias_requires_repeated_agreement() -> None:
    source = """
      s_GlobalMetadataHeader->methodsOffset + 484;
      s_GlobalMetadataHeader->typesOffset + 484;
      s_GlobalMetadataHeader->fieldsOffset + 12;
    """
    result = infer_source_bias(source, minimum_support=2)
    assert result.value == 484
    assert result.support == 2

def test_infer_export_aliases_matches_same_api_slot() -> None:
    original = "DO_API(const Il2CppAssembly**, il2cpp_domain_get_assemblies, (const Il2CppDomain*, size_t*));"
    modified = "DO_API(const Il2CppAssembly**, ab626d_wasting_your_life, (const Il2CppDomain*, size_t*));"
    assert infer_export_aliases(original, modified)[0].canonical == "il2cpp_domain_get_assemblies"
```

- [ ] **Step 5: Verify RED, implement evidence parsers, and verify GREEN**

Run the focused tests before and after implementation. Expected final result: all tests in both new files pass.

- [ ] **Step 6: Save an exact checkpoint patch**

```powershell
git diff --no-index -- "$BackupRoot\baseline\REToolkit\src\retoolkit\metadata" 'D:\VSCode\REToolkit\src\retoolkit\metadata' |
  Set-Content "$BackupRoot\task2-retoolkit-metadata.patch"
```

---

### Task 3: Add REToolkit structural validation and contract-driven rebuild

**Files:**
- Create: `src/retoolkit/metadata/mfuscator_validate.py`
- Modify: `src/retoolkit/metadata/mfuscator.py`
- Test: `tests/test_mfuscator_validate.py`
- Modify: `tests/test_mfuscator.py`

**Interfaces:**
- Consumes: `MfuscatorContract` from Task 2.
- Produces: `ValidationFinding`, `ValidationReport`, `validate_candidate(data, contract, descriptors)`, and `rebuild_with_report(data, contract)`.

- [ ] **Step 1: Write failing validator tests**

```python
def test_validator_rejects_out_of_bounds_and_record_remainder() -> None:
    contract = fixture_contract(record_size=8)
    report = validate_candidate(bytes(64), contract, ((60, 8),))
    assert report.accepted is False
    assert {f.code for f in report.findings} == {"section.bounds", "section.record_size"}

def test_validator_rejects_overlapping_nonempty_sections() -> None:
    contract = fixture_contract(section_count=2)
    report = validate_candidate(bytes(256), contract, ((64, 64), (96, 64)))
    assert report.accepted is False
    assert any(f.code == "section.overlap" for f in report.findings)
```

- [ ] **Step 2: Verify RED**

Run: `py -3.13 -m pytest tests/test_mfuscator_validate.py -q`

Expected: missing validator module.

- [ ] **Step 3: Implement deterministic findings and score**

```python
@dataclass(frozen=True)
class ValidationFinding:
    code: str
    severity: Literal["error", "warning", "info"]
    section: str | None
    message: str

@dataclass(frozen=True)
class ValidationReport:
    accepted: bool
    score: int
    findings: tuple[ValidationFinding, ...]
```

Errors subtract 100 points, warnings subtract 10, confirmed structural checks add one, and `accepted` is true only when no error finding exists.

- [ ] **Step 4: Write a failing compatibility test for `FixupConfig`**

```python
def test_existing_fixup_config_rebuild_uses_contract_validator() -> None:
    rebuilt, report = rebuild_with_report(fixture_bytes(), FixupConfig.from_doc(CONFIG).to_contract())
    assert report.accepted
    assert rebuilt[:8] == struct.pack("<II", 0xFAB11BAF, 31)
```

- [ ] **Step 5: Refactor rebuild and verify GREEN**

Keep `rebuild_metadata(data, config) -> bytes` as a compatibility wrapper over `rebuild_with_report`; reject the output when validation has error findings.

- [ ] **Step 6: Run the REToolkit metadata suites**

Run: `py -3.13 -m pytest tests/test_mfuscator.py tests/test_mfuscator_contract.py tests/test_mfuscator_source.py tests/test_mfuscator_validate.py -q`

Expected: all focused tests pass.

---

### Task 4: Add source-assisted inspection and Analysis2-only reporting

**Files:**
- Modify: `src/retoolkit/cli.py`
- Modify: `tests/test_cli_contract.py`
- Create: `docs/runbooks/mfuscator-recovery.md`

**Interfaces:**
- Produces CLI: `python -m retoolkit mfuscator inspect --metadata PATH --modified-header PATH --modified-runtime PATH --original-api PATH --modified-api PATH --output-dir PATH`.

- [ ] **Step 1: Write failing CLI tests**

```python
def test_mfuscator_inspect_writes_contract_and_report_to_selected_directory(tmp_path) -> None:
    result = _run("mfuscator", "inspect", "--fixture", "everlusting", "--output-dir", str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "mfuscator-contract.json").is_file()
    assert (tmp_path / "mfuscator-analysis.json").is_file()

def test_mfuscator_inspect_rejects_existing_analysis_directory(tmp_path) -> None:
    output = tmp_path / "Analysis"
    output.mkdir()
    result = _run("mfuscator", "inspect", "--fixture", "everlusting", "--output-dir", str(output))
    assert result.returncode == 2
```

- [ ] **Step 2: Verify RED, implement CLI dispatch, and verify GREEN**

The handler resolves the output path, rejects any path whose components contain the exact directory name `Analysis`, writes atomically, and returns the existing single-JSON stdout envelope.

- [ ] **Step 3: Run CLI and acceptance tests**

Run: `py -3.13 -m pytest tests/test_cli_contract.py tests/acceptance/test_contracts.py tests/acceptance/test_resilience.py -q`

Expected: all tests pass and stdout remains a single JSON document.

---

### Task 5: Add the Cpp2IL contract and validator

**Files:**
- Create: `Cpp2IL.Plugin.Mfuscator/MfuscatorMetadataContract.cs`
- Create: `Cpp2IL.Plugin.Mfuscator/MfuscatorMetadataValidator.cs`
- Create: `Cpp2IL.Plugin.Mfuscator.Tests/MfuscatorMetadataContractTests.cs`
- Create: `Cpp2IL.Plugin.Mfuscator.Tests/MfuscatorMetadataValidatorTests.cs`

**Interfaces:**
- Produces: `MfuscatorMetadataContract`, `MfuscatorSectionContract`, `MfuscatorPayloadTransform`, `MfuscatorValidationFinding`, `MfuscatorValidationReport`, and `MfuscatorMetadataValidator.Validate`.

- [ ] **Step 1: Write failing Everlusting contract test**

```csharp
[Test]
public void Everlusting_contract_has_676_byte_header_and_31_sections()
{
    var contract = MfuscatorMetadataContract.Everlusting;
    Assert.Multiple(() =>
    {
        Assert.That(contract.HeaderOffset, Is.EqualTo(4));
        Assert.That(contract.HeaderLength, Is.EqualTo(676));
        Assert.That(contract.SourceBias, Is.EqualTo(484));
        Assert.That(contract.Sections, Has.Count.EqualTo(31));
    });
}
```

- [ ] **Step 2: Verify RED**

Run: `dotnet test Cpp2IL.Plugin.Mfuscator.Tests\Cpp2IL.Plugin.Mfuscator.Tests.csproj -c Debug --no-restore --filter MfuscatorMetadataContractTests`

Expected: type-not-found compile failure.

- [ ] **Step 3: Implement records and exact contract**

```csharp
internal sealed record MfuscatorSectionContract(
    string Name, int CustomOffsetField, int CustomSizeField,
    int? RecordSize = null, int Alignment = 4,
    MfuscatorPayloadTransform? PayloadTransform = null);

internal sealed record MfuscatorMetadataContract(
    string Name, uint MetadataMagic, uint MetadataVersion,
    byte[] HeaderPrefix, int HeaderOffset, int HeaderLength,
    int PayloadStart, int PreservedTailStart, int SourceBias,
    byte[] XxteaKey, IReadOnlyList<MfuscatorSectionContract> Sections)
{
    internal static MfuscatorMetadataContract Everlusting { get; }
}
```

- [ ] **Step 4: Write failing validator tests**

Cover bounds, overlap, alignment, record-size remainder, and an accepted synthetic candidate using real byte arrays.

- [ ] **Step 5: Implement validator and run the focused suite**

Run: `dotnet test Cpp2IL.Plugin.Mfuscator.Tests\Cpp2IL.Plugin.Mfuscator.Tests.csproj -c Debug --no-restore --filter "MfuscatorMetadataContractTests|MfuscatorMetadataValidatorTests"`

Expected: all focused tests pass.

---

### Task 6: Refactor Cpp2IL decoding and validate searched layouts

**Files:**
- Modify: `Cpp2IL.Plugin.Mfuscator/CustomMetadataHeaderDecoder.cs`
- Modify: `Cpp2IL.Plugin.Mfuscator/MfuscatorSupportPlugin.cs`
- Modify: `Cpp2IL.Plugin.Mfuscator.Tests/CustomMetadataHeaderDecoderTests.cs`

**Interfaces:**
- Consumes: Task 5 contract and validator.
- Produces: `TryDecodeMetadataHeader(byte[], MfuscatorMetadataContract, out byte[])`, `TryRebuildMetadata(byte[], MfuscatorMetadataContract, out byte[], out MfuscatorValidationReport)`, and `GetMetadataLayout(UnityVersion)`.

- [ ] **Step 1: Write a failing contract-driven rebuild test**

Change the captured-header test to call the contract overload and assert that the returned validation report is accepted and names all 31 sections.

- [ ] **Step 2: Verify RED and implement the smallest refactor**

Move fixed constants into `MfuscatorMetadataContract.Everlusting`; retain compatibility overloads that delegate to the contract overload.

- [ ] **Step 3: Write failing Unity-version ordering tests**

```csharp
[TestCase("6000.3.0a2", 31, 8)]
[TestCase("6000.3.0a5", 35, 8)]
[TestCase("6000.3.0a6", 105, 12)]
[TestCase("6000.3.0b1", 38, 12)]
[TestCase("6000.5.0a3", 39, 12)]
public void Metadata_layout_mapping_is_ordered(string unity, int version, int descriptorWidth) { /* parse and assert */ }
```

- [ ] **Step 4: Implement ordered mapping before broader comparisons**

Check the most specific `6000.3 alpha6` boundary before `6000.5` boundaries so the branch is reachable. Return a layout record containing metadata version, descriptor width, expected section count, and assemblies section index.

- [ ] **Step 5: Write a failing candidate-selection test**

Create two in-bounds candidate layouts: one with overlapping record ranges and one structurally valid. Assert that selection returns the valid candidate even when the overlapping candidate is enumerated first.

- [ ] **Step 6: Validate before installing `rebuiltMetadata`**

Run each legacy candidate through `MfuscatorMetadataValidator.Validate`; sort accepted candidates by descending score and stable enumeration index; install only the highest accepted candidate.

- [ ] **Step 7: Run all Mfuscator plugin tests**

Run: `dotnet test Cpp2IL.Plugin.Mfuscator.Tests\Cpp2IL.Plugin.Mfuscator.Tests.csproj -c Debug --no-restore`

Expected: all tests pass.

---

### Task 7: Make method-map serialization work with reflection disabled

**Files:**
- Create: `Cpp2IL/MethodPointerMapEntry.cs`
- Create: `Cpp2IL/Cpp2IlJsonSerializerContext.cs`
- Modify: `Cpp2IL/Program.cs`
- Create: `Cpp2IL.Core.Tests/MethodPointerMapSerializationTests.cs`

**Interfaces:**
- Produces: `MethodPointerMapEntry` and `Cpp2IlJsonSerializerContext.Default.ListMethodPointerMapEntry`.

- [ ] **Step 1: Write a failing serialization test**

```csharp
[Test]
public void Method_pointer_map_serializes_with_source_generated_context()
{
    var rows = new List<MethodPointerMapEntry>
    {
        new("Assembly-CSharp", "Example.Type", "Run", "System.Void Example.Type::Run()", "0x1234", "0x234")
    };
    var json = JsonSerializer.Serialize(rows, Cpp2IlJsonSerializerContext.Default.ListMethodPointerMapEntry);
    Assert.That(json, Does.Contain("Assembly-CSharp"));
}
```

- [ ] **Step 2: Verify RED**

Run: `dotnet test Cpp2IL.Core.Tests\Cpp2IL.Core.Tests.csproj -c Debug --no-restore --filter MethodPointerMapSerializationTests`

Expected: missing entry/context types.

- [ ] **Step 3: Implement typed rows and source-generation context**

```csharp
internal sealed record MethodPointerMapEntry(
    string Assembly, string Type, string Method,
    string Signature, string Pointer, string Rva);

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(List<MethodPointerMapEntry>))]
internal partial class Cpp2IlJsonSerializerContext : JsonSerializerContext;
```

Replace the anonymous projection with `new MethodPointerMapEntry(...)` and serialize with the generated `JsonTypeInfo` overload.

- [ ] **Step 4: Verify GREEN and build Cpp2IL**

```powershell
dotnet test Cpp2IL.Core.Tests\Cpp2IL.Core.Tests.csproj -c Debug --no-restore --filter MethodPointerMapSerializationTests
dotnet build Cpp2IL.sln -c Debug --no-restore
```

Expected: test and build exit 0 without reflection-serialization diagnostics.

---

### Task 8: Run the Everlusting end-to-end gate

**Files:**
- Write dump/analysis output only under: `D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\mfuscator-20260801`
- Write transient pipeline output under: `D:\Temp\opencode\retoolkit-mfusactor-e2e-20260801`

**Interfaces:**
- Produces: reconstructed metadata, contract/report JSON, method map, and exact command log.

- [ ] **Step 1: Generate the source-assisted report**

```powershell
py -3.13 -m retoolkit mfuscator inspect `
  --metadata 'D:\SteamLibrary\steamapps\common\Everlusting Life\Everlusting Life_Data\il2cpp_data\Metadata\global-metadata.dat' `
  --modified-header 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\vm\GlobalMetadataFileInternals.h' `
  --modified-runtime 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\vm\GlobalMetadata.cpp' `
  --original-api 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\il2cpp-api-functions.ho' `
  --modified-api 'D:\Temp\opencode\mfuscator_refs\mfuscator_libil2cpp\libil2cpp\il2cpp-api-functions.h' `
  --output-dir 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\mfuscator-20260801'
```

Expected report: header length 676, source bias 484, 31 canonical section descriptors, and the renamed domain-assemblies export alias.

- [ ] **Step 2: Run the REToolkit pipeline with the rebuilt Cpp2IL**

```powershell
$env:RETOOLKIT_GAME_ROOT='D:\SteamLibrary\steamapps\common\Everlusting Life'
$env:RETOOLKIT_WORKSPACE='D:\Temp\opencode\retoolkit-mfusactor-e2e-20260801'
$env:RETOOLKIT_CPP2IL='D:\VSCode\Cpp2IL\Cpp2IL\Cpp2IL\bin\Debug\net10.0\Cpp2IL.exe'
$env:RETOOLKIT_CPP2IL_PLUGINS='D:\VSCode\Cpp2IL\Cpp2IL\Cpp2IL\bin\Debug\net10.0\Plugins'
$env:RETOOLKIT_GHIDRA='D:\VSCode\REToolkit'
py -3.13 -m retoolkit pipeline restart profiles\everlusting\profile.json
```

Expected: exit 0, metadata reported as 31.1, and `method-pointer-map.json` exists.

- [ ] **Step 3: Verify exact method count and hashes**

```powershell
$Map = Get-Content 'D:\Temp\opencode\retoolkit-mfusactor-e2e-20260801\cpp2il\method-pointer-map.json' -Raw | ConvertFrom-Json
if ($Map.Count -ne 206366) { throw "Expected 206366 methods, got $($Map.Count)" }
Get-FileHash 'D:\Temp\opencode\retoolkit-mfusactor-e2e-20260801\metadata\global-metadata.dat' -Algorithm SHA256
```

Expected method count: exactly `206366`.

- [ ] **Step 4: Run complete test suites**

```powershell
py -3.13 -m pytest -q
dotnet test Cpp2IL.Plugin.Mfuscator.Tests\Cpp2IL.Plugin.Mfuscator.Tests.csproj -c Debug --no-restore
dotnet test Cpp2IL.Core.Tests\Cpp2IL.Core.Tests.csproj -c Debug --no-restore
```

Expected: all suites exit 0.

---

### Task 9: Package verified outputs and rollback

**Files:**
- Create: `$BackupRoot\delivery\mfuscator-upgrade.patch`
- Create: `$BackupRoot\delivery\verification.md`
- Create: `$BackupRoot\delivery\rollback.ps1`
- Copy: rebuilt `Cpp2IL.exe`, Mfuscator plugin DLL, contract/report JSON.

**Interfaces:**
- Produces the four verified roles: modified artifacts, patch, verification record, rollback.

- [ ] **Step 1: Produce diffs without staging unrelated state**

Use `git diff` for tracked Cpp2IL files and `git diff --no-index` against the baseline copies for REToolkit and new/untracked Cpp2IL files. Concatenate them into `mfuscator-upgrade.patch` with file headers preserved.

- [ ] **Step 2: Write rollback from the byte-for-byte backup**

`rollback.ps1` verifies every destination is inside one of the two requested repositories, copies each preserved original back with `Copy-Item -LiteralPath -Force`, removes only files listed as newly created by this implementation, and never traverses or references an existing `Analysis` directory.

- [ ] **Step 3: Reopen and execute all delivered roles**

```powershell
Get-FileHash "$BackupRoot\delivery\Cpp2IL.exe" -Algorithm SHA256
Get-FileHash "$BackupRoot\delivery\Cpp2IL.Plugin.Mfuscator.dll" -Algorithm SHA256
Get-Content "$BackupRoot\delivery\mfuscator-upgrade.patch" -TotalCount 20
Get-Content "$BackupRoot\delivery\verification.md" -Raw
& powershell -NoProfile -ExecutionPolicy Bypass -File "$BackupRoot\delivery\rollback.ps1" -WhatIf
```

Expected: hashes are produced, patch and verification records reopen, and rollback `-WhatIf` lists only intended files.

## Self-review

- Spec coverage: exact-game contract, source-assisted inference, validator, 12-byte descriptor model, reflection-free method map, Analysis2 isolation, live fixture, patch, verification, and rollback each have a task.
- Placeholder scan: implementation-facing APIs, paths, assertions, commands, and expected outcomes are explicit.
- Type consistency: Python tasks consistently use `MfuscatorContract`; C# tasks consistently use `MfuscatorMetadataContract`; reports are returned alongside rebuild results and used by candidate selection.
