# REToolkit Native Analysis and Ghidra Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fast native triage and three measured Ghidra workflows: cached targeted headless, sharded parallel headless, and a resumable GUI bulk-analysis bundle with a detailed operator manual.

**Architecture:** Map PE addresses and extract bounded x86-64 findings before Ghidra, persist a workspace-owned Ghidra base project per binary/tool/profile cache key, reuse that project through `-process`, batch targets instead of spawning per method, and shard medium-size jobs across isolated project replicas. Large/full jobs are prepared as GUI bundles containing target manifests, Java scripts, progress files, and deterministic export/import contracts.

**Tech Stack:** Python 3.13, standard-library PE parsing, optional `iced-x86`, Java GhidraScript API, Ghidra Headless Analyzer, pytest, PowerShell performance counters.

## Global Constraints

- Requires the Phase 1 `ReIndex`, `MethodRecord`, and `TargetQuery` interfaces.
- Existing `Analysis` remains byte-for-byte unchanged; project cache, workers,
  GUI bundles, logs, and exports live under the configured `Analysis2` workspace.
- Targeted mode never starts one JVM per method.
- A valid decompilation cache hit starts no JVM.
- A base project is imported once per binary SHA-256, Ghidra version, loader,
  script hash, analyzer profile, and image-base configuration.
- Worker processes never concurrently write the same local Ghidra project.
- `-max-cpu` is supplied only when analysis is enabled; it is not counted as
  parallel decompilation for a serial `DecompInterface` loop.
- GUI scripts write progress/result records after each completed target.

---

## Task 1: Add PE Address Mapping and Fast Native Findings

**Files:**
- Create: `src/retoolkit/native/__init__.py`
- Create: `src/retoolkit/native/pe.py`
- Create: `src/retoolkit/native/models.py`
- Create: `src/retoolkit/native/disasm.py`
- Create: `schemas/native_findings.schema.json`
- Modify: `pyproject.toml`
- Create: `tests/test_pe_mapping.py`
- Create: `tests/test_native_disasm.py`

**Interfaces:**
- Consumes: binary path and Phase 1 `MethodRecord` targets.
- Produces: `PeImage`, `PeSection`, `StaticFinding`, `NativeAnalyzer.analyze`.

- [ ] **Step 1: Write failing PE mapping tests using a synthetic PE fixture**

```python
def test_rva_file_offset_round_trip(pe_fixture) -> None:
    image = PeImage.open(pe_fixture)
    assert image.image_base == 0x180000000
    assert image.rva_to_file_offset(0x1100) == 0x500
    assert image.file_offset_to_rva(0x500) == 0x1100
    assert image.rva_to_va(0x1100) == 0x180001100


def test_unmapped_rva_is_typed_validation_error(pe_fixture) -> None:
    with pytest.raises(ResultError, match="RVA 0x900000 is outside mapped PE sections"):
        PeImage.open(pe_fixture).rva_to_file_offset(0x900000)
```

- [ ] **Step 2: Run focused tests and verify missing native package**

Run: `py -3.13 -m pytest tests/test_pe_mapping.py -q`
Expected: collection failure for `retoolkit.native`.

- [ ] **Step 3: Implement strict PE32+ parsing**

```python
@dataclass(frozen=True)
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class PeImage:
    path: Path
    image_base: int
    machine: int
    sections: tuple[PeSection, ...]

    @classmethod
    def open(cls, path: Path) -> "PeImage": ...
    def rva_to_file_offset(self, rva: int) -> int: ...
    def file_offset_to_rva(self, offset: int) -> int: ...
    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva
```

Use `struct.unpack_from` for DOS header, PE signature, COFF header, PE32+
optional header, image base, and section table. Reject truncated headers,
non-PE32+ binaries, integer overflow, overlapping raw sections, and offsets
outside the file.

- [ ] **Step 4: Write failing instruction/reference extraction tests**

```python
def test_analyzer_extracts_direct_call_branch_and_rip_reference(pe_fixture) -> None:
    target = MethodRecord(1, "A", "N.T", "M", "sig", 0x1100, None, "k")
    findings = NativeAnalyzer(window_bytes=96).analyze(pe_fixture, [target])
    finding = findings[0]
    assert finding.entry_rva == 0x1100
    assert 0x1200 in finding.direct_calls
    assert finding.conditional_branches
    assert finding.rip_references
```

- [ ] **Step 5: Add optional decoder dependency and implementation**

Add:

```toml
[project.optional-dependencies]
analysis = ["iced-x86>=1.21,<2"]
```

Install the implementation/test environment with:

```powershell
py -3.13 -m pip install -e ".[dev,analysis]"
```

Implement:

```python
@dataclass(frozen=True)
class StaticFinding:
    method_id: int
    entry_rva: int
    bytes_sha256: str
    instructions: tuple[dict, ...]
    direct_calls: tuple[int, ...]
    conditional_branches: tuple[int, ...]
    rip_references: tuple[int, ...]
    immediates: tuple[int, ...]
    strings: tuple[str, ...]
    status: str


class NativeAnalyzer:
    def __init__(self, *, window_bytes: int = 256) -> None:
        self.window_bytes = window_bytes

    def analyze(self, binary: Path, targets: list[MethodRecord]) -> list[StaticFinding]:
        image = PeImage.open(binary)
        decoder = _load_iced_x86()
        return [_analyze_one(image, binary, decoder, target, self.window_bytes)
                for target in targets]
```

When the optional decoder is absent, return a typed capability result that
still includes address mappings and byte hashes; do not treat it as a corrupt
binary.

- [ ] **Step 6: Validate schema and deterministic output**

Sort instructions by address and each reference list numerically. Validate the
serialized document against `native_findings.schema.json`.

- [ ] **Step 7: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_pe_mapping.py tests/test_native_disasm.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/native schemas/native_findings.schema.json pyproject.toml tests/test_pe_mapping.py tests/test_native_disasm.py
git commit -m "feat: add fast native analysis"
```

## Task 2: Define Ghidra Manifests, Cache Keys, and Base Project Lifecycle

**Files:**
- Create: `src/retoolkit/ghidra/__init__.py`
- Create: `src/retoolkit/ghidra/models.py`
- Create: `src/retoolkit/ghidra/cache.py`
- Create: `src/retoolkit/ghidra/manifests.py`
- Create: `schemas/ghidra_target_manifest.schema.json`
- Create: `schemas/ghidra_result.schema.json`
- Create: `schemas/re_index_v2.sql`
- Modify: `src/retoolkit/re_index/schema.py`
- Create: `tests/test_ghidra_cache.py`
- Create: `tests/test_ghidra_manifests.py`
- Create: `tests/test_re_index_ghidra_migration.py`

**Interfaces:**
- Consumes: binary/tool/profile/script hashes and indexed methods.
- Produces: `GhidraCacheKey`, `GhidraProjectCache`, `TargetManifest`, `GhidraRecord`.

- [ ] **Step 1: Write failing stable cache-key tests**

```python
def test_cache_key_changes_for_every_semantic_input() -> None:
    base = GhidraCacheKey("a" * 64, "11.4", "PeLoader", "b" * 64,
                          "minimal", 0x180000000)
    assert base.digest() == GhidraCacheKey(**asdict(base)).digest()
    for field, value in {
        "ghidra_version": "11.5", "script_sha256": "c" * 64,
        "analyzer_profile": "balanced", "image_base": 0x140000000,
    }.items():
        changed = replace(base, **{field: value})
        assert changed.digest() != base.digest()
```

- [ ] **Step 2: Run tests and verify missing Ghidra package**

Run: `py -3.13 -m pytest tests/test_ghidra_cache.py tests/test_ghidra_manifests.py -q`
Expected: import failures.

- [ ] **Step 3: Implement canonical cache keys and project metadata**

```python
@dataclass(frozen=True)
class GhidraCacheKey:
    binary_sha256: str
    ghidra_version: str
    loader: str
    script_sha256: str
    analyzer_profile: str
    image_base: int

    def digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class GhidraProjectCache:
    def __init__(self, root: Path) -> None:
        self.root = root

    def project(self, key: GhidraCacheKey) -> CachedProject:
        return CachedProject(self.root / key.digest(), key)
```

`CachedProject` owns `project.gpr`, `project.rep`, `cache-key.json`,
`import-complete.json`, a lock, and replica directories. It publishes the base
project only after the import command exits `0` and the expected program exists.

- [ ] **Step 4: Implement versioned target/result manifests**

```python
@dataclass(frozen=True)
class GhidraTarget:
    target_id: int
    method_id: int
    rva: int
    address: int
    identity: str


@dataclass(frozen=True)
class TargetManifest:
    schema_version: str
    binary_sha256: str
    method_map_sha256: str
    image_base: int
    targets: tuple[GhidraTarget, ...]
```

Manifests are sorted by `(rva, identity, target_id)`, written atomically, and
validated against JSON Schema before an external process starts.

- [ ] **Step 5: Add RE Index migration version 2 for native/Ghidra evidence**

```sql
CREATE TABLE IF NOT EXISTS functions (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id),
  entry_rva INTEGER NOT NULL,
  end_rva INTEGER,
  name TEXT,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  UNIQUE(binary_id, entry_rva, source)
);
CREATE TABLE IF NOT EXISTS static_findings (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id),
  analyzer TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  finding_json TEXT NOT NULL,
  UNIQUE(method_id, analyzer, input_hash)
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY,
  source_method_id INTEGER NOT NULL REFERENCES methods(id),
  target_method_id INTEGER REFERENCES methods(id),
  target_rva INTEGER,
  kind TEXT NOT NULL,
  evidence_source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  UNIQUE(source_method_id, target_method_id, target_rva, kind, evidence_source)
);
CREATE TABLE IF NOT EXISTS ghidra_runs (
  id TEXT PRIMARY KEY,
  cache_key TEXT NOT NULL,
  mode TEXT NOT NULL,
  worker_count INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_utc TEXT NOT NULL,
  ended_utc TEXT
);
CREATE TABLE IF NOT EXISTS decompilations (
  id INTEGER PRIMARY KEY,
  ghidra_run_id TEXT NOT NULL REFERENCES ghidra_runs(id),
  method_id INTEGER NOT NULL REFERENCES methods(id),
  input_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  function_name TEXT,
  function_entry_rva INTEGER,
  function_end_rva INTEGER,
  pseudocode TEXT,
  error TEXT,
  duration_ms INTEGER NOT NULL,
  UNIQUE(method_id, input_hash)
);
PRAGMA user_version = 2;
```

The migration test opens a v1 fixture, migrates it to v2, verifies all method
rows remain, and checks that a second open performs no schema changes.

- [ ] **Step 6: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_ghidra_cache.py tests/test_ghidra_manifests.py tests/test_re_index_ghidra_migration.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/ghidra schemas/ghidra_target_manifest.schema.json schemas/ghidra_result.schema.json schemas/re_index_v2.sql src/retoolkit/re_index/schema.py tests/test_ghidra_cache.py tests/test_ghidra_manifests.py tests/test_re_index_ghidra_migration.py
git commit -m "feat: define persistent Ghidra project contracts"
```

## Task 3: Implement Cached Targeted Headless Batches

**Files:**
- Create: `ghidra_scripts/ImportPreparedProgram.java`
- Create: `ghidra_scripts/SeedIl2CppFunctions.java`
- Create: `ghidra_scripts/DecompileBatch.java`
- Create: `src/retoolkit/ghidra/targeted.py`
- Modify: `src/retoolkit/adapters/ghidra.py`
- Create: `tests/test_ghidra_targeted.py`
- Modify: `tests/test_ghidra_adapter.py`
- Modify: `tests/fakes/tool.cs`

**Interfaces:**
- Consumes: `CachedProject`, `TargetManifest`, Ghidra capability.
- Produces: `TargetedGhidraRunner.run(...) -> GhidraRunResult`.

- [ ] **Step 1: Write failing command-shape tests**

```python
def test_first_run_imports_once_and_second_run_processes_existing_project(fake_ghidra, tmp_path) -> None:
    runner = targeted_runner(fake_ghidra, tmp_path)
    first = runner.run(manifest("a", [0x1000, 0x2000]))
    second = runner.run(manifest("a", [0x3000]))
    assert first.commands[0].mode == "import"
    assert second.commands[0].mode == "process"
    assert fake_ghidra.count_argument("-import") == 1
    assert fake_ghidra.count_argument("-process") == 1


def test_one_batch_never_spawns_per_method(fake_ghidra, tmp_path) -> None:
    result = targeted_runner(fake_ghidra, tmp_path).run(manifest("a", range(100)))
    assert result.jvm_launches == 1
    assert result.completed == 100
```

- [ ] **Step 2: Run focused tests and confirm failures**

Run: `py -3.13 -m pytest tests/test_ghidra_targeted.py -q`
Expected: missing runner/classes.

- [ ] **Step 3: Implement one-time base-project import**

The first command is:

```text
analyzeHeadless <cache-root> retoolkit-base
  -import <binary>
  -noanalysis
  -scriptPath <ghidra_scripts>
  -postScript ImportPreparedProgram.java <metadata-json>
  -log <import.log>
  -scriptlog <import-script.log>
```

On success, hash logs/project metadata and atomically write
`import-complete.json`. Later commands use:

```text
analyzeHeadless <cache-root> retoolkit-base
  -process GameAssembly.dll
  -noanalysis
  -scriptPath <ghidra_scripts>
  -postScript SeedIl2CppFunctions.java <manifest>
  -postScript DecompileBatch.java <manifest> <results.jsonl> <progress.json>
```

- [ ] **Step 4: Implement `SeedIl2CppFunctions.java`**

The script parses the manifest through Ghidra's bundled JSON support, validates
the program image base and target address, disassembles at each missing entry,
creates a function when possible, and installs a sanitized symbol plus the full
managed identity as a repeatable comment. It emits one result per target:

```java
Map<String, Object> record = new LinkedHashMap<>();
record.put("target_id", targetId);
record.put("rva", String.format("0x%x", rva));
record.put("address", address.toString());
record.put("status", function == null ? "seed_failed" : "seeded");
appendJsonLine(output, record);
```

- [ ] **Step 5: Implement `DecompileBatch.java`**

Use one `DecompInterface`, configure C output, and process manifest order.
After every target, append and flush a JSONL record containing target ID,
function name/bounds, pseudocode or typed failure, duration, and timeout status.
Atomically replace `progress.json` with counts and the last completed target.

```java
DecompInterface decompiler = new DecompInterface();
decompiler.toggleCCode(true);
decompiler.toggleSyntaxTree(true);
decompiler.openProgram(currentProgram);
try {
    for (Target target : targets) {
        if (completed.contains(target.id())) continue;
        Result row = decompileOne(decompiler, target, perFunctionTimeout, monitor);
        appendAndFlush(resultPath, row);
        writeProgressAtomic(progressPath, target.id(), ++completedCount, targets.size());
    }
}
finally {
    decompiler.dispose();
}
```

- [ ] **Step 6: Implement Python runner and cache-hit behavior**

```python
class TargetedGhidraRunner:
    def run(self, manifest: TargetManifest, *, batch_size: int = 128,
            per_function_timeout: int = 180, resume: bool = False) -> GhidraRunResult:
        project = self.cache.ensure_base_project(self.key, self.binary)
        missing = self.result_cache.missing(manifest.targets, self.key)
        if not missing:
            return GhidraRunResult.from_cache(manifest.targets)
        commands = []
        for batch in batched(missing, batch_size):
            commands.append(self._run_process_batch(project, batch, per_function_timeout))
        return self._merge(manifest, commands)
```

The `GhidraAdapter.decompile_rvas` compatibility method delegates to targeted
mode with a generated manifest so existing callers continue working.

After validating the merged result schema, the runner imports `functions`,
`decompilations`, caller/callee edges, and static findings through a single
`ReIndex` transaction. A failed merge changes no index rows.

- [ ] **Step 7: Test per-target timeout preservation and resume**

The fake writes 20 completed records then stalls. Expected: timeout kills the
process tree, the 20 records remain valid, and `resume=True` sends only the
unfinished targets.

- [ ] **Step 8: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_ghidra_targeted.py tests/test_ghidra_adapter.py -q`
Expected: all tests pass.

```bash
git add ghidra_scripts/ImportPreparedProgram.java ghidra_scripts/SeedIl2CppFunctions.java ghidra_scripts/DecompileBatch.java src/retoolkit/ghidra/targeted.py src/retoolkit/adapters/ghidra.py tests/test_ghidra_targeted.py tests/test_ghidra_adapter.py tests/fakes/tool.cs
git commit -m "feat: batch targeted Ghidra decompilation"
```

## Task 4: Implement Parallel Worker Sharding and Performance Benchmarking

**Files:**
- Create: `src/retoolkit/ghidra/planner.py`
- Create: `src/retoolkit/ghidra/workers.py`
- Create: `src/retoolkit/ghidra/benchmark.py`
- Create: `schemas/ghidra_benchmark.schema.json`
- Create: `scripts/measure_ghidra_workers.ps1`
- Create: `tests/test_ghidra_planner.py`
- Create: `tests/test_ghidra_workers.py`
- Create: `tests/test_ghidra_benchmark.py`

**Interfaces:**
- Consumes: cached base project and unresolved target manifest.
- Produces: `GhidraPlan`, `GhidraExecutor.execute`, benchmark JSON.

- [ ] **Step 1: Write failing deterministic sharding tests**

```python
def test_plan_shards_by_batches_not_individual_methods() -> None:
    plan = GhidraPlanner().plan(targets(1000), mode="parallel", workers=4, batch_size=128)
    assert len(plan.workers) == 4
    assert sum(len(batch.targets) for worker in plan.workers for batch in worker.batches) == 1000
    assert max(len(batch.targets) for worker in plan.workers for batch in worker.batches) <= 128
    assert plan.jvm_launches <= 8


def test_auto_worker_count_respects_cpu_and_memory() -> None:
    resources = HostResources(logical_cpus=16, available_bytes=20 * GiB,
                              measured_worker_bytes=3 * GiB)
    assert choose_workers(resources, configured_max=8) == 6
```

- [ ] **Step 2: Implement planner and conservative auto-worker selection**

```python
def choose_workers(resources: HostResources, *, configured_max: int) -> int:
    cpu_limit = max(1, resources.logical_cpus - 2)
    memory_limit = max(1, resources.available_bytes // max(resources.measured_worker_bytes, 1))
    return max(1, min(configured_max, cpu_limit, memory_limit))
```

Use deterministic round-robin assignment of whole batches. Explicit worker
counts bypass auto-selection after validation.

- [ ] **Step 3: Implement isolated project replicas**

Create a replica once per worker cache key after the base project is closed.
Record base-project manifest hash in each replica. A stale or incomplete replica
is rebuilt; a valid replica is reused. Never enumerate one shell and delete in
another; all copy/remove operations use resolved `Path`/PowerShell literal paths
inside the workspace.

- [ ] **Step 4: Implement process execution and deterministic merge**

```python
class GhidraExecutor:
    def execute(self, plan: GhidraPlan, *, resume: bool = False) -> GhidraRunResult:
        with ThreadPoolExecutor(max_workers=plan.worker_count) as pool:
            futures = [pool.submit(self._run_worker, worker, resume) for worker in plan.workers]
            shards = [future.result() for future in futures]
        return merge_shards(shards, expected_target_ids=plan.target_ids)
```

ThreadPoolExecutor coordinates external processes; analysis itself occurs in
isolated Ghidra JVMs. Merge rejects duplicate conflicting target records and
sorts by target ID/RVA.

- [ ] **Step 5: Implement benchmark record and PowerShell counters**

Record cold import, warm batch, cache hit, method throughput, process CPU,
working set, disk bytes/sec, JVM launches, completed/failed counts, and scaling
efficiency for worker counts `1,2,4,...`. At one worker, benchmark batch sizes
`32,64,128,256`; select the fastest size that stays below the configured memory
ceiling, then use that size for worker scaling.

```python
efficiency = throughput_n / (throughput_1 * workers)
```

Stop auto-scaling after two consecutive worker counts fail to improve total
throughput by at least five percent. Report the measured optimum; do not hide
negative scaling.

- [ ] **Step 6: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_ghidra_planner.py tests/test_ghidra_workers.py tests/test_ghidra_benchmark.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/ghidra/planner.py src/retoolkit/ghidra/workers.py src/retoolkit/ghidra/benchmark.py schemas/ghidra_benchmark.schema.json scripts/measure_ghidra_workers.ps1 tests/test_ghidra_planner.py tests/test_ghidra_workers.py tests/test_ghidra_benchmark.py
git commit -m "feat: parallelize Ghidra target batches"
```

## Task 5: Generate the GUI Bulk Bundle and Java Automation

**Files:**
- Create: `src/retoolkit/ghidra/gui_bundle.py`
- Create: `ghidra_scripts/BulkAnalyzeTargets.java`
- Create: `ghidra_scripts/BulkDecompileTargets.java`
- Create: `ghidra_scripts/ExportRetoolkitResults.java`
- Create: `schemas/ghidra_gui_bundle.schema.json`
- Create: `schemas/ghidra_progress.schema.json`
- Create: `tests/test_ghidra_gui_bundle.py`
- Create: `tests/test_ghidra_java_contracts.py`

**Interfaces:**
- Consumes: base project, target manifest, analyzer profile.
- Produces: `prepare_gui_bundle(...) -> GuiBundle`, `import_gui_bundle(...) -> ImportSummary`.

- [ ] **Step 1: Write failing bundle-completeness and hash tests**

```python
def test_bundle_contains_every_operator_artifact(tmp_path, profile, targets) -> None:
    bundle = prepare_gui_bundle(profile, targets, tmp_path / "bundle")
    assert {path.name for path in bundle.root.iterdir()} == {
        "target-manifest.json", "method-map.normalized.json", "analyzer-profile.json",
        "SeedIl2CppFunctions.java", "BulkAnalyzeTargets.java",
        "BulkDecompileTargets.java", "ExportRetoolkitResults.java",
        "progress.json", "README-GHIDRA-GUI.md", "bundle-manifest.json",
    }
    assert bundle.verify_hashes() == []
```

- [ ] **Step 2: Implement atomic bundle generation**

Generate in a sibling temporary directory, validate all JSON schemas, hash every
file into `bundle-manifest.json`, then atomically rename to the requested path.
Reject any output path whose normalized components contain the exact component
`Analysis`; accept `Analysis2`.

- [ ] **Step 3: Implement `BulkAnalyzeTargets.java`**

The script reads target address sets and analyzer selections, queues analysis
only for those sets, uses the GUI task monitor, records analyzer start/end and
timeout, and updates `progress.json` atomically. It supports `resume=true` by
skipping completed target IDs.

- [ ] **Step 4: Implement `BulkDecompileTargets.java`**

Use the same target/result contract as headless mode, display progress through
`monitor.setMaximum`, `monitor.setProgress`, and `monitor.setMessage`, flush one
JSONL record per target, and stop cleanly when the monitor is cancelled.

- [ ] **Step 5: Implement `ExportRetoolkitResults.java`**

Export, per target:

```json
{
  "target_id": 1,
  "rva": "0x434a60",
  "function": {"name": "FUN_180434a60", "entry": "180434a60", "end": "180434b20"},
  "callers": [],
  "callees": [],
  "data_references": [],
  "symbols": [],
  "pseudocode": "void FUN_180434a60(void) { return; }",
  "status": "completed",
  "duration_ms": 120
}
```

The export header includes binary SHA-256, method-map SHA-256, Ghidra version,
program image base, script hashes, and analyzer profile hash.

- [ ] **Step 6: Implement strict GUI import validation**

`import_gui_bundle()` verifies every manifest hash and compares the export
header with the current binary, method map, image base, and schema version
before opening an index transaction. Import all records or none.

- [ ] **Step 7: Run bundle/Java contract tests and commit**

Run: `py -3.13 -m pytest tests/test_ghidra_gui_bundle.py tests/test_ghidra_java_contracts.py -q`
Expected: all tests pass; Java source contract tests find progress, cancellation,
flush, and required output fields.

```bash
git add src/retoolkit/ghidra/gui_bundle.py ghidra_scripts/BulkAnalyzeTargets.java ghidra_scripts/BulkDecompileTargets.java ghidra_scripts/ExportRetoolkitResults.java schemas/ghidra_gui_bundle.schema.json schemas/ghidra_progress.schema.json tests/test_ghidra_gui_bundle.py tests/test_ghidra_java_contracts.py
git commit -m "feat: generate Ghidra GUI bulk-analysis bundles"
```

## Task 6: Add Native/Ghidra CLI, Profile Settings, and Detailed GUI Manual

**Files:**
- Create: `src/retoolkit/commands/native.py`
- Create: `src/retoolkit/commands/ghidra.py`
- Modify: `src/retoolkit/cli.py`
- Modify: `schemas/profile.schema.json`
- Modify: `profiles/everlusting/profile.json`
- Create: `docs/runbooks/ghidra-bulk-gui.md`
- Create: `tests/test_cli_ghidra.py`
- Modify: `tests/test_profile.py`
- Modify: `tests/test_runbook_references.py`
- Modify: `tests/live/test_ghidra_live.py`

**Interfaces:**
- Consumes: Phase 1 index and Tasks 1-5 services.
- Produces: native/Ghidra commands, profile configuration, operator runbook.

- [ ] **Step 1: Write failing parser and mode-selection tests**

```python
def test_ghidra_cli_exposes_all_modes() -> None:
    parser = build_parser()
    for mode in ("targeted", "parallel", "gui"):
        args = parser.parse_args(["ghidra", "analyze", "p.json", "--query", "N.T::*", "--mode", mode])
        assert args.mode == mode


@pytest.mark.parametrize(("count", "mode"), [(1, "targeted"), (256, "targeted"),
                                               (257, "parallel"), (5000, "parallel"),
                                               (5001, "gui")])
def test_auto_mode_thresholds_are_profile_driven(count, mode, profile) -> None:
    assert select_mode(count, profile.analysis.ghidra) == mode
```

- [ ] **Step 2: Register commands**

Required CLI:

```text
retoolkit native scan PROFILE --query QUERY [--window-bytes 256]
retoolkit ghidra prepare PROFILE [--analyzer-profile minimal]
retoolkit ghidra analyze PROFILE --query QUERY [--mode auto|targeted|parallel|gui]
retoolkit ghidra benchmark PROFILE --targets FILE --workers 1,2,4 --batch-size 128
retoolkit ghidra prepare-gui PROFILE --query QUERY --output DIRECTORY
retoolkit ghidra import-gui PROFILE --bundle DIRECTORY
```

- [ ] **Step 3: Extend profile schema with exact Ghidra settings**

```json
{
  "ghidra": {
    "cache_root": "${RETOOLKIT_WORKSPACE}/ghidra-cache",
    "default_mode": "auto",
    "targeted_max_targets": 256,
    "parallel_max_targets": 5000,
    "batch_size": 128,
    "max_workers": 8,
    "per_function_timeout_seconds": 180,
    "analyzer_profile": "minimal",
    "max_cpu": 0
  }
}
```

Schema types enforce positive limits, mode enum, analyzer-profile enum, and
workspace-contained cache path.

- [ ] **Step 4: Write the numbered GUI manual**

`docs/runbooks/ghidra-bulk-gui.md` must contain these explicit sections and
literal commands/screens:

1. Required Ghidra/JDK versions and `retoolkit doctor` check.
2. `index build` prerequisite and expected method count.
3. Exact `ghidra prepare-gui` command writing to `Analysis2`.
4. Bundle hash verification command.
5. Launching Ghidra and opening the generated workspace-owned project.
6. Confirming the correct `GameAssembly.dll` SHA-256 and image base.
7. Opening Script Manager.
8. Adding the bundle directory under Script Directories.
9. Refreshing scripts and locating each REToolkit Java script.
10. Running `SeedIl2CppFunctions.java` and selecting `target-manifest.json`.
11. Comparing seeded/skipped/failed counts with the manifest.
12. Opening Auto Analyze settings and choosing the generated analyzer profile.
13. Setting GUI worker threads and explaining the RAM/CPU tradeoff.
14. Running `BulkAnalyzeTargets.java` and reading progress.
15. Cancelling cleanly and confirming `progress.json` remains valid.
16. Resuming the analyzer script.
17. Running `BulkDecompileTargets.java`.
18. Inspecting a sample target and pseudocode in CodeBrowser.
19. Running `ExportRetoolkitResults.java`.
20. Verifying export hashes and record counts.
21. Closing the program/project cleanly.
22. Running the exact `ghidra import-gui` command.
23. Running an index query proving imported callers/callees are available.
24. Troubleshooting project lock, script compile, Java heap, image base,
    timeout, missing function, malformed export, and stale hash errors.
25. Workspace cleanup and rollback; no command targets `Analysis`.

Every step includes the expected visible result and the next diagnostic command
when it differs.

- [ ] **Step 5: Test runbook references and parser/profile behavior**

Run: `py -3.13 -m pytest tests/test_cli_ghidra.py tests/test_profile.py tests/test_runbook_references.py -q`
Expected: all tests pass and every referenced script/command exists.

- [ ] **Step 6: Run live targeted/cached/parallel gates**

```powershell
$env:RETOOLKIT_LIVE_GHIDRA='1'
$env:RETOOLKIT_GHIDRA='D:\Tools\ghidra_12.1.2_PUBLIC'
$env:RETOOLKIT_GAME_ROOT='D:\SteamLibrary\steamapps\common\Everlusting Life'
py -3.13 -m pytest tests\live\test_ghidra_live.py -v
```

Expected live assertions:

- first targeted run imports once;
- warm run uses `-process`;
- cached repeat launches no JVM;
- 100-target/one-worker run launches one JVM;
- 1/2/4 worker report is schema-valid and records measured scaling;
- outputs are under `Analysis2` workspace.

- [ ] **Step 7: Commit Phase 2**

```bash
git add src/retoolkit/commands/native.py src/retoolkit/commands/ghidra.py src/retoolkit/cli.py schemas/profile.schema.json profiles/everlusting/profile.json docs/runbooks/ghidra-bulk-gui.md tests/test_cli_ghidra.py tests/test_profile.py tests/test_runbook_references.py tests/live/test_ghidra_live.py
git commit -m "feat: expose optimized Ghidra analysis modes"
```

## Phase 2 Verification and Rollback

- Produce four roles: modified source/archive, `phase-2-native-ghidra.patch`,
  `phase-2-verification.md`, and `phase-2-rollback.ps1`.
- Verification records baseline fresh-import command and modified cold/warm/
  cached/1-2-4-worker commands with literal outputs and exit statuses.
- Replay patch in a fresh repository and run all Phase 1+2 non-live tests.
- Execute rollback dry-run in the real repo and real rollback in the replay repo.
- Verify the baseline adapter behavior returns after rollback and the existing
  `Analysis` manifest remains unchanged.
