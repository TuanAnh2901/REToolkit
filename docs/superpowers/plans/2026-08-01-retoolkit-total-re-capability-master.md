# REToolkit Total RE Capability Upgrade Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn REToolkit into an indexed, query-driven reverse-engineering system that produces target dossiers, bulk method recovery, and correlated runtime evidence while removing fresh-import Ghidra from the fast path.

**Architecture:** Build one SQLite RE Index as the system of record, feed it with the existing Cpp2IL method map, lightweight native analysis, three Ghidra execution modes, and multi-target Frida traces, then synthesize dossiers and bulk reports through explicit confidence rules. Deliver the work as four independently testable phases so each phase adds usable capability and can be rolled back without invalidating earlier phases.

**Tech Stack:** Python 3.13, SQLite, JSON Schema Draft 2020-12, optional iced-x86, Java GhidraScript, Frida JavaScript/Python, pytest, PowerShell, existing Cpp2IL plugin.

## Global Constraints

- Primary live target is the current game build; generic core modules contain no build-specific constants.
- Existing `Analysis` is read-only; all new game-derived artifacts go below `Analysis2` or the configured REToolkit workspace.
- Preserve the current metadata fixup, Cpp2IL export, normalized method-map, CLI JSON envelope, evidence manifest, workspace lock, and resume behavior.
- Persistent Ghidra projects and worker replicas are workspace-owned and keyed by binary/tool/configuration hashes.
- Never start one Ghidra process per method; targeted mode batches targets and parallel mode shards batches across isolated workers.
- `-max-cpu` is used for enabled auto-analysis only; process-level sharding supplies parallel decompilation.
- Every long operation has timeout, progress, checkpoint, resume, deterministic merge, and explicit stale-input detection.
- Every external command records exact argv, inputs, versions, hashes, duration, literal output, and exit status.
- Each phase follows test-first implementation and ends with unit, integration, live, patch replay, and rollback verification.

---

## Plan Set and Dependency Order

1. [`2026-08-01-retoolkit-re-index-query.md`](2026-08-01-retoolkit-re-index-query.md)
   - SQLite schema, migrations, method-map import, target queries, CLI.
2. [`2026-08-01-retoolkit-native-ghidra.md`](2026-08-01-retoolkit-native-ghidra.md)
   - PE/RVA mapping, lightweight disassembly, persistent targeted Ghidra,
     parallel workers, GUI bundle, detailed GUI runbook.
3. [`2026-08-01-retoolkit-frida-correlation.md`](2026-08-01-retoolkit-frida-correlation.md)
   - Multi-target runtime tracing, sampling, aggregation, address correlation.
4. [`2026-08-01-retoolkit-dossier-bulk.md`](2026-08-01-retoolkit-dossier-bulk.md)
   - Confidence engine, target dossier, bulk recovery queue, end-to-end orchestration.

The plans are sequential at their public-interface boundaries. Tests and
documentation within a plan may be implemented independently only after the
interfaces produced by the previous plan exist.

## Cross-Plan Interfaces

Phase 1 produces:

```python
class ReIndex:
    @classmethod
    def open(cls, path: Path) -> "ReIndex": ...
    def import_method_map(self, document: dict, *, run_id: str,
                          binary_sha256: str, method_map_sha256: str) -> int: ...
    def resolve(self, query: TargetQuery) -> list[MethodRecord]: ...
    def upsert_artifact(self, artifact: ArtifactRecord) -> None: ...

@dataclass(frozen=True)
class TargetQuery:
    assembly: str | None = None
    namespace: str | None = None
    type_pattern: str | None = None
    method_pattern: str | None = None
    identity: str | None = None
    rva: int | None = None
    limit: int = 100
```

Phase 2 consumes `ReIndex` and produces:

```python
class NativeAnalyzer:
    def analyze(self, binary: Path, targets: list[MethodRecord]) -> list[StaticFinding]: ...

class GhidraPlanner:
    def plan(self, targets: list[MethodRecord], *, mode: str,
             workers: int | str, batch_size: int) -> GhidraPlan: ...

class GhidraExecutor:
    def execute(self, plan: GhidraPlan, *, resume: bool = False) -> GhidraRunResult: ...
```

Phase 3 consumes indexed methods and produces:

```python
class TraceRecipe:
    target_ids: tuple[int, ...]
    duration_seconds: int
    capture: tuple[str, ...]
    sample_every: int
    max_events_per_target: int

class RuntimeTraceService:
    def trace(self, recipe: TraceRecipe, *, target: str | int,
              mode: str = "attach") -> TraceSummary: ...
```

Phase 4 consumes all indexed evidence and produces:

```python
class Correlator:
    def correlate_target(self, target_id: int) -> CorrelatedTarget: ...

class DossierService:
    def build(self, target_id: int, *, depth: str) -> dict: ...

class BulkRecoveryService:
    def run(self, request: BulkRequest, *, resume: bool = False) -> BulkSummary: ...
```

## File Ownership Map

| Area | Files owned by plan |
|---|---|
| RE Index/query | `src/retoolkit/re_index/**`, `src/retoolkit/commands/index.py`, `src/retoolkit/commands/target.py`, `schemas/re_index.schema.sql`, query/index tests |
| Native/Ghidra | `src/retoolkit/native/**`, `src/retoolkit/ghidra/**`, `src/retoolkit/commands/native.py`, `src/retoolkit/commands/ghidra.py`, `ghidra_scripts/*.java`, Ghidra schemas/tests/runbook |
| Frida/correlation ingest | `src/retoolkit/runtime/trace_*.py`, `src/retoolkit/runtime/multi_trace.js`, `src/retoolkit/commands/trace.py`, runtime schemas/tests |
| Dossier/bulk | `src/retoolkit/analysis/**`, `src/retoolkit/commands/analyze.py`, `src/retoolkit/commands/dossier.py`, `src/retoolkit/commands/bulk.py`, report schemas/tests |
| Shared registration only | `src/retoolkit/cli.py`, `schemas/profile.schema.json`, `profiles/everlusting/profile.json`, `README.md` |

## Master Task 1: Capture Immutable Baselines

**Files:**
- Create: `docs/benchmarks/re-capability-baseline-2026-08-01.md`
- Create: `scripts/benchmark_re_baseline.ps1`
- Create: `tests/test_re_baseline_script.py`

**Interfaces:**
- Consumes: existing CLI, Cpp2IL adapter, Ghidra adapter, Frida capability probe.
- Produces: a hash-addressed baseline record used by the four phase acceptance gates.

- [ ] **Step 1: Write the failing baseline-script contract test**

```python
def test_baseline_script_names_all_required_measurements() -> None:
    text = Path("scripts/benchmark_re_baseline.ps1").read_text(encoding="utf-8")
    required = {
        "cpp2il_method_count", "cpp2il_seconds", "ghidra_cold_seconds",
        "ghidra_cpu_percent", "ghidra_disk_bytes_per_second",
        "frida_probe", "input_sha256", "exit_status",
    }
    assert required <= set(re.findall(r'"([a-z0-9_]+)"\s*:', text))
```

- [ ] **Step 2: Run the focused test and verify the missing script failure**

Run: `py -3.13 -m pytest tests/test_re_baseline_script.py -q`
Expected: `FAIL` because `scripts/benchmark_re_baseline.ps1` does not exist.

- [ ] **Step 3: Implement the baseline script**

The script accepts `-Profile`, `-Output`, and `-GhidraRva`; hashes the binary,
records `Get-Counter` process CPU/disk samples while each command runs, stores
literal stdout/stderr and exit code, and writes JSON atomically through a
temporary file followed by `Move-Item`.

```powershell
param(
  [Parameter(Mandatory)][string]$Profile,
  [Parameter(Mandatory)][string]$Output,
  [Parameter(Mandatory)][UInt64]$GhidraRva
)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  schema_version = '1.0.0'
  input_sha256 = $null
  cpp2il_method_count = $null
  cpp2il_seconds = $null
  ghidra_cold_seconds = $null
  ghidra_cpu_percent = $null
  ghidra_disk_bytes_per_second = $null
  frida_probe = $null
  exit_status = 0
}
```

- [ ] **Step 4: Run unit and dry-run fixture tests**

Run: `py -3.13 -m pytest tests/test_re_baseline_script.py tests/test_cli_contract.py -q`
Expected: all tests pass.

- [ ] **Step 5: Run the live baseline against the current profile**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\benchmark_re_baseline.ps1 `
  -Profile profiles\everlusting\profile.json `
  -Output 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\retoolkit-re-upgrade\baseline.json' `
  -GhidraRva 0x434A60
```

Expected: exit `0`; the record contains method count `206366` and measured
Ghidra cold duration/CPU/disk values. If the live Ghidra capability is absent,
the record contains a typed `missing` classification and the remaining baseline
still completes.

- [ ] **Step 6: Document and commit the baseline**

```bash
git add scripts/benchmark_re_baseline.ps1 tests/test_re_baseline_script.py docs/benchmarks/re-capability-baseline-2026-08-01.md
git commit -m "test: capture REToolkit RE capability baseline"
```

## Master Task 2: Execute the Four Phase Plans

**Files:**
- Consume: the four plan documents listed above.
- Modify: `docs/benchmarks/re-capability-baseline-2026-08-01.md` after each phase.

**Interfaces:**
- Consumes: the exact cross-plan interfaces in this master plan.
- Produces: four reviewed commits/series, each with its own verified rollback.

- [ ] **Step 1: Execute Phase 1 and run its full gate**

Run all commands in `2026-08-01-retoolkit-re-index-query.md`.
Expected: index build and target queries work without Ghidra or Frida.

- [ ] **Step 2: Execute Phase 2 and run its full gate**

Run all commands in `2026-08-01-retoolkit-native-ghidra.md`.
Expected: fast native results, cached targeted headless, scalable parallel
workers, generated GUI bundle, and completed GUI runbook.

- [ ] **Step 3: Execute Phase 3 and run its full gate**

Run all commands in `2026-08-01-retoolkit-frida-correlation.md`.
Expected: one Frida session traces multiple methods and imports correlated
runtime events into the index.

- [ ] **Step 4: Execute Phase 4 and run its full gate**

Run all commands in `2026-08-01-retoolkit-dossier-bulk.md`.
Expected: fast/balanced/deep dossiers and resumable bulk recovery.

## Master Task 3: End-to-End Acceptance and Delivery

**Files:**
- Create: `docs/benchmarks/re-capability-final-2026-08-01.md`
- Create: `D:/Temp/opencode/retoolkit-total-re-upgrade-20260801/retoolkit-total-re-upgrade.patch`
- Create: `D:/Temp/opencode/retoolkit-total-re-upgrade-20260801/verification.md`
- Create: `D:/Temp/opencode/retoolkit-total-re-upgrade-20260801/rollback.ps1`
- Create: `D:/Temp/opencode/retoolkit-total-re-upgrade-20260801/artifact-manifest.json`
- Modify: `README.md`

**Interfaces:**
- Consumes: all four phase artifacts and the immutable baseline.
- Produces: verified source, patch, verification record, rollback, and manifest.

- [ ] **Step 1: Run the full unit and integration suite**

Run: `py -3.13 -m pytest -q`
Expected: all non-live tests pass; only explicitly gated live tests may skip.

- [ ] **Step 2: Run the current-build index and fast dossier gate**

```powershell
retoolkit index build profiles\everlusting\profile.json
retoolkit analyze profiles\everlusting\profile.json `
  --query "AutoChess.BattleUnit::HandleAttackInternal" --depth fast
```

Expected: exit `0`; `206366` methods indexed; no Ghidra/Frida subprocess for
the fast dossier; output and evidence live below `Analysis2`.

- [ ] **Step 3: Run targeted, parallel, and cached Ghidra benchmarks**

```powershell
retoolkit ghidra benchmark profiles\everlusting\profile.json `
  --targets Analysis2\retoolkit-re-upgrade\benchmark-targets.json `
  --workers 1,2,4 --batch-size 128
```

Expected: cold/warm/cache metrics are recorded; cache replay launches no JVM;
100 targets with one worker launch one JVM; the report includes scaling
efficiency without asserting improvement when hardware saturation is observed.

- [ ] **Step 4: Execute the GUI manual gate**

Follow `docs/runbooks/ghidra-bulk-gui.md` exactly, export the GUI bundle result,
and import it with:

```powershell
retoolkit ghidra import-gui profiles\everlusting\profile.json `
  --bundle 'D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis2\retoolkit-re-upgrade\ghidra-gui-bundle'
```

Expected: hash validation succeeds and imported decompilations/xrefs are
queryable from the index.

- [ ] **Step 5: Run the multi-target Frida live gate**

```powershell
retoolkit trace profiles\everlusting\profile.json `
  --query "BattleUnit::*" --duration 30 `
  --capture call-count,thread,backtrace --max-events 1000
```

Expected: one attach/spawn session; runtime addresses map to indexed candidates;
session detaches or terminates cleanly.

- [ ] **Step 6: Run dossier and bulk resume gates**

```powershell
$targetDoc = retoolkit target resolve profiles\everlusting\profile.json "Assembly-CSharp!System.Void AutoChess.BattleUnit::HandleAttackInternal()" | ConvertFrom-Json
$targetId = $targetDoc.data.matches[0].id
retoolkit dossier profiles\everlusting\profile.json --target $targetId --depth deep
retoolkit bulk recover profiles\everlusting\profile.json --failed-only --checkpoint
retoolkit bulk recover profiles\everlusting\profile.json --failed-only --resume
```

Expected: dossier cites provenance/confidence; resume processes only unfinished
work; summaries are deterministic.

- [ ] **Step 7: Verify the old Analysis tree was not modified**

Compare the pre-recorded `Analysis` tree manifest with a fresh read-only hash
manifest. Expected: zero added, removed, or changed files.

- [ ] **Step 8: Build and replay the delivery patch**

Generate the patch from the immutable baseline, apply it in a fresh temporary
repository, run the full test suite there, and compare normalized file hashes.
Expected: `git apply --check` and replay both exit `0`; mismatches `0`.

- [ ] **Step 9: Execute rollback dry-run and isolated real rollback**

Run `rollback.ps1 -WhatIf` against the working repository and run the real
rollback only in the replay repository. Expected: dry-run changes nothing;
isolated rollback restores baseline hashes and baseline commands.

- [ ] **Step 10: Write the final verification record and commit docs**

```bash
git add README.md docs/benchmarks/re-capability-final-2026-08-01.md
git commit -m "docs: publish REToolkit RE capability benchmarks"
```

The verification record must contain baseline and modified commands, literal
outputs, exit statuses, input hashes, tool versions, performance tables,
artifact hashes, patch replay output, rollback output, and the unchanged
`Analysis` manifest result.
