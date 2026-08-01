# REToolkit Target Dossier and Bulk Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Synthesize indexed managed, native, Ghidra, and Frida evidence into confidence-scored target dossiers and run resumable bulk recovery that schedules only missing work.

**Architecture:** Add explicit correlation rules over the RE Index, generate schema-validated dossiers at fast/balanced/deep depth, rank failed or queried methods into a persistent work queue, and orchestrate Phase 2/3 services through artifact dependencies and cache state rather than rerunning the old linear pipeline.

**Tech Stack:** Python 3.13, SQLite RE Index, JSON Schema, existing evidence/state infrastructure, Phase 2 native/Ghidra services, Phase 3 runtime trace service, pytest.

## Global Constraints

- Requires Phase 1-3 public interfaces and migrations.
- Reports distinguish observations from inferences and retain conflicting evidence.
- `fast` depth starts neither Ghidra nor Frida.
- `balanced` schedules only the missing bounded Ghidra or runtime evidence.
- `deep` may expand caller/callee depth but obeys configured target/event limits.
- Work queue state is transactional and interrupted `running` items return to `pending` during resume.
- Identical evidence hashes produce byte-deterministic dossiers and bulk summaries.
- All outputs use the configured `Analysis2` workspace; existing `Analysis` remains unchanged.

---

## Task 1: Add Correlation Records and Explicit Confidence Rules

**Files:**
- Create: `src/retoolkit/analysis/__init__.py`
- Create: `src/retoolkit/analysis/models.py`
- Create: `src/retoolkit/analysis/correlation.py`
- Create: `schemas/correlated_target.schema.json`
- Create: `schemas/re_index_v4.sql`
- Modify: `src/retoolkit/re_index/schema.py`
- Create: `tests/test_correlation.py`
- Create: `tests/test_re_index_analysis_migration.py`

**Interfaces:**
- Consumes: methods, static findings, functions, decompilations, edges, runtime events.
- Produces: `EvidenceRef`, `Claim`, `CorrelatedTarget`, `Correlator.correlate_target`.

- [ ] **Step 1: Write failing confidence and conflict tests**

```python
def test_method_map_plus_native_entry_is_probable(indexed_target) -> None:
    correlated = Correlator(indexed_target.index).correlate_target(indexed_target.id)
    assert correlated.address_claim.confidence == "probable"
    assert {e.kind for e in correlated.address_claim.evidence} == {
        "cpp2il-method-map", "native-entry"
    }


def test_matching_ghidra_and_runtime_evidence_is_confirmed(fully_observed_target) -> None:
    correlated = Correlator(fully_observed_target.index).correlate_target(fully_observed_target.id)
    assert correlated.address_claim.confidence == "confirmed"


def test_conflicting_runtime_rva_is_preserved_not_overwritten(conflicting_target) -> None:
    correlated = Correlator(conflicting_target.index).correlate_target(conflicting_target.id)
    assert correlated.address_claim.confidence == "conflict"
    assert len(correlated.address_claim.conflicts) == 1
```

- [ ] **Step 2: Implement immutable correlation models**

```python
Confidence = Literal["candidate", "probable", "high", "confirmed", "conflict"]


@dataclass(frozen=True)
class EvidenceRef:
    kind: str
    artifact_id: int | None
    record_id: int | None
    observed: bool
    summary: str


@dataclass(frozen=True)
class Claim:
    name: str
    value: object
    confidence: Confidence
    evidence: tuple[EvidenceRef, ...]
    conflicts: tuple[EvidenceRef, ...] = ()


@dataclass(frozen=True)
class CorrelatedTarget:
    target_id: int
    method: MethodRecord
    address_claim: Claim
    function_claim: Claim | None
    callers: tuple[Claim, ...]
    callees: tuple[Claim, ...]
    runtime: tuple[Claim, ...]
```

- [ ] **Step 3: Implement rule table rather than numeric magic**

```python
def address_confidence(kinds: set[str], conflicts: tuple[EvidenceRef, ...]) -> Confidence:
    if conflicts:
        return "conflict"
    if "frida-runtime-hit" in kinds and "cpp2il-method-map" in kinds:
        return "confirmed"
    if "ghidra-function" in kinds and "native-entry" in kinds:
        return "high"
    if "cpp2il-method-map" in kinds and "native-entry" in kinds:
        return "probable"
    return "candidate"
```

Each claim lists observation records first, inference records second, and
conflicts separately. Unknown sources never raise confidence.

- [ ] **Step 4: Add analysis migration version 4**

```sql
CREATE TABLE IF NOT EXISTS correlated_claims (
  id INTEGER PRIMARY KEY,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  claim_name TEXT NOT NULL,
  claim_json TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  created_utc TEXT NOT NULL,
  UNIQUE(target_id, claim_name, evidence_hash)
);
CREATE TABLE IF NOT EXISTS dossier_artifacts (
  target_id INTEGER NOT NULL REFERENCES targets(id),
  depth TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  artifact_id INTEGER NOT NULL REFERENCES artifacts(id),
  PRIMARY KEY(target_id, depth, evidence_hash)
);
PRAGMA user_version = 4;
```

- [ ] **Step 5: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_correlation.py tests/test_re_index_analysis_migration.py -q`
Expected: all tests pass and v3 databases migrate transactionally.

```bash
git add src/retoolkit/analysis schemas/correlated_target.schema.json schemas/re_index_v4.sql src/retoolkit/re_index/schema.py tests/test_correlation.py tests/test_re_index_analysis_migration.py
git commit -m "feat: correlate static and runtime RE evidence"
```

## Task 2: Build Fast, Balanced, and Deep Target Dossiers

**Files:**
- Create: `src/retoolkit/analysis/dossier.py`
- Create: `schemas/target_dossier.schema.json`
- Create: `src/retoolkit/commands/dossier.py`
- Modify: `src/retoolkit/cli.py`
- Create: `tests/test_dossier.py`
- Create: `tests/test_cli_dossier.py`

**Interfaces:**
- Consumes: `Correlator`, index evidence and target ID.
- Produces: `DossierService.build(target_id, depth) -> dict`, `retoolkit dossier`.

- [ ] **Step 1: Write failing dossier shape and cache tests**

```python
def test_fast_dossier_contains_required_sections_without_external_tools(index, external_spy) -> None:
    dossier = DossierService(index).build(1, depth="fast")
    assert set(dossier) >= {"schema_version", "target", "addresses", "managed",
                            "native", "graph", "runtime", "claims", "provenance"}
    assert external_spy.invocations == []


def test_identical_evidence_returns_same_bytes_and_cache_hit(index) -> None:
    service = DossierService(index)
    first = service.build_bytes(1, depth="deep")
    second = service.build_bytes(1, depth="deep")
    assert first == second
    assert service.last_cache_hit is True
```

- [ ] **Step 2: Implement depth contracts**

```python
DEPTH_REQUIREMENTS = {
    "fast": frozenset({"method-map", "native"}),
    "balanced": frozenset({"method-map", "native", "one-deep-source"}),
    "deep": frozenset({"method-map", "native", "ghidra", "runtime", "graph-depth"}),
}
```

`DossierService` only synthesizes evidence. Scheduling missing work belongs to
Task 5's analyze orchestrator. If requested evidence is absent, the dossier
contains a deterministic `missing_evidence` list instead of invoking a tool.

- [ ] **Step 3: Implement canonical dossier serialization**

```python
class DossierService:
    def build(self, target_id: int, *, depth: str) -> dict:
        if depth not in DEPTH_REQUIREMENTS:
            raise ResultError.validation(f"unknown dossier depth {depth!r}")
        correlated = Correlator(self.index).correlate_target(target_id)
        document = self._document(correlated, depth)
        errors = validate(document, "target_dossier.schema.json")
        if errors:
            raise ResultError.internal("dossier failed schema validation", details=errors)
        return document

    def build_bytes(self, target_id: int, *, depth: str) -> bytes:
        return (json.dumps(self.build(target_id, depth=depth), sort_keys=True,
                           ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
```

- [ ] **Step 4: Add dossier CLI**

```text
retoolkit dossier PROFILE --target 1 --depth fast|balanced|deep [--output PATH]
```

Default output is `profile.workspace / "dossiers" / str(target_id) / f"{depth}.json"`. The handler
adds the artifact to evidence and returns path/hash/cache status.

- [ ] **Step 5: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_dossier.py tests/test_cli_dossier.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/analysis/dossier.py schemas/target_dossier.schema.json src/retoolkit/commands/dossier.py src/retoolkit/cli.py tests/test_dossier.py tests/test_cli_dossier.py
git commit -m "feat: generate evidence-backed target dossiers"
```

## Task 3: Add Persistent Work Queue and Recovery Ranking

**Files:**
- Create: `src/retoolkit/analysis/work_queue.py`
- Create: `src/retoolkit/analysis/ranking.py`
- Create: `src/retoolkit/analysis/cpp2il_failures.py`
- Create: `schemas/bulk_request.schema.json`
- Create: `schemas/bulk_progress.schema.json`
- Create: `schemas/re_index_v5.sql`
- Modify: `src/retoolkit/re_index/schema.py`
- Create: `tests/test_work_queue.py`
- Create: `tests/test_recovery_ranking.py`
- Create: `tests/test_cpp2il_failures.py`

**Interfaces:**
- Consumes: queries, Cpp2IL log, static/runtime/index statistics.
- Produces: `WorkQueue`, `RecoveryCandidate`, `rank_candidates`, migration version 5.

- [ ] **Step 1: Write failing interrupted-state and deterministic-ranking tests**

```python
def test_running_items_return_to_pending_on_resume(queue) -> None:
    item = queue.enqueue(target_id=1, operation="ghidra", priority=50)
    queue.claim("worker-1")
    queue.recover_interrupted(active_workers=set())
    assert queue.get(item.id).state == "pending"


def test_ranking_is_deterministic() -> None:
    candidates = [candidate(2, callers=1, runtime_hits=9),
                  candidate(1, callers=10, runtime_hits=0)]
    assert [c.target_id for c in rank_candidates(candidates)] == [2, 1]
```

- [ ] **Step 2: Implement migration version 5**

```sql
CREATE TABLE IF NOT EXISTS work_items (
  id INTEGER PRIMARY KEY,
  request_id TEXT NOT NULL,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  operation TEXT NOT NULL,
  priority INTEGER NOT NULL,
  state TEXT NOT NULL,
  attempt INTEGER NOT NULL DEFAULT 0,
  worker_id TEXT,
  input_hash TEXT NOT NULL,
  error_code TEXT,
  error_message TEXT,
  updated_utc TEXT NOT NULL,
  UNIQUE(request_id, target_id, operation, input_hash)
);
CREATE INDEX IF NOT EXISTS ix_work_claim ON work_items(request_id, state, priority DESC, id);
PRAGMA user_version = 5;
```

Claim one item with `BEGIN IMMEDIATE`, select the highest priority pending row,
update it to running, commit, then return it. Resume resets only workers not in
the supplied active-worker set.

- [ ] **Step 3: Parse Cpp2IL warnings into typed failure candidates**

Recognize `Skipping <identity>: Decompilation failed`, `Method <identity> is too
big`, missing pointer, and malformed-map failures. Store raw log line, category,
identity, and resolved target candidates. Unresolved log lines remain in the
summary rather than being discarded.

- [ ] **Step 4: Implement explicit ranking tuple**

```python
def ranking_key(candidate: RecoveryCandidate) -> tuple:
    return (
        -candidate.profile_priority,
        -int(candidate.runtime_hits > 0),
        -candidate.runtime_hits,
        -candidate.caller_count,
        -candidate.string_reference_count,
        candidate.native_size if candidate.native_size is not None else 2**63,
        candidate.identity,
        candidate.rva,
    )
```

Profile priority is the only manual weight. The rest are lexicographic,
documented signals to keep ranking explainable.

- [ ] **Step 5: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_work_queue.py tests/test_recovery_ranking.py tests/test_cpp2il_failures.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/analysis/work_queue.py src/retoolkit/analysis/ranking.py src/retoolkit/analysis/cpp2il_failures.py schemas/bulk_request.schema.json schemas/bulk_progress.schema.json schemas/re_index_v5.sql src/retoolkit/re_index/schema.py tests/test_work_queue.py tests/test_recovery_ranking.py tests/test_cpp2il_failures.py
git commit -m "feat: queue and rank bulk RE recovery work"
```

## Task 4: Implement Resumable Bulk Recovery

**Files:**
- Create: `src/retoolkit/analysis/bulk.py`
- Create: `schemas/bulk_summary.schema.json`
- Create: `src/retoolkit/commands/bulk.py`
- Modify: `src/retoolkit/cli.py`
- Create: `tests/test_bulk_recovery.py`
- Create: `tests/test_cli_bulk.py`

**Interfaces:**
- Consumes: work queue, Phase 2 native/Ghidra services, Phase 3 trace service.
- Produces: `BulkRequest`, `BulkRecoveryService.run`, bulk CLI and four output files.

- [ ] **Step 1: Write failing schedule and resume tests**

```python
def test_bulk_runs_fast_scan_before_scheduling_ghidra(services, request) -> None:
    summary = BulkRecoveryService(**services).run(request)
    assert services["calls"][0].kind == "native"
    assert all(call.kind != "ghidra" for call in services["calls"]
               if call.target_id in services["native_resolved"])


def test_resume_processes_only_unfinished_items(services, interrupted_request) -> None:
    first = BulkRecoveryService(**services).run(interrupted_request)
    second = BulkRecoveryService(**services).run(interrupted_request, resume=True)
    assert set(second.processed_target_ids).isdisjoint(first.completed_target_ids)
```

- [ ] **Step 2: Implement request model and scheduling**

```python
@dataclass(frozen=True)
class BulkRequest:
    request_id: str
    query: TargetQuery | None = None
    failed_only: bool = False
    operations: tuple[str, ...] = ("native", "ghidra")
    ghidra_mode: str = "auto"
    workers: int | str = "auto"
    checkpoint_every: int = 128
    max_targets: int = 10000
```

Create target/work rows once, run native work first, re-evaluate missing
evidence, then group remaining Ghidra work through `GhidraPlanner`. Runtime work
is scheduled only when included in `operations`.

- [ ] **Step 3: Implement deterministic outputs**

Write atomically:

```text
profile.workspace / "bulk" / request_id / "bulk-summary.json"
profile.workspace / "bulk" / request_id / "recovered-methods.jsonl"
profile.workspace / "bulk" / request_id / "failed-methods.jsonl"
profile.workspace / "bulk" / request_id / "recovery-progress.json"
```

Sort recovered/failed records by target ID. Summary includes counts by operation,
status/error category, Ghidra mode, cache hits, durations, input/tool hashes, and
resume history.

- [ ] **Step 4: Add bulk CLI**

```text
retoolkit bulk recover PROFILE
  [--query QUERY | --failed-only]
  [--operations native,ghidra,frida]
  [--ghidra-mode auto|targeted|parallel|gui]
  [--workers auto|N]
  [--checkpoint-every N]
  [--max-targets N]
  [--resume]
```

Require exactly one of `--query` and `--failed-only`. GUI selection creates a
bundle and marks items `waiting_gui` rather than claiming completion.

- [ ] **Step 5: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_bulk_recovery.py tests/test_cli_bulk.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/analysis/bulk.py schemas/bulk_summary.schema.json src/retoolkit/commands/bulk.py src/retoolkit/cli.py tests/test_bulk_recovery.py tests/test_cli_bulk.py
git commit -m "feat: add resumable bulk method recovery"
```

## Task 5: Implement Query-Driven Analyze Orchestration

**Files:**
- Create: `src/retoolkit/analysis/orchestrator.py`
- Create: `src/retoolkit/commands/analyze.py`
- Modify: `src/retoolkit/cli.py`
- Create: `schemas/analysis_plan.schema.json`
- Create: `tests/test_analysis_orchestrator.py`
- Create: `tests/test_cli_analyze.py`

**Interfaces:**
- Consumes: query, requested depth, evidence cache state and all phase services.
- Produces: `AnalysisOrchestrator.plan/run`, `retoolkit analyze`.

- [ ] **Step 1: Write failing depth-planning tests**

```python
def test_fast_plan_contains_no_external_stage(orchestrator) -> None:
    plan = orchestrator.plan(query("N.T::M"), depth="fast")
    assert [step.kind for step in plan.steps] == ["resolve", "native", "correlate", "dossier"]


def test_balanced_plan_uses_cached_ghidra_without_process(orchestrator_with_cache) -> None:
    plan = orchestrator_with_cache.plan(query("N.T::M"), depth="balanced")
    assert all(step.kind != "ghidra-process" for step in plan.steps)
    assert any(step.kind == "ghidra-cache" for step in plan.steps)
```

- [ ] **Step 2: Implement artifact dependency planning**

```python
@dataclass(frozen=True)
class AnalysisStep:
    kind: str
    target_ids: tuple[int, ...]
    input_hash: str
    reason: str


class AnalysisOrchestrator:
    def plan(self, query: TargetQuery, *, depth: str) -> AnalysisPlan: ...
    def run(self, plan: AnalysisPlan, *, resume: bool = False) -> AnalysisResult: ...
```

Plan only missing/stale artifacts. `fast` never includes external tools.
`balanced` chooses one available deep source using profile preference and cache.
`deep` includes Ghidra and runtime evidence subject to limits.

- [ ] **Step 3: Add analyze CLI with plan-only mode**

```text
retoolkit analyze PROFILE --query QUERY --depth fast|balanced|deep [--plan-only] [--resume]
```

`--plan-only` prints the schema-validated plan and has no side effects.

- [ ] **Step 4: Test stale-input rescheduling and commit**

Changing only the trace recipe invalidates runtime/correlation/dossier steps,
not method-map/native/Ghidra artifacts. Changing the binary invalidates all
address-dependent evidence.

Run: `py -3.13 -m pytest tests/test_analysis_orchestrator.py tests/test_cli_analyze.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/analysis/orchestrator.py src/retoolkit/commands/analyze.py src/retoolkit/cli.py schemas/analysis_plan.schema.json tests/test_analysis_orchestrator.py tests/test_cli_analyze.py
git commit -m "feat: orchestrate query-driven RE analysis"
```

## Task 6: End-to-End A/B/C Acceptance, Docs, and Live Gates

**Files:**
- Create: `tests/integration/test_total_re_workflow.py`
- Create: `tests/live/test_total_re_live.py`
- Create: `docs/runbooks/target-dossier.md`
- Create: `docs/runbooks/bulk-recovery.md`
- Create: `docs/runbooks/runtime-tracing.md`
- Modify: `README.md`
- Modify: `tests/test_runbook_references.py`

**Interfaces:**
- Consumes: all Phase 1-4 commands.
- Produces: documented, verified A/B/C workflows.

- [ ] **Step 1: Write mocked end-to-end acceptance test**

```python
def test_total_workflow_builds_index_traces_decompiles_and_reports(fixture_profile) -> None:
    build = run_cli("index", "build", fixture_profile)
    analyze = run_cli("analyze", fixture_profile, "--query", "N.T::M", "--depth", "deep")
    dossier = json.loads(Path(analyze["data"]["dossier"]).read_text())
    assert build["data"]["method_count"] == 3
    assert dossier["claims"]["address"]["confidence"] == "confirmed"
    assert dossier["provenance"]
```

- [ ] **Step 2: Write focused runbooks**

Each runbook starts with prerequisites, exact commands, expected JSON fields,
artifact locations, resume behavior, failure diagnostics, and rollback. The
Ghidra GUI details remain in the Phase 2 GUI runbook and are linked rather than
duplicated.

- [ ] **Step 3: Run the full non-live suite**

Run: `py -3.13 -m pytest -q`
Expected: all non-live tests pass; only explicit live gates skip.

- [ ] **Step 4: Run live A target-dossier gate**

```powershell
retoolkit analyze profiles\everlusting\profile.json `
  --query "AutoChess.BattleUnit::HandleAttackInternal" --depth deep
```

Expected: method resolution, native findings, Ghidra evidence, runtime status,
confidence/provenance and dossier artifact all succeed. When no battle calls the
method during the trace window, runtime is `observed_zero_calls`, not fabricated.

- [ ] **Step 5: Run live B bulk-recovery and resume gate**

```powershell
retoolkit bulk recover profiles\everlusting\profile.json --failed-only `
  --operations native,ghidra --workers auto --checkpoint-every 128
retoolkit bulk recover profiles\everlusting\profile.json --failed-only --resume
```

Expected: deterministic summaries and second run processes only unfinished work.

- [ ] **Step 6: Run live C runtime-first gate**

```powershell
retoolkit trace profiles\everlusting\profile.json --query "BattleUnit::*" `
  --duration 30 --capture call-count,thread,backtrace --max-events 1000
```

Expected: one Frida session, bounded events, mapped runtime addresses and clean
lifecycle.

- [ ] **Step 7: Verify performance and filesystem constraints**

Compare final metrics to the immutable baseline. Verify index-only/cache-hit
queries spawn no JVM, warm targeted throughput is at least 2x fresh-import
baseline, worker scaling is reported honestly, and the old `Analysis` manifest
has zero changes.

- [ ] **Step 8: Commit Phase 4 docs/tests**

```bash
git add tests/integration/test_total_re_workflow.py tests/live/test_total_re_live.py docs/runbooks/target-dossier.md docs/runbooks/bulk-recovery.md docs/runbooks/runtime-tracing.md README.md tests/test_runbook_references.py
git commit -m "test: verify complete REToolkit RE workflows"
```

## Phase 4 Verification and Rollback

- Produce modified source/archive, `phase-4-dossier-bulk.patch`,
  `phase-4-verification.md`, and `phase-4-rollback.ps1`.
- Verification includes A/B/C commands, literal outputs, exit statuses,
  performance comparison, current-build hashes, dossier/bulk/trace artifact
  hashes, patch replay, and unchanged `Analysis` manifest.
- Rollback removes Phase 4 code/schema additions and restores shared CLI/profile
  files while preserving user-generated database/report backups.
