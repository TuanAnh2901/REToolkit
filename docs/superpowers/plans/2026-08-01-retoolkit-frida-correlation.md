# REToolkit Frida Multi-Target Trace and Runtime Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve and trace many indexed IL2CPP methods in one Frida session, aggregate bounded runtime evidence, and map relocated runtime addresses/backtraces back to RE Index methods.

**Architecture:** Define a versioned trace recipe and event contract, generate one Frida JavaScript payload containing the existing resolver plus a multi-target tracer, enforce sampling and event limits inside the injected script, aggregate messages in Python, and commit summary/events to the SQLite index in one validated transaction.

**Tech Stack:** Python 3.13, Frida Python 17.x, JavaScript, existing `resolver.js`, SQLite RE Index, JSON Schema, pytest and Node-based JS shim tests.

## Global Constraints

- Requires Phase 1 RE Index interfaces; consumes Phase 2 address mappings when available.
- One trace request uses one Frida spawn/attach session for all selected targets.
- Runtime tracing is bounded by duration, sampling, and per-target/global event limits.
- Spawn mode always resumes after script load and terminates the spawned child on failure/timeout; attach mode always detaches.
- Raw runtime events and summaries go below the configured `Analysis2` workspace.
- Runtime addresses are stored both raw and normalized as module-relative RVAs.
- Existing resolver functions remain backward compatible and keep their current tests.

---

## Task 1: Define Trace Recipes, Events, and Index Tables

**Files:**
- Create: `src/retoolkit/runtime/trace_models.py`
- Create: `src/retoolkit/runtime/trace_recipes.py`
- Create: `schemas/trace_recipe.schema.json`
- Create: `schemas/runtime_event.schema.json`
- Create: `schemas/trace_summary.schema.json`
- Create: `schemas/re_index_v3.sql`
- Modify: `src/retoolkit/re_index/schema.py`
- Create: `tests/test_trace_models.py`
- Create: `tests/test_re_index_runtime_migration.py`

**Interfaces:**
- Consumes: Phase 1 target IDs/method IDs.
- Produces: `TraceRecipe`, `RuntimeEvent`, `TraceSummary`, migration version 3.

- [ ] **Step 1: Write failing recipe validation tests**

```python
def test_recipe_requires_targets_and_bounded_limits() -> None:
    with pytest.raises(ValueError, match="target_ids"):
        TraceRecipe(target_ids=(), duration_seconds=30)
    with pytest.raises(ValueError, match="duration"):
        TraceRecipe(target_ids=(1,), duration_seconds=0)
    with pytest.raises(ValueError, match="sample_every"):
        TraceRecipe(target_ids=(1,), duration_seconds=30, sample_every=0)


def test_recipe_serialization_is_deterministic() -> None:
    recipe = TraceRecipe((3, 1, 3), 30, ("return", "call-count"), 2, 100)
    assert recipe.to_dict()["target_ids"] == [1, 3]
    assert recipe.to_json() == recipe.to_json()
```

- [ ] **Step 2: Implement immutable models**

```python
@dataclass(frozen=True)
class TraceRecipe:
    target_ids: tuple[int, ...]
    duration_seconds: int
    capture: tuple[str, ...] = ("call-count",)
    sample_every: int = 1
    max_events_per_target: int = 1000
    max_events_total: int = 10000
    backtrace_depth: int = 16

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_ids", tuple(sorted(set(self.target_ids))))
        if not self.target_ids:
            raise ValueError("target_ids must not be empty")
        if not 1 <= self.duration_seconds <= 3600:
            raise ValueError("duration_seconds must be between 1 and 3600")
        if self.sample_every < 1:
            raise ValueError("sample_every must be positive")
```

`RuntimeEvent` includes schema version, session ID, sequence, target/method ID,
thread ID, module base, runtime address, RVA, arguments, return, backtrace,
timestamp, and event kind. `TraceSummary` includes counts, drops, resolve status,
session lifecycle, duration, and artifact hashes.

- [ ] **Step 3: Add migration version 3**

```sql
CREATE TABLE IF NOT EXISTS trace_sessions (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  recipe_sha256 TEXT NOT NULL,
  target_process TEXT NOT NULL,
  mode TEXT NOT NULL,
  started_utc TEXT NOT NULL,
  ended_utc TEXT,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_events (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES trace_sessions(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  method_id INTEGER NOT NULL REFERENCES methods(id),
  thread_id INTEGER,
  runtime_address INTEGER NOT NULL,
  module_base INTEGER NOT NULL,
  rva INTEGER NOT NULL,
  event_kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(session_id, sequence)
);
CREATE INDEX IF NOT EXISTS ix_runtime_events_target ON runtime_events(target_id);
CREATE INDEX IF NOT EXISTS ix_runtime_events_rva ON runtime_events(rva);
CREATE TABLE IF NOT EXISTS trace_aggregates (
  session_id TEXT NOT NULL REFERENCES trace_sessions(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  call_count INTEGER NOT NULL,
  emitted_count INTEGER NOT NULL,
  dropped_count INTEGER NOT NULL,
  first_timestamp REAL,
  last_timestamp REAL,
  PRIMARY KEY(session_id, target_id)
);
PRAGMA user_version = 3;
```

- [ ] **Step 4: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_trace_models.py tests/test_re_index_runtime_migration.py -q`
Expected: all tests pass and v2 databases migrate without losing methods,
native findings, functions, edges, or decompilations.

```bash
git add src/retoolkit/runtime/trace_models.py src/retoolkit/runtime/trace_recipes.py schemas/trace_recipe.schema.json schemas/runtime_event.schema.json schemas/trace_summary.schema.json schemas/re_index_v3.sql src/retoolkit/re_index/schema.py tests/test_trace_models.py tests/test_re_index_runtime_migration.py
git commit -m "feat: define runtime trace contracts"
```

## Task 2: Extend Resolver and Implement Multi-Target Frida Script

**Files:**
- Modify: `src/retoolkit/runtime/resolver.js`
- Create: `src/retoolkit/runtime/multi_trace.js`
- Modify: `tests/js/frida-shim.mjs`
- Create: `tests/js/test-multi-trace.mjs`
- Create: `tests/test_runtime_js.py`

**Interfaces:**
- Consumes: serialized recipe plus target records containing managed identity/RVA.
- Produces: ordered `ready`, `resolved`, `enter`, `leave`, `aggregate`, `complete`, and `error` messages.

- [ ] **Step 1: Write failing Node shim tests**

```javascript
test('installs many hooks and emits one ready sentinel', async () => {
  const runtime = makeShim({ methods: [target(1, 0x1000), target(2, 0x2000)] });
  const messages = await runTrace(runtime, recipe([1, 2]));
  assert.equal(messages.filter(m => m.kind === 'ready').length, 1);
  assert.deepEqual(messages.filter(m => m.kind === 'resolved').map(m => m.target_id), [1, 2]);
  assert.equal(runtime.interceptorAttachCount, 2);
});

test('sampling and limits bound emitted events while preserving call count', async () => {
  const messages = await runHotTarget({ calls: 100 }, recipe([1], { sample_every: 10, max_events_per_target: 5 }));
  const aggregate = messages.find(m => m.kind === 'aggregate');
  assert.equal(aggregate.call_count, 100);
  assert.equal(aggregate.emitted_count, 5);
  assert.ok(aggregate.dropped_count > 0);
});
```

- [ ] **Step 2: Extend the JS shim**

Implement deterministic fake `Interceptor.attach/detach`, `Thread.backtrace`,
`Process.getCurrentThreadId`, module base, pointer arithmetic, argument/return
values, and explicit invocation of registered callbacks.

- [ ] **Step 3: Add resolver return shape without breaking existing calls**

Add:

```javascript
function resolveTarget(spec) {
  const module = waitForGameAssembly();
  const pointer = spec.rva !== undefined
    ? module.base.add(ptr(spec.rva))
    : findMethod(spec.assembly, spec.namespace, spec.type, spec.method, spec.args || -1);
  return {
    target_id: spec.target_id,
    method_id: spec.method_id,
    module_base: module.base.toString(),
    runtime_address: pointer.toString(),
    rva: pointer.sub(module.base).toString(),
  };
}
```

Existing exported resolver names and message contracts remain valid.

- [ ] **Step 4: Implement bounded multi-target tracing**

`multi_trace.js` validates `RETOOLKIT_PARAMS`, resolves all targets before
attaching, installs one hook per distinct runtime address, maintains per-target
call/emitted/dropped counters, samples in `onEnter/onLeave`, optionally captures
bounded arguments/returns/backtraces, and detaches all listeners in `finish()`.

```javascript
const state = new Map();
const listeners = [];

function shouldEmit(target) {
  target.call_count += 1;
  if ((target.call_count - 1) % recipe.sample_every !== 0) return false;
  if (target.emitted_count >= recipe.max_events_per_target) return false;
  if (globalEmitted >= recipe.max_events_total) return false;
  target.emitted_count += 1;
  globalEmitted += 1;
  return true;
}
```

Messages include a monotonic sequence assigned inside the script. `complete`
is emitted only after listeners detach and aggregate records are sent.

- [ ] **Step 5: Run JS and Python wrapper tests**

Run: `node --test tests/js/test-multi-trace.mjs`
Expected: all Node tests pass.

Run: `py -3.13 -m pytest tests/test_runtime_js.py tests/acceptance/test_content_scan.py -q`
Expected: all tests pass; resolver compatibility scan remains green.

- [ ] **Step 6: Commit**

```bash
git add src/retoolkit/runtime/resolver.js src/retoolkit/runtime/multi_trace.js tests/js/frida-shim.mjs tests/js/test-multi-trace.mjs tests/test_runtime_js.py
git commit -m "feat: trace multiple IL2CPP targets per Frida session"
```

## Task 3: Implement Python Trace Service and Aggregation

**Files:**
- Create: `src/retoolkit/runtime/trace_service.py`
- Create: `src/retoolkit/runtime/trace_aggregate.py`
- Modify: `src/retoolkit/adapters/frida.py`
- Modify: `src/retoolkit/adapters/frida_runner.py`
- Modify: `tests/fakes/frida.py`
- Create: `tests/test_trace_service.py`
- Create: `tests/test_trace_aggregate.py`
- Modify: `tests/test_frida_adapter.py`
- Modify: `tests/test_frida_runner.py`

**Interfaces:**
- Consumes: `TraceRecipe`, indexed targets, process name/PID.
- Produces: `RuntimeTraceService.trace(...) -> TraceSummary` plus JSONL artifacts.

- [ ] **Step 1: Write failing single-session and lifecycle tests**

```python
def test_two_targets_use_one_attach_session(fake_frida, service, recipe) -> None:
    summary = service.trace(recipe, target=4242, mode="attach")
    assert fake_frida.device.attach_calls == [4242]
    assert summary.resolved_targets == 2
    assert summary.session_status == "completed"
    assert fake_frida.sessions[0].detached is True


def test_spawn_failure_resumes_then_kills_child(fake_frida, service, recipe) -> None:
    fake_frida.script_error = RuntimeError("load failed")
    with pytest.raises(ResultError):
        service.trace(recipe, target="game.exe", mode="spawn")
    assert fake_frida.device.resume_calls == [fake_frida.spawned_pid]
    assert fake_frida.device.kill_calls == [fake_frida.spawned_pid]
```

- [ ] **Step 2: Implement message validation and aggregation**

```python
class TraceAggregator:
    def accept(self, envelope: dict) -> None:
        payload = envelope.get("message", {}).get("payload")
        errors = validate(payload, "runtime_event.schema.json")
        if errors:
            raise ResultError.validation("invalid Frida runtime event", details=errors)
        if payload["sequence"] <= self.last_sequence:
            raise ResultError.validation("non-monotonic Frida event sequence")
        self.last_sequence = payload["sequence"]
        self.events.append(RuntimeEvent.from_dict(payload))
```

Aggregate counts independently of sampled event rows. Reject unknown target IDs,
address/RVA mismatches, duplicate sequences, and completion before readiness.

- [ ] **Step 3: Implement `RuntimeTraceService`**

```python
class RuntimeTraceService:
    def __init__(self, index: ReIndex, adapter: FridaAdapter, workspace: Path) -> None:
        self.index = index
        self.adapter = adapter
        self.workspace = workspace

    def trace(self, recipe: TraceRecipe, *, target: str | int,
              mode: str = "attach") -> TraceSummary:
        targets = self.index.fetch_trace_targets(recipe.target_ids)
        script = Path(__file__).with_name("multi_trace.js")
        messages = self.adapter.run_trace(
            target=target, trace_script=script,
            params={"recipe": recipe.to_dict(), "targets": [t.to_trace_dict() for t in targets]},
            mode=mode,
        )
        aggregator = TraceAggregator(recipe, targets)
        for message in messages:
            aggregator.accept(message)
        return aggregator.finish(self.workspace)
```

Write raw JSONL and summary JSON atomically; add both to the evidence manifest.

- [ ] **Step 4: Preserve backward compatibility in `FridaAdapter.run_trace`**

Attach mode selects a PID; spawn mode passes the process path/name directly to
`FridaRunner` instead of preselecting a PID. Existing single-trace callers still
receive `list[dict]`.

- [ ] **Step 5: Run service/adapter tests and commit**

Run: `py -3.13 -m pytest tests/test_trace_service.py tests/test_trace_aggregate.py tests/test_frida_adapter.py tests/test_frida_runner.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/runtime/trace_service.py src/retoolkit/runtime/trace_aggregate.py src/retoolkit/adapters/frida.py src/retoolkit/adapters/frida_runner.py tests/fakes/frida.py tests/test_trace_service.py tests/test_trace_aggregate.py tests/test_frida_adapter.py tests/test_frida_runner.py
git commit -m "feat: aggregate bounded Frida runtime evidence"
```

## Task 4: Import Runtime Events and Correlate Addresses

**Files:**
- Create: `src/retoolkit/re_index/runtime.py`
- Create: `tests/test_runtime_index_import.py`
- Create: `tests/test_runtime_address_correlation.py`

**Interfaces:**
- Consumes: validated raw events/summary and indexed methods.
- Produces: `import_trace`, `resolve_runtime_address`, aggregate query methods.

- [ ] **Step 1: Write failing atomic-import and relocation tests**

```python
def test_import_trace_is_all_or_nothing(index, valid_trace) -> None:
    broken = [*valid_trace, {**valid_trace[-1], "sequence": valid_trace[-2]["sequence"]}]
    with pytest.raises(ResultError):
        import_trace(index, session_doc(), broken, summary_doc())
    assert index.scalar("SELECT COUNT(*) FROM runtime_events") == 0


def test_runtime_address_maps_by_module_relative_rva(index_with_methods) -> None:
    match = resolve_runtime_address(index_with_methods,
                                    module_base=0x7FF600000000,
                                    runtime_address=0x7FF60000434A60)
    assert match.rva == 0x434A60
```

- [ ] **Step 2: Implement transactional import**

Validate recipe/event/summary hashes, ensure every target/method pair exists,
derive `rva = runtime_address - module_base`, compare it with the resolved event
RVA, then insert the session, events, and aggregates in one transaction.

- [ ] **Step 3: Implement exact and containing-function address correlation**

Resolve exact method RVA first. If Phase 2 function bounds exist, resolve the
containing function and label it `containing`. Multiple candidates are returned
as a conflict-preserving list ordered by confidence and identity.

- [ ] **Step 4: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_runtime_index_import.py tests/test_runtime_address_correlation.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/re_index/runtime.py tests/test_runtime_index_import.py tests/test_runtime_address_correlation.py
git commit -m "feat: correlate runtime addresses with indexed methods"
```

## Task 5: Add Trace CLI, Profile Recipes, and Live Gate

**Files:**
- Create: `src/retoolkit/commands/trace.py`
- Modify: `src/retoolkit/cli.py`
- Modify: `schemas/profile.schema.json`
- Modify: `profiles/everlusting/profile.json`
- Create: `tests/test_cli_trace.py`
- Modify: `tests/test_profile.py`
- Modify: `tests/live/test_frida_live.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: target queries, trace recipe defaults, process selection.
- Produces: `retoolkit trace` and imported runtime evidence.

- [ ] **Step 1: Write failing parser and service-invocation tests**

```python
def test_trace_parser_accepts_required_capture_options() -> None:
    args = build_parser().parse_args([
        "trace", "p.json", "--query", "BattleUnit::*", "--duration", "30",
        "--capture", "args,return,call-count,thread,backtrace",
        "--sample-every", "10", "--max-events", "1000",
    ])
    assert args.duration == 30
    assert args.max_events == 1000
```

- [ ] **Step 2: Register the trace command**

```text
retoolkit trace PROFILE
  (--query QUERY | --target-id ID ...)
  [--pid PID | --process NAME]
  [--mode attach|spawn]
  [--duration SECONDS]
  [--capture LIST]
  [--sample-every N]
  [--max-events N]
  [--backtrace-depth N]
```

Resolve the query through Phase 1, create target rows if absent, build a recipe,
run one service session, import it, and return artifact paths/counts in
`Result.ok("trace", data)`.

- [ ] **Step 3: Add profile defaults**

```json
{
  "frida_trace": {
    "duration_seconds": 30,
    "capture": ["call-count", "thread"],
    "sample_every": 1,
    "max_events_per_target": 1000,
    "max_events_total": 10000,
    "backtrace_depth": 16
  }
}
```

- [ ] **Step 4: Run CLI/profile and full suites**

Run: `py -3.13 -m pytest tests/test_cli_trace.py tests/test_profile.py -q`
Expected: focused tests pass.

Run: `py -3.13 -m pytest -q`
Expected: all non-live tests pass.

- [ ] **Step 5: Run the current-build multi-target live gate**

```powershell
$env:RETOOLKIT_LIVE_FRIDA='1'
$env:RETOOLKIT_GAME_ROOT='D:\SteamLibrary\steamapps\common\Everlusting Life'
py -3.13 -m pytest tests\live\test_frida_live.py -v
```

Expected: one process session, at least two targets resolved, ready/complete
sentinels observed, monotonic events imported, runtime RVAs mapped, clean
detach/kill, and outputs under `Analysis2`.

- [ ] **Step 6: Commit Phase 3**

```bash
git add src/retoolkit/commands/trace.py src/retoolkit/cli.py schemas/profile.schema.json profiles/everlusting/profile.json tests/test_cli_trace.py tests/test_profile.py tests/live/test_frida_live.py README.md
git commit -m "feat: expose correlated multi-target runtime tracing"
```

## Phase 3 Verification and Rollback

- Produce source/archive, `phase-3-frida.patch`, `phase-3-verification.md`, and
  `phase-3-rollback.ps1`.
- Verification includes one-session fake proof, Node shim output, current-build
  live command/output/exit status, trace hashes, event counts, and cleanup state.
- Patch replay runs Phase 1-3 non-live tests.
- Rollback restores the pre-Phase-3 resolver/adapter and removes only Phase 3
  schema/code artifacts; v3 databases are preserved as data and reopened by the
  baseline code only after exporting a backup.
