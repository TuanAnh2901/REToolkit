# REToolkit Total RE Capability Upgrade Design

**Date:** 2026-08-01  
**Status:** Approved design, pending implementation plan  
**Primary target:** the current IL2CPP game build, followed by reusable profiles for other builds

## 1. Objective

Upgrade REToolkit from a linear wrapper around metadata fixup, Cpp2IL, Frida,
and targeted Ghidra into a queryable reverse-engineering system. A user must be
able to request one target dossier, recover a large set of difficult methods,
or collect runtime evidence without manually translating managed identities,
RVAs, virtual addresses, file offsets, and runtime addresses between tools.

The upgrade includes all three workflows:

1. **Target dossier:** resolve a class/method query and produce correlated
   static and runtime evidence.
2. **Bulk recovery:** prioritize and recover large groups of methods, including
   methods for which managed decompilation failed.
3. **Runtime-first investigation:** trace selected methods and correlate live
   addresses, arguments, return values, call counts, and backtraces with the
   static index.

## 2. Constraints

- Preserve the existing metadata-fixup and Cpp2IL behavior and contracts.
- The current game build is the first live acceptance target; game-specific
  knowledge belongs in its profile or evidence, not generic core modules.
- Existing `Analysis` content is read-only. Every new dump, database, Ghidra
  project, trace, and report is written below `Analysis2` or another explicitly
  configured REToolkit workspace.
- Ghidra must not mutate an existing user-managed project. Persistent projects
  and worker replicas are owned by REToolkit under the configured workspace.
- Identical inputs and tool versions produce deterministic normalized outputs.
- Every external-tool result records command, versions, input hashes, duration,
  exit status, artifact hashes, and provenance.
- Every long operation supports progress reporting, bounded timeouts,
  checkpointing, and resume.
- The fast path must not start Ghidra when the index already contains enough
  evidence to answer a query.

## 3. Current-State Findings

The existing pipeline is linear:

```text
validate -> fixup -> cpp2il -> normalize -> frida? -> ghidra? -> evidence
```

Cpp2IL exports a method map and the normalizer preserves managed identity and
RVA. Frida and Ghidra are optional adapters, but their targets are supplied
manually through the profile. No persistent query index joins their outputs.

The current Ghidra adapter creates a fresh project, imports the binary, passes
`-noanalysis`, and runs `DecompileTargets.java`. The script opens one
`DecompInterface` and decompiles its arguments sequentially. This design incurs
JVM and import cost on every invocation and does not use additional cores for
the serial decompiler loop. Ghidra's `-max-cpu` option controls the maximum CPU
available to headless processing and auto-analysis; it does not make the
existing sequential `-noanalysis` script parallel by itself.

## 4. Selected Architecture: Hybrid Evidence Graph

The selected approach combines lightweight static analysis, persistent indexed
evidence, targeted/batched Ghidra, parallel Ghidra workers, GUI-assisted bulk
analysis, and multi-target Frida tracing.

```text
metadata / binary / Cpp2IL output
                |
                v
        RE Index + Query Engine
          /        |         \
         v         v          v
 fast native    Frida       Ghidra queue
   analysis     tracing    targeted/parallel/GUI
         \        |          /
          \       v         /
            Correlation Engine
                    |
                    v
         dossier / bulk report / evidence
```

The RE Index is the system of record. External tools are evidence producers,
not isolated terminal stages. Queries can schedule only the missing work and
reuse evidence whose cache key remains valid.

## 5. RE Index

Use SQLite from the Python standard library. Import the normalized method map
once instead of repeatedly parsing the approximately 70 MB JSON document.

The database is stored at:

```text
<workspace>/re-index/retoolkit.db
```

Required entities:

- `runs`: run identifiers, timestamps, profile and input hashes.
- `tools`: tool names, versions, executable/script hashes.
- `binaries`: SHA-256, image base, architecture, size and PE section layout.
- `methods`: assembly, type, method, signature, RVA, pointer and collision key.
- `targets`: normalized query, priority, requested depth and work state.
- `functions`: entry RVA, bounds, names, symbol sources and confidence.
- `edges`: caller, callee, xref/data-reference type and evidence source.
- `static_findings`: instructions, constants, strings and field-offset evidence.
- `runtime_events`: target, runtime address, thread, arguments, return,
  backtrace, timestamp and sample count.
- `decompilations`: backend, target, pseudocode, status, error and duration.
- `artifacts`: logical name, path, hash, producer and provenance.

The index supports exact managed identities, wildcard class/method filters,
namespace filters, RVA lookup, collision-preserving results, and reverse lookup
from runtime/native address to managed candidates.

## 6. Query and Target Dossier

The public workflow is query-driven:

```powershell
retoolkit target resolve PROFILE "Namespace.Type::Method"
retoolkit target search PROFILE --class BattleUnit --method Attack
retoolkit analyze PROFILE --query "BattleUnit::HandleAttackInternal" --depth balanced
retoolkit dossier PROFILE --target TARGET_ID
```

Analysis depths:

- `fast`: RE Index, PE mapping, strings, lightweight x86-64 disassembly and
  already-cached evidence.
- `balanced`: fast evidence plus targeted Ghidra or a bounded runtime trace.
- `deep`: multi-level callers/callees, Ghidra pseudocode, runtime backtraces,
  field observations, conflict analysis, and confidence synthesis.

A dossier contains managed identity, RVA/VA/file offset/runtime address,
function bounds, native instructions, constants, strings, callers/callees,
field-offset observations, decompiler output, runtime call counts and samples,
confidence, conflicts, and artifact provenance.

## 7. Fast Native Analysis

A lightweight static layer runs before Ghidra:

- Parse PE headers and section mappings.
- Convert RVA, virtual address, file offset, and ASLR-adjusted runtime address.
- Extract bounded native byte windows around method-map RVAs.
- Decode x86-64 instructions through an optional analysis dependency.
- Detect direct calls, conditional branches, RIP-relative references,
  immediates, common jump thunks, and referenced strings.
- Seed an initial call/reference graph with confidence labels.

This layer is optimized for bulk classification and target prioritization. It
does not pretend to replace Ghidra's decompiler or type propagation.

## 8. Ghidra Execution Modes

### 8.1 Ghidra 1: Targeted Headless

Use for a single dossier or approximately 1-256 uncached targets.

It must not launch one headless process per method. The adapter imports the
binary once into a persistent workspace-owned project keyed by binary SHA-256,
Ghidra version, loader configuration, and analysis profile. Subsequent work
uses `-process` on the existing program.

Targets are sent in batches, initially defaulting to 128. A batch script:

1. Reads a target manifest.
2. Seeds/disassembles missing target functions.
3. Applies the minimal selected analyzers to the required address sets.
4. Reuses one `DecompInterface` for the batch.
5. Writes one JSONL record immediately after each target.
6. Applies a per-function timeout and preserves completed records.

Cache identity includes binary SHA-256, target RVA, Ghidra version, script hash,
analyzer profile, and relevant method-map hash. A valid cache hit starts no JVM.

### 8.2 Ghidra 2: Parallel Headless Workers

Use for approximately 257-5000 targets or when explicitly requested.

REToolkit shards the target queue across isolated workers. Each worker receives
a workspace-owned replica of the prepared base project, processes batches in
one JVM invocation, writes an independent JSONL shard and checkpoint, and can
be retried without invalidating completed shards. Project replicas avoid local
project write-lock contention and keep a worker failure isolated.

`--workers auto` is selected from logical CPU count, available RAM, measured
per-worker memory, and configured limits. REToolkit benchmarks 1, 2, 4, and
additional worker counts only while throughput continues to improve. The
explicit `--workers N` setting always takes precedence.

`-max-cpu N` is used when auto-analysis is enabled inside a worker. Parallel
decompilation throughput comes from queue sharding and multiple isolated
workers, rather than assuming that `-max-cpu` parallelizes a serial
`DecompInterface` loop.

### 8.3 Ghidra 3: GUI Bulk Workflow

Use for full auto-analysis, more than approximately 5000 targets, interactive
type/function correction, or whenever measured GUI throughput is better than
parallel headless throughput.

REToolkit generates a self-contained bundle:

```text
<workspace>/ghidra-gui-bundle/
  target-manifest.json
  method-map.normalized.json
  analyzer-profile.json
  SeedIl2CppFunctions.java
  BulkAnalyzeTargets.java
  BulkDecompileTargets.java
  ExportRetoolkitResults.java
  progress.json
  README-GHIDRA-GUI.md
```

The Java scripts seed managed symbols, build target address sets, run the chosen
analyzers with GUI progress, decompile in resumable batches, and export function
bounds, symbols, xrefs, callers/callees, data references, pseudocode, errors,
and timing as versioned JSONL.

`docs/runbooks/ghidra-bulk-gui.md` provides numbered instructions for checking
Ghidra/JDK, preparing the bundle, opening the correct project/program, adding
the script directory, configuring memory and CPU workers, running each script,
checking counts, pausing/resuming, exporting, importing results into REToolkit,
troubleshooting, and cleaning up workspace-owned replicas.

### 8.4 Mode Selection

Initial automatic policy:

```text
valid cache hit                       -> index result, no Ghidra
1-256 uncached targets                -> targeted headless
257-5000 uncached targets             -> parallel headless
full analysis or >5000 targets        -> GUI bundle
explicit --mode                       -> requested mode
```

Thresholds are profile defaults refined by benchmark results; they are not
permanent core constants.

## 9. Bulk Recovery

Bulk recovery ingests Cpp2IL warnings/failures and user queries, then ranks work
by profile priority, caller count, referenced strings, native size, runtime hit
count, and unresolved evidence. It performs fast native classification first,
sends only targets that benefit from deeper analysis to Ghidra, and checkpoints
after every batch.

Required outputs:

```text
bulk-summary.json
recovered-methods.jsonl
failed-methods.jsonl
recovery-progress.json
```

Retries are classified by cause: missing function, decompiler timeout, project
failure, script failure, malformed target, or conflicting identity. Completed
work is never repeated unless a cache input changed or the user requests force.

## 10. Frida Runtime Analysis

One Frida session handles many selected targets. The resolver accepts exact
managed identity, RVA, or target ID and reports module base and ASLR-adjusted
runtime addresses. Trace recipes select arguments, return values, call counts,
threads, backtraces, sampling, rate limits, and whitelisted object fields.

Runtime JSONL is aggregated and imported into the RE Index. Backtrace addresses
are mapped to indexed methods. High-frequency methods are sampled and counted
without emitting unbounded event streams. Spawn and attach lifecycles retain
the existing cleanup guarantees.

## 11. Correlation and Confidence

Every conclusion retains all supporting and conflicting evidence. Confidence
is derived by explicit rules:

- One uncorroborated heuristic source: `candidate`.
- Method-map plus valid native entry mapping: `probable`.
- Static disassembly and Ghidra function agreement: `high`.
- Matching runtime hit at the relocated address: `confirmed`.
- Contradictory identity, address, or bounds: `conflict` until resolved.

Reports must distinguish observation from inference and list the artifacts that
support each result.

## 12. Pipeline and CLI Model

Replace the single all-or-nothing linear workflow with artifact-driven commands
that can still be orchestrated end to end:

```text
index build
target resolve/search
native scan
ghidra prepare/analyze/import
trace
correlate
dossier
bulk recover
```

`retoolkit analyze` schedules the missing commands according to depth and cache
state. Existing profile validation, workspace locking, atomic state, structured
errors, and evidence hashing remain shared infrastructure.

## 13. Error Handling and Resume

- Each work item has `pending`, `running`, `completed`, `failed`, or `stale` state.
- A dead worker's `running` items return to `pending` during resume.
- Per-target errors are records; infrastructure errors fail only the affected
  shard or stage.
- External process timeouts terminate the process tree and preserve flushed
  artifacts.
- Database updates use transactions; JSON/JSONL manifests use atomic replace.
- Cache invalidation names the changed input: binary, metadata, method map,
  profile, script, analyzer profile, or tool version.
- GUI imports reject mismatched binary/method-map hashes before changing the
  index.

## 14. Performance and Acceptance Gates

Record a baseline using the current fresh-import targeted adapter before the
new Ghidra implementation is enabled.

Required gates:

- An index-only query starts no external process.
- The same binary is imported once per valid project cache key.
- A 100-target targeted run with one worker launches one JVM.
- An identical cached query completes in under one second and launches no JVM.
- Warm targeted throughput is at least twice the current fresh-import
  throughput per target.
- Parallel tests at 1, 2, and 4 workers report methods/second, CPU utilization,
  peak memory, disk throughput, and scaling efficiency.
- A worker timeout preserves completed target records and resume processes only
  unfinished work.
- Frida resolves and traces multiple targets in one session and maps runtime
  hits back to indexed managed candidates.
- Target dossier fields cite evidence and confidence.
- Bulk recovery produces deterministic summaries and stable resume behavior.
- All game-derived outputs are located under `Analysis2` or the configured
  workspace; the existing `Analysis` tree remains byte-for-byte unchanged.

## 15. Testing Strategy

### Unit tests

- SQLite schema, migrations, import idempotency, query filters and collisions.
- PE/RVA/VA/file-offset/runtime-address conversion.
- Target ranking and work-queue transitions.
- Cache keys and invalidation.
- Ghidra batch/shard planning, worker count selection and merge determinism.
- Frida recipe generation, event aggregation and rate limiting.
- Correlation/confidence rules.

### Adapter tests

- Fake Ghidra CLI verifies one import, subsequent `-process`, batching,
  `-max-cpu` placement, per-target output and timeout preservation.
- Fake worker processes verify sharding and resume.
- Java script fixtures verify manifest parsing and JSONL output contracts.
- Fake Frida verifies multi-target attach/spawn and clean detach/kill.

### Integration tests

- Synthetic PE plus method map produces a complete fast dossier.
- Mocked end-to-end A/B/C workflow populates one index and deterministic report.
- GUI bundle round trip validates export/import hashes and schemas.

### Live gates

- Current game metadata and binary build the expected 206366-entry map.
- Targeted headless benchmark compares cold, warm, and cached runs.
- Parallel headless benchmark compares 1, 2, and 4 workers.
- GUI manual is executed once against a generated bundle and its export is
  imported successfully.
- Frida resolves selected targets and returns address/call evidence.

## 16. Delivery Decomposition

Implementation is split into four independently testable plans:

1. **RE Index and query engine.**
2. **Fast native analysis and the three Ghidra modes.**
3. **Multi-target Frida tracing and runtime correlation.**
4. **Target dossier and bulk recovery orchestration.**

Each plan uses test-first changes, preserves existing contracts, updates the
profile/schema/runbooks, records baseline and modified commands with literal
outputs and exit statuses, and provides a patch plus runnable rollback.
