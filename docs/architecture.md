# Architecture

## Package layout (Cpp2IL-inspired boundaries)

Cpp2IL separates CLI / Core / Lib / plugins / tests; retoolkit mirrors that
conceptually in Python:

```
src/retoolkit/
  cli.py               CLI entry: one JSON document on stdout, exit-code contract
  contracts/           versioned JSON contracts (result, schema, profile)
  core/                safety infrastructure (evidence, state, capabilities, pipeline)
  adapters/            external-tool process control (cpp2il, ghidra, frida)
  runtime/             resolver.js (shared Frida IL2CPP resolver, ES5)
  metadata/            binary primitives (xxtea, scanner, mfuscator fixup)
  normalizers/         artifact normalization (method_map)
schemas/               JSON Schemas for every canonical contract
profiles/              game reference profiles (everlusting, examples)
ghidra_scripts/        DecompileTargets.java (derived, attributed)
tests/                 pytest + Node test runner + fakes + fixtures
scripts/               probe scripts + acceptance runner
research/              probed external-tool contracts
docs/                  architecture, profile authoring, runbooks
```

## Contracts (all carry `schema_version`)

| Schema | Owner | Purpose |
|---|---|---|
| `result` (in code) | CLI | every command's stdout document + exit codes 0/1/2/3/4/5/130 |
| `profile.schema.json` | contracts/profile.py | portable game/tool description; strict unknown-field rejection |
| `capability.schema.json` | core/capabilities.py | doctor report |
| `evidence.schema.json` | core/evidence.py | append-only per-run artifact manifest (SHA-256) |
| `state.schema.json` | core/state.py | linear pipeline state; atomic writes; resume/invalidation |
| `metadata_fixup.schema.json` | metadata/mfuscator.py | profile-driven obfuscation rebuild rules |
| `method_map.schema.json` | normalizers/method_map.py | canonical normalized method map |

Canonical core JSON is byte-deterministic and excludes timestamps/absolute
paths; evidence manifests may include provenance and resolved paths.

## Safety invariants

- `shell=False` argument arrays everywhere; spaced paths tested.
- Atomic writes (temp file + `os.replace`) for state and evidence.
- Per-workspace O_EXCL lock; stale lock from a dead PID is stolen.
- Timeouts kill the whole process tree (`taskkill /T /F`), verified no-orphan.
- Game inputs read-only; writes only under the workspace.
- `shell=True`, non-JSON stdout, and raw tracebacks never reach CLI results.

## Linear vs parallel

Implementation happens in parallel waves, but the **runtime pipeline is
strictly linear and sequential** (no DAG executor). Resume is the only
"skip" mechanism, and only for completed stages whose input hash matches.

## Adapter contracts

- **Cpp2IL** (`adapters/cpp2il.py`): probed contract in
  `research/cpp2il-contract.md`. The shipped trimmed build crashes on
  `--export-method-map` (reflection serialization disabled); the adapter
  detects the signature and points at the documented non-trimmed build fix.
  Plugin auto-load requires cwd = parent of a `Plugins/` dir containing
  `Cpp2IL.Plugin.Mfuscator.dll`.
- **Ghidra** (`adapters/ghidra.py`): headless `analyzeHeadless` with explicit
  RVA targets (address = `image_base` + RVA); never mutates existing user
  projects; missing install -> exit 2, timeout -> exit 3.
- **Frida** (`adapters/frida.py`): composes `runtime/resolver.js` with
  read-only trace scripts; ambiguous process selection -> exit 1 with
  candidates; resolve-only (no hooks, no memory writes).

## Excluded scope (v1)

No runtime DAG/parallel executor, no database, no generic plugin framework,
no MelonLoader/mod generation, no bundled third-party binaries, no
anti-cheat/server bypass, no cross-platform abstraction layer. Manual Ghidra
GUI / x64dbg workflows are documented, not automated.
