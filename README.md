# retoolkit

Reusable Windows-first Unity IL2CPP reverse-engineering toolkit. Orchestrates
Cpp2IL, Frida, and targeted Ghidra workflows through versioned JSON contracts,
a resumable linear pipeline, and append-only SHA-256 evidence.

Built for autonomous AI-agent CLI execution: every command emits exactly one
JSON document on stdout; diagnostics go to stderr.

## Install

```powershell
py -3.13 -m pip install -e ".[dev]"
```

Requires Python 3.13 (`py -3.13`); older interpreters are rejected with a
clear message.

## Quickstart (non-live)

```powershell
py -3.13 -m retoolkit --version
py -3.13 -m retoolkit doctor --json          # probe python/frida/node/dotnet/cpp2il/ghidra/x64dbg
py -3.13 -m retoolkit profile validate profiles/everlusting/profile.json --fixture --json
py -3.13 -m retoolkit pipeline plan profiles/everlusting/profile.json --json
```

All stdout parses as JSON. Exit codes: `0` ok, `1` validation, `2` missing
capability, `3` timeout, `4` lock conflict, `5` internal, `130` interrupted.

## Pipeline

```
validate -> fixup -> cpp2il -> normalize -> frida? -> ghidra? -> evidence
```

Sequential and resumable. Completed stages are skipped on resume only when
their input hashes still match; changed inputs/tools make the state stale and
require `--restart`.

```powershell
py -3.13 -m retoolkit pipeline run     profiles/everlusting/profile.json
py -3.13 -m retoolkit pipeline resume  profiles/everlusting/profile.json
py -3.13 -m retoolkit pipeline restart profiles/everlusting/profile.json
```

Game inputs are read-only; all transformed copies and outputs land under the
profile's workspace.

## Live gates

Real tool/game runs are opt-in and never part of the default suite:

| Gate | Enables |
|---|---|
| `RETOOLKIT_LIVE_CPP2IL=1` | real Cpp2IL method-map export against the game |
| `RETOOLKIT_LIVE_FRIDA=1` | spawn the game and run a resolve-only trace |
| `RETOOLKIT_LIVE_GHIDRA=1` | targeted headless decompile (needs installed Ghidra) |

## Reference profile

`profiles/everlusting/` is the first reference profile (Everlusting Life,
Unity 6000.1.4f1, Mfuscator-obfuscated metadata). Paths resolve from
environment variables; see `profiles/everlusting/README.md`.

## Manual fallbacks

- `docs/runbooks/ghidra-gui.md` — interactive decompile/xrefs/types
- `docs/runbooks/x64dbg.md` — breakpoint/memory/register capture (doc-only in v1)

## Docs

- `docs/architecture.md` — package map, contracts, safety invariants
- `docs/profile-authoring.md` — adding a new game / metadata fixup
- `docs/resolver-api.md` — the shared IL2CPP Frida resolver
- `research/cpp2il-contract.md` — probed Cpp2IL CLI behavior (incl. the
  non-trimmed-build requirement for `--export-method-map`)

## Tests

```powershell
py -3.13 -m pytest -q          # all non-live tests
node --test tests/js/*.test.mjs # Frida resolver (Node shim)
powershell -File scripts/run_acceptance.ps1
```
