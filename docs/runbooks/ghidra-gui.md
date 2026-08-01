# Ghidra GUI runbook (manual fallback)

Use the GUI when interactive xref browsing, type recovery, or structural
editing is materially faster than headless scripted analysis. Everything the
GUI produces is exported into the toolkit workspace and verified by a command.

## Prerequisites

- Ghidra installed (e.g. `D:\Tools\ghidra_12.1.2_PUBLIC`); verified by
  `py -3.13 -m retoolkit doctor` reporting `ghidra present`.
- A read-only **copy** of `GameAssembly.dll` in the toolkit workspace
  (never analyze the installed game file).

## Address convention

All analysis addresses are full virtual addresses = `0x180000000` + RVA.
Example: method RVA `0x434A60` (from `method-map.normalized.json`) becomes
address `0x180434a60`. RVAs come from the Cpp2IL method map, never from
managed-DLL comments.

## Workflow: targeted decompile + xrefs

1. `File -> New Project` in the toolkit workspace; project name `retoolkit-gui`.
2. `File -> Import File` -> the workspace copy of `GameAssembly.dll`; keep the
   default image base `0x180000000`.
3. Analyze (default auto-analysis is fine for targeted work).
4. `Navigate -> Go To` address `0x180434a60` (or your target from the map).
5. Double-click the function; `Window -> Decompiler` shows pseudo-C.
6. Right-click an interesting call/reference -> `References -> Find references to`
   to trace callers.
7. Apply names/types: right-click -> `Edit Label` / `Set Data Type`.

### Export into workspace

- `File -> Export Program` -> format *C/C++* or *Text* -> save to
  `<workspace>/ghidra-gui/decompile-0x180434a60.c`.

### Stop conditions

- Stop when the targeted function's behavior is understood or you have spent
  30 minutes without progress; export what you have and note the open question
  in the evidence file.

### Artifact verification

```powershell
py -3.13 -c "import pathlib,sys; p=pathlib.Path(r'<workspace>\ghidra-gui\decompile-0x180434a60.c'); sys.exit(0 if p.is_file() and p.stat().st_size > 100 else 1)"
```

Exit 0 means the exported artifact is present and non-trivial.

## Workflow: triage a new RVA list

1. From `method-map.normalized.json` pick target RVAs.
2. Convert to addresses (add `0x180000000`), then repeat the import/analyze
   steps above or use `ghidra_scripts/DecompileTargets.java` headless
   (see `docs/architecture.md`) for the batch path.
