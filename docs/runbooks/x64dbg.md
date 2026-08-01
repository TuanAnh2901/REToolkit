# x64dbg runbook (manual fallback, documentation-only in v1)

Use x64dbg when you need live breakpoints, memory dumps, or register state of
a running process — things Frida/Ghidra don't expose cleanly. v1 documents
the workflow only; the toolkit never launches x64dbg.

## Prerequisites

- x64dbg installed and on PATH (or configured); verified by
  `py -3.13 -m retoolkit doctor` reporting `x64dbg present`. If missing,
  **stop here** — the toolkit remains fully usable without it.
- A working understanding of the method map: target RVAs from
  `method-map.normalized.json`.

## Address convention

x64dbg uses module-relative offsets for GameAssembly.dll. A method RVA
`0x434A60` is entered directly as `GameAssembly.dll+0x434A60`.

## Workflow: breakpoint + register capture

1. Launch the game; in x64dbg `File -> Attach` and pick the game process.
2. `View -> Symbols` (Alt+E) -> `GameAssembly.dll` -> `Ctrl+G` and enter
   `GameAssembly.dll+0x434A60`.
3. `F2` to set the breakpoint; trigger the code path in-game.
4. On break: `View -> Registers` (Alt+R) records register state.
5. Memory: `View -> Memory Map` (Alt+M), select the region, `Ctrl+E` dump to
   the workspace.

### Export into workspace

- Register/memory dumps: `File -> Take Log`, save to
  `<workspace>/x64dbg/capture-<timestamp>.txt`.

### Stop conditions

- Stop after the breakpoint fires once and registers are captured; do not
  step through anti-cheat or server-authentication code paths.

### Artifact verification

```powershell
py -3.13 -c "import pathlib,sys; p=pathlib.Path(r'<workspace>\x64dbg'); files=list(p.glob('*.txt')) if p.is_dir() else []; sys.exit(0 if files and all(f.stat().st_size>0 for f in files) else 1)"
```

Exit 0 means at least one non-empty capture exists in the workspace.

## Not covered by v1

The toolkit does not automate x64dbg, does not hook anti-cheat, and does not
patch game memory. This runbook is operator guidance only.
