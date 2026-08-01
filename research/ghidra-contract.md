# Ghidra Headless Contract (probed 2026-07-31)

## Status: MISSING CAPABILITY (not installed)

Ghidra is available only as an archive on this machine:

- `D:\Tools\ghidra_12.1.2_PUBLIC_20260605.zip`

It has **not** been extracted/installed. The toolkit therefore records a
deterministic `missing` capability and never attempts to run `analyzeHeadless`
until the operator installs it.

## Install Prerequisites (documented for the operator / live gate)

1. Extract the archive, e.g. to `D:\Tools\ghidra_12.1.2_PUBLIC` (requires
   Java 21+ runtime; Ghidra 12 ships with a bundled JBR).
2. Verify the archive SHA-256 before extraction (record the hash in evidence).
3. Point the profile at it: `tools.ghidra.path` = extracted root, or set
   `RETOOLKIT_GHIDRA` so the capability probe finds
   `<root>\support\analyzeHeadless.bat`.

## Expected headless contract (from the generic script pattern, deferred to live gate)

```
analyzeHeadless.bat <project_dir> <project_name> -import <binary>
  -scriptPath <toolkit>\ghidra_scripts
  -postScript DecompileTargets.java <rva> <output.txt>
  -deleteProject
```

- Targets explicit RVAs only; never full-analysis by default.
- Output: one text file per requested RVA, exported into the toolkit
  workspace and hashed into evidence.
- Existing user Ghidra projects are read-only inputs; the adapter copies into
  the workspace before any write-capable run.

## Probe Contract

`scripts/probe_ghidra.py` emits one JSON document:

- `classification`: `missing` | `ok` | `incompatible`
- `root` / `headless_path` (when present)
- `version` (when present)
- `install_guidance` for the missing case
