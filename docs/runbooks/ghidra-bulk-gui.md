# REToolkit Ghidra GUI bulk workflow

## Prerequisites

Ghidra 12.1.x, a supported JDK, a validated profile, and a workspace with an
`Analysis2` directory are required. Run `retoolkit doctor` before opening GUI.

1. Install Ghidra 12.1.x and a supported JDK; run `retoolkit doctor` and confirm the headless path.
2. Build the index with the command shown in the verification block below; record the method count.
3. Prepare GUI output only under `Analysis2`: `retoolkit ghidra prepare-gui profiles/everlusting/profile.json --query 'N.T::*' --output "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle"`.
4. Verify hashes with `retoolkit ghidra import-gui profiles/everlusting/profile.json --bundle "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle" --verify-only`.
5. Launch Ghidra and open the generated workspace-owned project.
6. Confirm the GameAssembly SHA-256 and image base in the generated target manifest.
7. Open **Window → Script Manager**.
8. Add the bundle directory under **Script Directories**.
9. Refresh and locate the four REToolkit Java scripts.
10. Run SeedIl2CppFunctions.java and select the generated target manifest.
11. Compare seeded, skipped, and failed counts with the manifest.
12. Open Auto Analyze settings and choose the generated analyzer profile.
13. Set GUI worker threads conservatively; each worker consumes RAM and CPU.
14. Run BulkAnalyzeTargets.java; watch the progress JSON file.
15. Cancel with the monitor and confirm the progress JSON remains valid.
16. Re-run the analyzer script with resume enabled; completed target IDs are skipped.
17. Run BulkDecompileTargets.java.
18. Inspect a sample target and pseudocode in CodeBrowser.
19. Run ExportRetoolkitResults.java.
20. Verify export hashes and record counts against the manifest.
21. Close the program and project cleanly to release the lock.
22. Import with `retoolkit ghidra import-gui profiles/everlusting/profile.json --bundle "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle"`.
23. Run a target query and confirm imported records are available.
24. For locks, script compile, heap, image-base, timeout, missing-function, malformed-export, or stale-hash errors, inspect the progress file, bundle-manifest hashes, and Ghidra logs before retrying.
25. Remove only the Analysis2 bundle after export; rollback never targets Analysis.

## Verification

```powershell
$workspace = "<workspace>"
if (-not (Test-Path (Join-Path $workspace "Analysis2"))) { throw "Analysis2 missing" }
Write-Output "GUI bundle root verified: $workspace\Analysis2"
```

## Stop conditions

Stop before importing when a hash differs, a project lock is held, a progress
file is malformed, or a Java script reports a target-count mismatch. Preserve
the bundle and logs for diagnosis; do not delete or write the protected
Analysis directory.

Expected live gates are opt-in. Without `RETOOLKIT_LIVE_GHIDRA=1` and a valid tool path, the live test skips rather than claiming a pass.
