# REToolkit Ghidra GUI bulk workflow

1. Install Ghidra 12.1.x and a supported JDK; run `retoolkit doctor` and confirm the headless path.
2. Build the index: `retoolkit index build profiles/everlusting/profile.json`; record the method count.
3. Prepare GUI output only under `Analysis2`: `retoolkit ghidra prepare-gui profiles/everlusting/profile.json --query 'N.T::*' --output "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle"`.
4. Verify hashes with `retoolkit ghidra import-gui profiles/everlusting/profile.json --bundle "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle" --verify-only`.
5. Launch Ghidra and open the generated workspace-owned project.
6. Confirm `GameAssembly.dll` SHA-256 and the image base in `target-manifest.json`.
7. Open **Window → Script Manager**.
8. Add the bundle directory under **Script Directories**.
9. Refresh and locate the four REToolkit Java scripts.
10. Run `SeedIl2CppFunctions.java` and select `target-manifest.json`.
11. Compare seeded, skipped, and failed counts with the manifest.
12. Open Auto Analyze settings and choose the generated analyzer profile.
13. Set GUI worker threads conservatively; each worker consumes RAM and CPU.
14. Run `BulkAnalyzeTargets.java`; watch `progress.json`.
15. Cancel with the monitor and confirm `progress.json` remains valid JSON.
16. Re-run the analyzer script with resume enabled; completed target IDs are skipped.
17. Run `BulkDecompileTargets.java`.
18. Inspect a sample target and pseudocode in CodeBrowser.
19. Run `ExportRetoolkitResults.java`.
20. Verify export hashes and record counts against the manifest.
21. Close the program and project cleanly to release the lock.
22. Import with `retoolkit ghidra import-gui profiles/everlusting/profile.json --bundle "$env:RETOOLKIT_WORKSPACE/Analysis2/ghidra-bundle"`.
23. Run a target query and confirm imported records are available.
24. For locks, script compile, heap, image-base, timeout, missing-function, malformed-export, or stale-hash errors, inspect `progress.json`, bundle-manifest hashes, and Ghidra logs before retrying.
25. Remove only the `Analysis2` bundle after export; rollback never targets `Analysis`.

Expected live gates are opt-in. Without `RETOOLKIT_LIVE_GHIDRA=1` and a valid tool path, the live test skips rather than claiming a pass.
