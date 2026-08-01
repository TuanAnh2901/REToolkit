"""Atomic, hash-addressed bundle generation for the Ghidra GUI workflow."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, json, os, shutil
from pathlib import Path
from .manifests import target_manifest_document, write_target_manifest
from .models import TargetManifest

JAVA_FILES = ("SeedIl2CppFunctions.java", "BulkAnalyzeTargets.java", "BulkDecompileTargets.java", "ExportRetoolkitResults.java")
@dataclass(frozen=True)
class GuiBundle:
    root: Path
    def verify_hashes(self) -> list[str]:
        manifest = json.loads((self.root / "bundle-manifest.json").read_text(encoding="utf-8"))
        errors=[]
        for name, expected in manifest.get("files", {}).items():
            path=self.root/name
            if not path.is_file(): errors.append(f"missing {name}"); continue
            actual=hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected: errors.append(f"hash mismatch {name}")
        return errors

@dataclass(frozen=True)
class ImportSummary:
    imported: int
    skipped: int = 0

def _safe_output(path: Path) -> None:
    if any(part == "Analysis" for part in path.resolve().parts):
        raise ValueError("GUI bundle output cannot be inside Analysis")

def prepare_gui_bundle(profile, targets: TargetManifest, output: Path, *, method_map: Path | None = None, analyzer_profile: dict | None = None) -> GuiBundle:
    output=Path(output); _safe_output(output)
    parent=output.parent; parent.mkdir(parents=True, exist_ok=True)
    temp=parent/(output.name+f".tmp-{os.getpid()}")
    if temp.exists(): shutil.rmtree(temp)
    temp.mkdir()
    write_target_manifest(temp/"target-manifest.json", targets)
    if method_map and Path(method_map).is_file(): shutil.copy2(method_map, temp/"method-map.normalized.json")
    else: (temp/"method-map.normalized.json").write_text("{\"schema_version\":\"1.0.0\",\"method_count\":0,\"methods\":[]}\n", encoding="utf-8")
    (temp/"analyzer-profile.json").write_text(json.dumps(analyzer_profile or {"profile": getattr(profile, "name", str(profile))}, sort_keys=True)+"\n", encoding="utf-8")
    script_root=Path(__file__).resolve().parents[3]/"ghidra_scripts"
    for name in JAVA_FILES: shutil.copy2(script_root/name, temp/name)
    (temp/"progress.json").write_text(json.dumps({"schema_version":"1.0.0","completed":0,"total":len(targets.targets)}, sort_keys=True)+"\n", encoding="utf-8")
    (temp/"README-GHIDRA-GUI.md").write_text("Open the project, run BulkAnalyzeTargets, then BulkDecompileTargets and ExportRetoolkitResults.\n", encoding="utf-8")
    files={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in temp.iterdir() if p.name != "bundle-manifest.json"}
    (temp/"bundle-manifest.json").write_text(json.dumps({"schema_version":"1.0.0","files":files}, sort_keys=True)+"\n", encoding="utf-8")
    if output.exists(): shutil.rmtree(output)
    os.replace(temp, output)
    return GuiBundle(output)

def import_gui_bundle(bundle: GuiBundle, *, expected_binary_sha256: str | None = None) -> ImportSummary:
    errors=bundle.verify_hashes()
    if errors: raise ValueError("bundle verification failed: "+"; ".join(errors))
    manifest=json.loads((bundle.root/"target-manifest.json").read_text(encoding="utf-8"))
    if expected_binary_sha256 and manifest.get("binary_sha256") != expected_binary_sha256: raise ValueError("binary hash mismatch")
    export=bundle.root/"results.jsonl"
    return ImportSummary(sum(1 for _ in export.open(encoding="utf-8")) if export.exists() else 0)
