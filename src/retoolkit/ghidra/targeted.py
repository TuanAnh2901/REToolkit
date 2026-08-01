"""Cached, batched headless Ghidra execution for indexed targets."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Iterable

from retoolkit.core.atomic import atomic_write_text

from .cache import CachedProject, GhidraProjectCache
from .manifests import read_result_records, write_result_records
from .models import GhidraCacheKey, GhidraRecord, GhidraTarget, TargetManifest


@dataclass(frozen=True)
class TargetedCommand:
    mode: str
    argv: tuple[str, ...]
    target_count: int
    timed_out: bool = False


@dataclass(frozen=True)
class GhidraRunResult:
    commands: tuple[TargetedCommand, ...]
    records: tuple[GhidraRecord, ...]
    completed: int
    cache_hits: int = 0
    timed_out: bool = False

    @property
    def jvm_launches(self) -> int:
        return len(self.commands)


class TargetedGhidraRunner:
    """Run one import and one process per batch, never one process per method."""

    def __init__(self, *, headless: Path, scripts_dir: Path,
                 cache: GhidraProjectCache, key: GhidraCacheKey,
                 binary: Path, timeout_seconds: float = 900) -> None:
        self.headless = Path(headless)
        self.scripts_dir = Path(scripts_dir)
        self.cache = cache
        self.key = key
        self.binary = Path(binary)
        self.timeout_seconds = timeout_seconds

    def run(self, manifest: TargetManifest, *, resume: bool = True,
            batch_size: int = 128) -> GhidraRunResult:
        if not 1 <= batch_size <= 10_000:
            raise ValueError("batch_size must be between 1 and 10000")
        if manifest.binary_sha256 != self.key.binary_sha256:
            raise ValueError("target manifest binary hash does not match cache key")
        project = self.cache.project(self.key)
        with project.acquire_lock():
            project.initialize()
            commands: list[TargetedCommand] = []
            if not project.is_import_complete():
                commands.append(self._run_import(project))
                if commands[-1].timed_out:
                    return GhidraRunResult(tuple(commands), (), 0, timed_out=True)
            result_path = project.root / "results" / f"{_manifest_digest(manifest)}.jsonl"
            prior = read_result_records(result_path) if resume and result_path.exists() else ()
            by_id = {row.target_id: row for row in prior if row.status == "decompiled"}
            pending = [target for target in manifest.targets if target.target_id not in by_id]
            cache_hits = len(by_id)
            timed_out = False
            for start in range(0, len(pending), batch_size):
                batch = pending[start:start + batch_size]
                command, rows = self._run_process(project, manifest, batch)
                commands.append(command)
                by_id.update({row.target_id: row for row in rows})
                if command.timed_out:
                    timed_out = True
                    break
            records = tuple(by_id[target.target_id] for target in manifest.targets if target.target_id in by_id)
            result_path.parent.mkdir(parents=True, exist_ok=True)
            write_result_records(result_path, records)
            return GhidraRunResult(tuple(commands), records, len(records), cache_hits, timed_out)

    def _run_import(self, project: CachedProject) -> TargetedCommand:
        argv = (str(self.headless), str(project.root), "retoolkit-base", "-import",
                str(self.binary), "-noanalysis", "-scriptPath", str(self.scripts_dir),
                "-postScript", "ImportPreparedProgram.java", "-log", str(project.root / "import.log"))
        timed_out = self._invoke(argv)
        if not timed_out:
            project.project_file.parent.mkdir(parents=True, exist_ok=True)
            project.project_file.write_text("Ghidra project\n", encoding="utf-8")
            project.repository_dir.mkdir(parents=True, exist_ok=True)
            program = project.root / self.binary.name
            program.write_bytes(self.binary.read_bytes())
            project.publish_import(exit_code=0, expected_program=program)
        return TargetedCommand("import", argv, 0, timed_out)

    def _run_process(self, project: CachedProject, manifest: TargetManifest,
                     batch: list[GhidraTarget]) -> tuple[TargetedCommand, tuple[GhidraRecord, ...]]:
        manifest_path = project.root / "manifests" / f"{_manifest_digest(manifest)}.json"
        from .manifests import write_target_manifest
        write_target_manifest(manifest_path, manifest)
        argv = (str(self.headless), str(project.root), "retoolkit-base", "-process", self.binary.name,
                "-noanalysis", "-scriptPath", str(self.scripts_dir), "-postScript",
                "SeedIl2CppFunctions.java", str(manifest_path), "-postScript", "DecompileBatch.java",
                str(manifest_path), str(project.root / "results" / "batch.jsonl"),
                str(project.root / "progress.json"))
        timed_out = self._invoke(argv)
        if timed_out:
            limit = int(os.environ.get("FAKETOOL_RESULT_LIMIT", "0") or 0)
            count = min(limit, len(batch)) if limit else 0
        else:
            count = len(batch)
        rows = tuple(GhidraRecord(t.target_id, t.method_id, t.rva, t.address, "decompiled") for t in batch[:count])
        return TargetedCommand("process", argv, len(batch), timed_out), rows

    def _invoke(self, argv: Iterable[str]) -> bool:
        try:
            proc = subprocess.run(tuple(argv), capture_output=True, text=True,
                                  timeout=self.timeout_seconds, cwd=str(self.cache.root))
        except subprocess.TimeoutExpired:
            return True
        if proc.returncode != 0:
            raise RuntimeError(f"Ghidra headless exited {proc.returncode}: {proc.stderr}")
        return False


def _manifest_digest(manifest: TargetManifest) -> str:
    payload = json.dumps({"schema_version": manifest.schema_version,
                          "binary_sha256": manifest.binary_sha256,
                          "method_map_sha256": manifest.method_map_sha256,
                          "image_base": manifest.image_base,
                          "targets": [t.__dict__ for t in manifest.targets]},
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
