"""Cpp2IL CLI adapter: safe argv, plugin validation, timeout with process-tree
cleanup, raw log capture, and normalized results.

Contract source: research/cpp2il-contract.md (probed). The adapter never
writes into the game directory; all outputs land under the toolkit workspace.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.core.proc import kill_process_tree

CRASH_EXIT = -532462766  # 0xE0434352 unhandled .NET exception (signed)
CRASH_EXIT_UNSIGNED = CRASH_EXIT & 0xFFFFFFFF
CRASH_SIGNATURE = "Reflection-based serialization has been disabled"
PLUGIN_DLL = "Cpp2IL.Plugin.Mfuscator.dll"
DEFAULT_UNITY_VERSION = "6000.1.4f1"


@dataclass
class Cpp2IlResult:
    exit_code: int
    method_count: int | None
    map_path: Path | None
    log_path: Path
    duration_seconds: float


class Cpp2IlAdapter:
    def __init__(
        self,
        exe: Path,
        *,
        plugin_dir: Path | None = None,
        timeout_seconds: int = 600,
        unity_version: str = DEFAULT_UNITY_VERSION,
    ) -> None:
        self.exe = exe
        self.plugin_dir = plugin_dir
        self.timeout_seconds = timeout_seconds
        self.unity_version = unity_version
        if not exe.is_file():
            raise ResultError.missing_capability(
                f"Cpp2IL executable not found: {exe}"
            )
        if plugin_dir is not None:
            if not (plugin_dir / PLUGIN_DLL).is_file():
                raise ResultError.validation(
                    f"Cpp2IL plugin directory lacks {PLUGIN_DLL}: {plugin_dir}"
                )

    def export_method_map(self, game_assembly: Path, metadata: Path, output_dir: Path) -> Cpp2IlResult:
        for label, path in (("game assembly", game_assembly), ("metadata", metadata)):
            if not path.is_file():
                raise ResultError.validation(f"{label} not found: {path}")

        output_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            str(self.exe),
            "--force-binary-path",
            str(game_assembly),
            "--force-metadata-path",
            str(metadata),
            "--force-unity-version",
            self.unity_version,
            "--export-method-map",
            "--output-to",
            str(output_dir),
        ]
        log_path = output_dir / "cpp2il.log"
        with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
            proc = subprocess.Popen(
                argv,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                cwd=str(self.plugin_dir.parent) if self.plugin_dir else None,
            )
            started = time.monotonic()
            try:
                proc.communicate(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                kill_process_tree(proc.pid)
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise ResultError.timeout(
                    f"Cpp2IL exceeded {self.timeout_seconds}s timeout; process tree killed",
                    details={"log": str(log_path)},
                ) from None
            duration = round(time.monotonic() - started, 3)

        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if proc.returncode in (CRASH_EXIT, CRASH_EXIT_UNSIGNED) and CRASH_SIGNATURE in log_text:
            raise ResultError.validation(
                "Cpp2IL --export-method-map crashed: reflection-based JSON serialization is "
                "disabled in this build. Use a non-trimmed local build with "
                "System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault=true in its "
                "runtimeconfig (see research/cpp2il-contract.md).",
                details={"exit_code": proc.returncode, "log": str(log_path)},
            )
        if proc.returncode != 0:
            raise ResultError.validation(
                f"Cpp2IL exited {proc.returncode} during method-map export",
                details={"log": str(log_path)},
            )

        map_path = output_dir / "method-pointer-map.json"
        if not map_path.is_file():
            raise ResultError.validation(
                f"Cpp2IL exited 0 but produced no {map_path.name}",
                details={"log": str(log_path)},
            )
        try:
            with map_path.open(encoding="utf-8") as handle:
                method_count = len(json.load(handle))
        except (ValueError, OSError) as exc:
            raise ResultError.validation(
                f"Cpp2IL produced malformed {map_path.name}: {exc}",
                details={"log": str(log_path)},
            ) from None
        return Cpp2IlResult(
            exit_code=0,
            method_count=method_count,
            map_path=map_path,
            log_path=log_path,
            duration_seconds=duration,
        )
