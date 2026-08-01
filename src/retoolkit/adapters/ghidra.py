"""Targeted Ghidra headless adapter: import a binary copy, decompile explicit
RVAs via DecompileTargets.java, capture and normalize the console output.

Contract source: research/ghidra-contract.md. The adapter never mutates an
existing user Ghidra project; it always creates a fresh project under the
toolkit workspace.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.core.proc import kill_process_tree

HEADLESS_REL = "support/analyzeHeadless.bat"
SCRIPT_NAME = "DecompileTargets.java"
LOG_FILE = "analyzeHeadless.log"

_TARGET_RE = re.compile(r"TARGET\s+(.+)")
_FUNCTION_RE = re.compile(r"FUNCTION\s+(.+?)\s+@\s+(.+)")
_NOT_FOUND_RE = re.compile(r"FUNCTION_NOT_FOUND")
_FAILED_RE = re.compile(r"DECOMPILATION_FAILED\s+(.+)")


@dataclass
class DecompileArtifact:
    address: str
    status: str  # "decompiled" | "not_found" | "failed"
    function: str | None = None
    path: Path | None = None
    sha256: str | None = None


@dataclass
class GhidraResult:
    artifacts: list[DecompileArtifact] = field(default_factory=list)
    log_path: Path | None = None
    duration_seconds: float = 0.0


class GhidraAdapter:
    def __init__(
        self,
        root: Path,
        *,
        scripts_dir: Path,
        timeout_seconds: int = 900,
        image_base: int = 0x180000000,
    ) -> None:
        self.root = root
        self.headless = root / HEADLESS_REL
        self.scripts_dir = scripts_dir
        self.timeout_seconds = timeout_seconds
        self.image_base = image_base
        if not self.headless.is_file():
            raise ResultError.missing_capability(
                f"Ghidra analyzeHeadless not found at {self.headless}; install Ghidra "
                "and point tools.ghidra.path at the extracted root "
                "(see research/ghidra-contract.md)"
            )
        if not (scripts_dir / SCRIPT_NAME).is_file():
            raise ResultError.validation(f"missing script {SCRIPT_NAME} in {scripts_dir}")

    def decompile_rvas(
        self,
        *,
        binary: Path,
        project_dir: Path,
        project_name: str,
        rvas: list[int],
        output_dir: Path,
    ) -> GhidraResult:
        if not binary.is_file():
            raise ResultError.validation(f"binary not found: {binary}")
        if not rvas:
            raise ResultError.validation("no RVAs requested")
        # Never reuse an existing project as a write target: fresh import only.
        project_path = project_dir / f"{project_name}.rep"
        if project_path.exists():
            raise ResultError.validation(
                f"Ghidra project already exists at {project_path}; the adapter only "
                "creates fresh workspace projects. Copy the binary into a new project "
                "name instead of mutating existing analysis."
            )
        project_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / LOG_FILE
        addresses = [format(self.image_base + rva, "x") for rva in rvas]
        argv = [
            str(self.headless),
            str(project_dir),
            project_name,
            "-import",
            str(binary),
            "-noanalysis",
            "-scriptPath",
            str(self.scripts_dir),
            "-postScript",
            SCRIPT_NAME,
            *addresses,
            "-scriptlog",
            str(log_path),
        ]
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout_seconds, cwd=str(output_dir)
            )
        except subprocess.TimeoutExpired as exc:
            if exc.pid is not None:
                kill_process_tree(exc.pid)
            raise ResultError.timeout(
                f"Ghidra headless exceeded {self.timeout_seconds}s timeout; Java process tree killed",
                details={"log": str(log_path)},
            ) from None
        duration = round(time.monotonic() - started, 3)
        if proc.returncode != 0:
            raise ResultError.validation(
                f"analyzeHeadless exited {proc.returncode}",
                details={"log": str(log_path)},
            )
        artifacts = self._normalize(log_path, addresses, output_dir)
        return GhidraResult(artifacts=artifacts, log_path=log_path, duration_seconds=duration)

    def _normalize(
        self, log_path: Path, addresses: list[str], output_dir: Path
    ) -> list[DecompileArtifact]:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        artifacts: list[DecompileArtifact] = []
        current: DecompileArtifact | None = None
        body: list[str] = []
        for line in lines:
            match = _TARGET_RE.search(line)
            if match:
                if current is not None:
                    artifacts.append(self._finish(current, body, output_dir))
                current = DecompileArtifact(address=match.group(1).strip(), status="decompiled")
                body = []
                continue
            if current is None:
                continue
            if _NOT_FOUND_RE.search(line):
                current.status = "not_found"
                body = []
                continue
            failed = _FAILED_RE.search(line)
            if failed:
                current.status = "failed"
                body = [failed.group(1)]
                continue
            function = _FUNCTION_RE.search(line)
            if function:
                current.function = function.group(1)
                continue
            body.append(line)
        if current is not None:
            artifacts.append(self._finish(current, body, output_dir))
        missing = {addr for addr in addresses} - {a.address for a in artifacts}
        for addr in sorted(missing):
            artifacts.append(DecompileArtifact(address=addr, status="missing_from_log"))
        return artifacts

    @staticmethod
    def _finish(artifact: DecompileArtifact, body: list[str], output_dir: Path) -> DecompileArtifact:
        if artifact.status == "decompiled":
            content = "\n".join(body).strip() + "\n"
            path = output_dir / f"decompile-{artifact.address}.txt"
            path.write_text(content, encoding="utf-8")
            artifact.path = path
            artifact.sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return artifact
