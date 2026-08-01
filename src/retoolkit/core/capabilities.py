"""Capability discovery: probe local tools and report present/missing with
versions and paths. Tools needing explicit configuration (Cpp2IL, Ghidra,
x64dbg) are never inferred from PATH alone."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate

SCHEMA = "capability.schema.json"
SCHEMA_VERSION = "1.0.0"


@dataclass
class Capability:
    name: str
    status: str
    version: str | None = None
    path: str | None = None


def _run_version(argv: list[str], timeout: int = 30) -> str | None:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def probe_python() -> Capability:
    return Capability(
        name="python",
        status="present",
        version=platform.python_version(),
        path=sys.executable,
    )


def probe_frida() -> Capability:
    try:
        import frida

        return Capability(name="frida", status="present", version=getattr(frida, "__version__", "unknown"))
    except ImportError:
        return Capability(name="frida", status="missing")


def probe_node() -> Capability:
    path = shutil.which("node")
    if not path:
        return Capability(name="node", status="missing")
    version = _run_version([path, "--version"])
    return Capability(
        name="node",
        status="present",
        version=version.lstrip("v") if version else None,
        path=path,
    )


def probe_dotnet() -> Capability:
    path = shutil.which("dotnet")
    if not path:
        return Capability(name="dotnet", status="missing")
    version = _run_version([path, "--version"])
    return Capability(name="dotnet", status="present", version=version, path=path)


def probe_cpp2il(exe_path: str | Path | None) -> Capability:
    if exe_path is None:
        return Capability(name="cpp2il", status="missing")
    exe = Path(exe_path)
    if not exe.is_file():
        return Capability(name="cpp2il", status="missing", path=str(exe))
    version = _run_version([str(exe), "--version"])
    match = re.search(r"Version\s+([^\s]+)", version or "")
    return Capability(
        name="cpp2il",
        status="present",
        version=match.group(1) if match else None,
        path=str(exe),
    )


def probe_ghidra(root: str | Path | None) -> Capability:
    if root is None:
        return Capability(name="ghidra", status="optional_missing")
    headless = Path(root) / "support" / "analyzeHeadless.bat"
    if not headless.is_file():
        return Capability(name="ghidra", status="optional_missing", path=str(Path(root)))
    version = None
    properties = Path(root) / "Ghidra" / "application.properties"
    try:
        match = re.search(r"application.version\s*=\s*([^\s]+)", properties.read_text(encoding="utf-8"))
        version = match.group(1) if match else None
    except OSError:
        pass
    return Capability(name="ghidra", status="present", version=version, path=str(headless))


def probe_x64dbg() -> Capability:
    path = shutil.which("x64dbg")
    if path:
        return Capability(name="x64dbg", status="present", path=path)
    return Capability(name="x64dbg", status="optional_missing")


def discover(
    *,
    cpp2il_path: str | Path | None = None,
    ghidra_root: str | Path | None = None,
) -> list[Capability]:
    return [
        probe_python(),
        probe_frida(),
        probe_node(),
        probe_dotnet(),
        probe_cpp2il(cpp2il_path),
        probe_ghidra(ghidra_root),
        probe_x64dbg(),
    ]


def report(capabilities: list[Capability]) -> dict:
    docs = []
    for cap in capabilities:
        doc = asdict(cap)
        docs.append({key: value for key, value in doc.items() if value is not None})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "capabilities": docs,
    }
    errors = validate(manifest, SCHEMA)
    if errors:
        raise ResultError.internal("capability report failed schema validation", details=errors)
    return manifest


def require(report_doc: dict, name: str, *, optional: bool = False) -> dict:
    for cap in report_doc["capabilities"]:
        if cap["name"] == name:
            if cap["status"] == "present":
                return cap
            if optional:
                return cap
            raise ResultError.missing_capability(
                f"required capability '{name}' is not available"
                + (f" (configured path: {cap['path']})" if cap.get("path") else ""),
                details=cap,
            )
    raise ResultError.missing_capability(f"unknown capability '{name}'")
