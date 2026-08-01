"""Shared pytest fixtures and path setup for the retoolkit suite.

Ensures ``src/`` is importable even when the package is not installed
(e.g. CI running pytest directly from a clean checkout), and builds the
FakeTool.exe process double used by adapter tests.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(SRC))


def _build_fake_tool(target: Path) -> None:
    script = REPO_ROOT / "tests" / "fakes" / "build_tool.ps1"
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-Output",
            str(target),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )


@pytest.fixture(scope="session")
def fake_tool(tmp_path_factory) -> Path:
    exe = tmp_path_factory.getbasetemp() / "faketool.exe"
    if not exe.exists():
        _build_fake_tool(exe)
    return exe
