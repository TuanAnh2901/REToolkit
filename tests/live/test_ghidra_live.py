"""Live Ghidra test: targeted headless decompile when Ghidra is installed.

Gated by RETOOLKIT_LIVE_GHIDRA=1 plus RETOOLKIT_GHIDRA pointing at an
extracted Ghidra root. Missing install skips before any process launches.
"""

import os
from pathlib import Path

import pytest

from retoolkit.adapters.ghidra import GhidraAdapter
from tests.live.gates import gate_enabled


@pytest.mark.live
def test_live_ghidra_targeted_decompile(tmp_path) -> None:
    enabled, reason = gate_enabled("ghidra")
    if not enabled:
        pytest.skip(reason)
    root = os.environ.get("RETOOLKIT_GHIDRA")
    if not root:
        pytest.skip("RETOOLKIT_GHIDRA not set")
    ghidra_root = Path(root)
    if not (ghidra_root / "support" / "analyzeHeadless.bat").is_file():
        pytest.skip(f"analyzeHeadless not installed at {ghidra_root}")

    game_root = os.environ.get("RETOOLKIT_GAME_ROOT")
    if not game_root:
        pytest.skip("RETOOLKIT_GAME_ROOT not set")
    binary = Path(game_root) / "GameAssembly.dll"
    if not binary.is_file():
        pytest.skip("GameAssembly.dll missing under RETOOLKIT_GAME_ROOT")

    scripts_dir = Path(__file__).resolve().parents[2] / "ghidra_scripts"
    adapter = GhidraAdapter(ghidra_root, scripts_dir=scripts_dir, timeout_seconds=900)
    result = adapter.decompile_rvas(
        binary=binary,
        project_dir=tmp_path / "project",
        project_name="live",
        rvas=[0x434A60],
        output_dir=tmp_path / "out",
    )
    assert len(result.artifacts) == 1
    assert result.artifacts[0].path is not None
