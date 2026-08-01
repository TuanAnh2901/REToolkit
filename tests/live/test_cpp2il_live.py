"""Live Cpp2IL test: full method-map export against the configured game.

Gated by RETOOLKIT_LIVE_CPP2IL=1 plus RETOOLKIT_CPP2IL and RETOOLKIT_GAME_ROOT.
Reads game inputs only; all outputs go to a temp workspace.
"""

import os
import shutil
from pathlib import Path

import pytest

from retoolkit.adapters.cpp2il import Cpp2IlAdapter
from tests.live.gates import gate_enabled


def _require(env_var: str) -> Path:
    value = os.environ.get(env_var)
    if not value:
        pytest.skip(f"{env_var} not set")
    path = Path(value)
    if not path.exists():
        pytest.skip(f"{env_var} path missing: {path}")
    return path


@pytest.mark.live
def test_live_cpp2il_method_map(tmp_path) -> None:
    enabled, reason = gate_enabled("cpp2il")
    if not enabled:
        pytest.skip(reason)
    exe = _require("RETOOLKIT_CPP2IL")
    game_root = _require("RETOOLKIT_GAME_ROOT")
    assembly = game_root / "GameAssembly.dll"
    metadata = game_root / "Everlusting Life_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    if not assembly.is_file() or not metadata.is_file():
        pytest.skip("game assembly/metadata missing under RETOOLKIT_GAME_ROOT")

    plugin_dir = None
    plugins_env = os.environ.get("RETOOLKIT_CPP2IL_PLUGINS")
    if plugins_env:
        plugin_dir = Path(plugins_env)

    output_dir = tmp_path / "out"
    try:
        adapter = Cpp2IlAdapter(exe, plugin_dir=plugin_dir, timeout_seconds=600)
        result = adapter.export_method_map(assembly, metadata, output_dir)
        assert result.exit_code == 0
        assert result.method_count > 100_000, f"unexpected method count {result.method_count}"
        assert result.map_path.is_file()
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


@pytest.mark.live
def test_live_cpp2il_missing_game_skips_before_launch() -> None:
    enabled, reason = gate_enabled("cpp2il")
    if not enabled:
        pytest.skip(reason)
    exe = _require("RETOOLKIT_CPP2IL")
    if not os.environ.get("RETOOLKIT_GAME_ROOT"):
        pytest.skip("RETOOLKIT_GAME_ROOT not set")
    with pytest.raises(Exception):
        # no assembly configured -> adapter must fail cleanly, never launch
        Cpp2IlAdapter(exe, plugin_dir=None).export_method_map(
            Path("missing.dll"), Path("missing.dat"), Path("unused")
        )
