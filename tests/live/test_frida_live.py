"""Live Frida test: spawn the configured game and run a resolve-only trace.

Gated by RETOOLKIT_LIVE_FRIDA=1 plus RETOOLKIT_GAME_ROOT. Never attaches to
non-profile targets and never leaves the spawned child running.
"""

import os
from pathlib import Path

import pytest

from retoolkit.adapters.frida import FridaAdapter
from tests.live.gates import gate_enabled


@pytest.mark.live
def test_live_frida_init_trace(tmp_path) -> None:
    enabled, reason = gate_enabled("frida")
    if not enabled:
        pytest.skip(reason)
    game_root = os.environ.get("RETOOLKIT_GAME_ROOT")
    if not game_root:
        pytest.skip("RETOOLKIT_GAME_ROOT not set")
    exe = Path(game_root) / "Everlusting Life.exe"
    if not exe.is_file():
        pytest.skip("game executable missing under RETOOLKIT_GAME_ROOT")

    adapter = FridaAdapter(timeout_seconds=180)
    jsonl = tmp_path / "trace.jsonl"
    try:
        messages = adapter.run_trace(
            target=str(exe),
            trace_script=Path(__file__).resolve().parents[2]
            / "profiles" / "examples" / "frida" / "init-trace.js",
            params={"targets": []},
            mode="spawn",
        )
        adapter.write_jsonl(messages, jsonl)
        assert jsonl.is_file()
        assert any("resolver" in str(m) or "trace" in str(m) for m in messages)
    finally:
        if jsonl.exists():
            jsonl.unlink()
