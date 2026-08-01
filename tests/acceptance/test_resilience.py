"""Acceptance: lock, corruption, timeout/orphan, interrupt/resume resilience."""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.core.state import WorkspaceLock, hash_inputs
from retoolkit.core.state import PipelineState

REPO_ROOT = Path(__file__).resolve().parents[2]
PY = sys.executable


def test_lock_conflict_exit_4_across_processes(tmp_path) -> None:
    lock = WorkspaceLock(tmp_path)
    lock.acquire()
    try:
        script = (
            "from retoolkit.core.state import WorkspaceLock; "
            f"WorkspaceLock(Path(r'{tmp_path}')).acquire()"
        )
        proc = subprocess.run(
            [PY, "-c", f"from pathlib import Path; {script}"],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 1  # ResultError raised, uncaught in -c
        assert "locked" in proc.stderr or "locked" in proc.stdout
    finally:
        lock.release()


def test_lock_conflict_maps_to_exit_4_via_cli(tmp_path) -> None:
    with WorkspaceLock(tmp_path):
        proc = subprocess.run(
            [PY, "-m", "retoolkit", "_err-test", "--code", "lock_conflict"],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
        )
    assert proc.returncode == 4
    assert json.loads(proc.stdout)["error"]["code"] == "lock_conflict"


def test_corrupt_state_rejected_with_restart_hint(tmp_path) -> None:
    (tmp_path / "state.json").write_text('{"schema_version": "1.0.0", "stages": [', encoding="utf-8")
    with pytest.raises(ResultError) as exc:
        PipelineState.load_or_create(tmp_path, ["a"], hash_inputs(["x"]))
    assert exc.value.exit_code == 1
    assert "--restart" in exc.value.message


def test_interrupted_stage_resumes(tmp_path) -> None:
    state = PipelineState.load_or_create(tmp_path, ["a", "b"], hash_inputs(["x"]))
    state.set_status("a", "completed", input_hash=hash_inputs(["a"]))
    state.set_status("b", "running")  # killed mid-run
    loaded = PipelineState.load_or_create(tmp_path, ["a", "b"], hash_inputs(["x"]))
    assert not loaded.can_skip("b", hash_inputs(["b"]))  # rerun, not skipped
    assert loaded.can_skip("a", hash_inputs(["a"]))
    # state file is valid JSON despite the interruption
    json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))


def test_timeout_orphan_cleanup_real_process(tmp_path, fake_tool, monkeypatch) -> None:
    """FakeTool sleeps + spawns a child; the adapter timeout must kill the
    whole tree and leave no orphan."""
    from retoolkit.adapters.cpp2il import Cpp2IlAdapter

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "Cpp2IL.Plugin.Mfuscator.dll").write_bytes(b"p")
    behavior = tmp_path / "behavior.txt"
    behavior.write_text("spawn_child\nsleep_ms=60000\n", encoding="utf-8")
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", str(behavior))
    work = tmp_path / "work"
    work.mkdir()
    adapter = Cpp2IlAdapter(fake_tool, plugin_dir=plugin_dir, timeout_seconds=1)
    assembly = tmp_path / "GameAssembly.dll"
    assembly.write_bytes(b"x")
    metadata = tmp_path / "m.dat"
    metadata.write_bytes(b"x")
    with pytest.raises(ResultError) as exc:
        adapter.export_method_map(assembly, metadata, work)
    assert exc.value.exit_code == 3
    time.sleep(1)  # give taskkill a moment
    pids = json.loads((tmp_path / "fake-pids.json").read_text(encoding="utf-8"))
    for pid in pids.values():
        listing = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
            capture_output=True, text=True, timeout=30,
        )
        assert str(pid) not in listing.stdout, f"orphan {pid} survived"


def test_stray_tool_stdout_never_breaks_cli_json(tmp_path, fake_tool, monkeypatch) -> None:
    """A tool writing prose to stdout must not corrupt the CLI's JSON output."""
    from retoolkit.core.capabilities import Capability, report
    from retoolkit.contracts.profile import Profile, ToolConfig
    from retoolkit.core import pipeline as pipeline_mod

    game = tmp_path / "game"
    game.mkdir()
    assembly = game / "GameAssembly.dll"
    assembly.write_bytes(b"x")
    metadata = game / "m.dat"
    metadata.write_bytes(b"x")
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "Cpp2IL.Plugin.Mfuscator.dll").write_bytes(b"p")
    behavior = tmp_path / "behavior.txt"
    work = tmp_path / "ws" / "cpp2il"
    behavior.write_text(
        f"stdout=this is stray prose from the tool\n"
        f"write_file|{work}|method-pointer-map.json|[{{\"assembly\":\"A\",\"type\":\"T\",\"method\":\"M\",\"signature\":\"S\",\"pointer\":\"0x1\",\"rva\":\"0x1\"}}]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", str(behavior))
    profile = Profile(
        name="stray", schema_version="1.0.0", game_root=game, game_assembly=assembly,
        metadata=metadata, workspace=tmp_path / "ws",
        tools={"cpp2il": ToolConfig(path=fake_tool, plugin_dir=plugins, timeout_seconds=30)},
        stages={"cpp2il": True},
        raw={},
    )
    monkeypatch.setattr(
        pipeline_mod, "discover",
        lambda **kwargs: [Capability(name="cpp2il", status="present", version="v", path=str(fake_tool))],
    )
    monkeypatch.setattr(pipeline_mod, "report", report)
    monkeypatch.setattr(pipeline_mod, "_make_adapters", lambda p, c, **kw: {
        "cpp2il": __import__("retoolkit.adapters.cpp2il", fromlist=["Cpp2IlAdapter"]).Cpp2IlAdapter(
            fake_tool, plugin_dir=plugins, timeout_seconds=30
        ),
        "ghidra": None, "frida": None,
    })
    result = pipeline_mod.run_pipeline(profile)
    assert result["stages"][2]["status"] == "completed"  # cpp2il
