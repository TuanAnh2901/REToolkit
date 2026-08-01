"""Task 10: Cpp2IL CLI adapter tests against the FakeTool process double."""

import json
import os
import subprocess

import pytest

from retoolkit.adapters.cpp2il import Cpp2IlAdapter
from retoolkit.contracts.result import ResultError

MAP_CONTENT = json.dumps(
    [
        {"assembly": "Assembly-CSharp", "type": "Foo", "method": "Bar",
         "signature": "System.Void Foo::Bar()", "pointer": "0x1", "rva": "0x1"},
        {"assembly": "Assembly-CSharp", "type": "Foo", "method": "Baz",
         "signature": "System.Int32 Foo::Baz()", "pointer": "0x2", "rva": "0x2"},
    ]
)


def _write_behavior(tmp_path, lines, name="behavior.txt") -> str:
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _setup(tmp_path, fake_tool, behavior_lines, *, timeout=30):
    game = tmp_path / "GameAssembly.dll"
    metadata = tmp_path / "global-metadata.dat"
    game.write_bytes(b"fake-binary")
    metadata.write_bytes(b"fake-metadata")
    work = tmp_path / "work"
    work.mkdir()
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "Cpp2IL.Plugin.Mfuscator.dll").write_bytes(b"plugin")
    adapter = Cpp2IlAdapter(fake_tool, plugin_dir=plugin_dir, timeout_seconds=timeout)
    return adapter, game, metadata, work, plugin_dir, _write_behavior(tmp_path, behavior_lines)


def _run(adapter, game, metadata, work, behavior, monkeypatch) -> None:
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", behavior)
    adapter.export_method_map(game, metadata, work)


def test_successful_export_parses_map(fake_tool, tmp_path, monkeypatch) -> None:
    work = tmp_path / "work"
    adapter, game, metadata, work, plugin_dir, behavior = _setup(tmp_path, fake_tool,
        [f"write_file|{work}|method-pointer-map.json|{MAP_CONTENT}"],
    )
    _run(adapter, game, metadata, work, behavior, monkeypatch)
    result = adapter.export_method_map(game, metadata, work)
    assert result.exit_code == 0
    assert result.method_count == 2
    assert result.map_path.name == "method-pointer-map.json"
    assert (work / "cpp2il.log").exists()


def test_missing_executable_raises_missing_capability(tmp_path) -> None:
    with pytest.raises(ResultError) as exc:
        Cpp2IlAdapter(tmp_path / "nope.exe", plugin_dir=None)
    assert exc.value.exit_code == 2


def test_missing_plugin_dll_rejected(tmp_path, fake_tool) -> None:
    empty = tmp_path / "plugins"
    empty.mkdir()
    with pytest.raises(ResultError) as exc:
        Cpp2IlAdapter(fake_tool, plugin_dir=empty)
    assert exc.value.exit_code == 1
    assert "Mfuscator" in exc.value.message


def test_timeout_kills_process_tree(fake_tool, tmp_path, monkeypatch) -> None:
    adapter, game, metadata, work, plugin_dir, behavior = _setup(tmp_path, fake_tool, ["spawn_child", "sleep_ms=60000"], timeout=1
    )
    with pytest.raises(ResultError) as exc:
        _run(adapter, game, metadata, work, behavior, monkeypatch)
    assert exc.value.exit_code == 3
    pids = json.loads((plugin_dir.parent / "fake-pids.json").read_text(encoding="utf-8"))
    for pid in pids.values():
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"],
            capture_output=True, text=True,
        )
        assert str(pid) not in result.stdout, f"orphan process {pid} survived timeout"


def test_crash_signature_maps_to_actionable_validation(fake_tool, tmp_path, monkeypatch) -> None:
    adapter, game, metadata, work, plugin_dir, behavior = _setup(tmp_path, fake_tool,
        ["exit=-532462766",
         "stderr=Unhandled exception. System.InvalidOperationException: Reflection-based serialization has been disabled for this application"],
    )
    with pytest.raises(ResultError) as exc:
        _run(adapter, game, metadata, work, behavior, monkeypatch)
    assert exc.value.exit_code == 1
    assert "runtimeconfig" in exc.value.message


def test_nonzero_exit_reported_with_log(fake_tool, tmp_path, monkeypatch) -> None:
    adapter, game, metadata, work, plugin_dir, behavior = _setup(tmp_path, fake_tool, ["exit=7"]
    )
    with pytest.raises(ResultError) as exc:
        _run(adapter, game, metadata, work, behavior, monkeypatch)
    assert exc.value.exit_code == 1
    assert "exited 7" in exc.value.message
    assert (work / "cpp2il.log").exists()


def test_argv_is_argument_array_with_spaced_paths(fake_tool, tmp_path, monkeypatch) -> None:
    work = tmp_path / "work"
    adapter, game, metadata, work, plugin_dir, behavior = _setup(tmp_path, fake_tool,
        [f"write_file|{work}|method-pointer-map.json|{MAP_CONTENT}"],
    )
    _run(adapter, game, metadata, work, behavior, monkeypatch)
    argv = json.loads((plugin_dir.parent / "fake-argv.json").read_text(encoding="utf-8"))
    # fake argv[0] is the first argument after the executable
    assert argv[0] == "--force-binary-path"
    assert "--force-metadata-path" in argv
    assert "--export-method-map" in argv
    # fake-argv.json landed in plugin_dir.parent: the adapter's cwd is the
    # plugin dir's parent, which is what makes Cpp2IL discover <cwd>/Plugins/.

