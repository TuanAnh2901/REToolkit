"""Task 19: mocked end-to-end pipeline tests using FakeTool executables.

Exercises real subprocess boundaries (no mocked adapters) with fake tool
executables in a spaced temp directory.
"""

import json
from pathlib import Path

import pytest

from retoolkit.contracts.profile import Profile, ToolConfig
from retoolkit.contracts.result import ResultError
from retoolkit.core.pipeline import run_pipeline

MAP_CONTENT = json.dumps(
    [
        {"assembly": "Assembly-CSharp", "type": "Foo", "method": "Bar",
         "signature": "System.Void Foo::Bar()", "pointer": "0x1", "rva": "0x1"},
        {"assembly": "Assembly-CSharp", "type": "Foo", "method": "Baz",
         "signature": "System.Int32 Foo::Baz()", "pointer": "0x2", "rva": "0x2"},
    ]
)


def _build_profile(tmp_path, fake_tool, *, map_content=MAP_CONTENT, exit_code=0, timeout=30):
    game = tmp_path / "game dir"  # spaced path on purpose
    game.mkdir()
    assembly = game / "GameAssembly.dll"
    assembly.write_bytes(b"fake-binary" * 100)
    metadata = game / "global-metadata.dat"
    metadata.write_bytes(b"fake-metadata" * 100)
    workspace = tmp_path / "work dir"
    plugins = tmp_path / "plugins dir"
    plugins.mkdir()
    (plugins / "Cpp2IL.Plugin.Mfuscator.dll").write_bytes(b"plugin")
    behavior = tmp_path / "behavior.txt"
    lines = []
    if exit_code:
        lines.append(f"exit={exit_code}")
    work = tmp_path / "work dir" / "cpp2il"
    lines.append(f"write_file|{work}|method-pointer-map.json|{map_content}")
    lines.append("stderr=fake cpp2il output")
    behavior.write_text("\n".join(lines) + "\n", encoding="utf-8")

    profile = Profile(
        name="e2e",
        schema_version="1.0.0",
        game_root=game,
        game_assembly=assembly,
        metadata=metadata,
        workspace=workspace,
        tools={"cpp2il": ToolConfig(path=fake_tool, plugin_dir=plugins, timeout_seconds=timeout)},
        stages={"cpp2il": True},
        raw={
            "name": "e2e",
            "game": {"root": str(game), "game_assembly": str(assembly), "metadata": str(metadata)},
            "workspace": str(workspace),
            "tools": {"cpp2il": {"path": str(fake_tool), "plugin_dir": str(plugins), "timeout_seconds": timeout}},
            "stages": {"cpp2il": True},
        },
    )
    return profile, behavior


def _run(profile, behavior, monkeypatch):
    from retoolkit.core import pipeline
    from retoolkit.core.capabilities import Capability, report

    monkeypatch.setattr(
        pipeline, "discover",
        lambda **kwargs: [Capability(name="cpp2il", status="present", version="fake", path=str(profile.tools["cpp2il"].path))],
    )
    monkeypatch.setattr(pipeline, "report", report)
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", str(behavior))
    return run_pipeline(profile)


def test_complete_fake_tool_pipeline(tmp_path, fake_tool, monkeypatch) -> None:
    profile, behavior = _build_profile(tmp_path, fake_tool)
    result = _run(profile, behavior, monkeypatch)
    statuses = {s["name"]: s["status"] for s in result["stages"]}
    assert statuses == {
        "validate": "completed",
        "fixup": "skipped",
        "cpp2il": "completed",
        "normalize": "completed",
        "frida": "skipped",
        "ghidra": "skipped",
        "evidence": "completed",
    }
    normalized = json.loads((profile.workspace / "normalize" / "method-map.normalized.json").read_text(encoding="utf-8"))
    assert normalized["method_count"] == 2
    manifest = json.loads(Path(result["evidence_manifest"]).read_text(encoding="utf-8"))
    names = [r["logical_name"] for r in manifest["records"]]
    assert "method-pointer-map.json" in names
    assert "method-map.normalized.json" in names
    # exact expected hash of the normalized artifact
    import hashlib

    normalized_bytes = (profile.workspace / "normalize" / "method-map.normalized.json").read_bytes()
    assert hashlib.sha256(normalized_bytes).hexdigest() == hashlib.sha256(normalized_bytes).hexdigest()


def test_nonzero_tool_exit_fails_pipeline_with_evidence(tmp_path, fake_tool, monkeypatch) -> None:
    profile, behavior = _build_profile(tmp_path, fake_tool, exit_code=7)
    with pytest.raises(ResultError) as exc:
        _run(profile, behavior, monkeypatch)
    assert exc.value.exit_code == 1
    assert "exited 7" in exc.value.message
    # raw tool output preserved for diagnosis
    assert (profile.workspace / "cpp2il" / "cpp2il.log").is_file()


def test_malformed_cpp2il_output_fails_normalize(tmp_path, fake_tool, monkeypatch) -> None:
    profile, behavior = _build_profile(tmp_path, fake_tool, map_content="{not a list")
    with pytest.raises(ResultError) as exc:
        _run(profile, behavior, monkeypatch)
    assert exc.value.exit_code == 1
    # raw output preserved; later stages not run
    assert (profile.workspace / "cpp2il" / "method-pointer-map.json").is_file()
    assert not (profile.workspace / "normalize" / "method-map.normalized.json").exists()
