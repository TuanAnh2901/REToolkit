"""Task 17: linear resumable pipeline tests with fake adapters."""

import json
from pathlib import Path

import pytest

from retoolkit.contracts.profile import Profile, ToolConfig
from retoolkit.contracts.result import ResultError
from retoolkit.core.pipeline import STAGES, plan, run_pipeline

MAP_CONTENT = json.dumps(
    [
        {"assembly": "Assembly-CSharp", "type": "Foo", "method": "Bar",
         "signature": "System.Void Foo::Bar()", "pointer": "0x1", "rva": "0x1"},
    ]
)


def _profile(tmp_path, *, stages=None, fixup=False) -> Profile:
    game = tmp_path / "game"
    game.mkdir()
    assembly = game / "GameAssembly.dll"
    assembly.write_bytes(b"fake-binary")
    metadata = game / "global-metadata.dat"
    metadata.write_bytes(b"fake-metadata")
    workspace = tmp_path / "work"
    profile = Profile(
        name="test",
        schema_version="1.0.0",
        game_root=game,
        game_assembly=assembly,
        metadata=metadata,
        workspace=workspace,
        tools={
            "cpp2il": ToolConfig(path=tmp_path / "cpp2il.exe", plugin_dir=tmp_path / "plugins", timeout_seconds=30),
        },
        stages=stages or {"cpp2il": True},
        raw={
            "name": "test",
            "game": {"root": str(game), "game_assembly": str(assembly), "metadata": str(metadata)},
            "workspace": str(workspace),
            "tools": {"cpp2il": {"path": str(tmp_path / "cpp2il.exe"), "plugin_dir": str(tmp_path / "plugins"), "timeout_seconds": 30}},
            "stages": stages or {"cpp2il": True},
        },
    )
    return profile


class FakeCpp2Il:
    def __init__(self, tmp_path, fail_once=False, produce_map=True):
        self.fail_once = fail_once
        self.calls = 0
        self.produce_map = produce_map
        self._tmp = tmp_path

    def export_method_map(self, game_assembly, metadata, output_dir):
        self.calls += 1
        if self.fail_once and self.calls == 1:
            raise ResultError.internal("synthetic cpp2il failure")
        output_dir.mkdir(parents=True, exist_ok=True)
        if self.produce_map:
            (output_dir / "method-pointer-map.json").write_text(MAP_CONTENT, encoding="utf-8")
        (output_dir / "cpp2il.log").write_text("fake log", encoding="utf-8")
        from retoolkit.adapters.cpp2il import Cpp2IlResult

        return Cpp2IlResult(exit_code=0, method_count=1, map_path=output_dir / "method-pointer-map.json",
                            log_path=output_dir / "cpp2il.log", duration_seconds=0.1)


def _run_with_fakes(profile, monkeypatch, cpp2il, restart=False):
    from retoolkit.core import pipeline
    from retoolkit.core.capabilities import Capability, report

    monkeypatch.setattr(
        pipeline, "discover",
        lambda **kwargs: [Capability(name="cpp2il", status="present", version="test", path=str(profile.tools["cpp2il"].path))],
    )
    monkeypatch.setattr(pipeline, "report", report)
    monkeypatch.setattr(pipeline, "_make_adapters", lambda p, c, **kw: {"cpp2il": cpp2il, "ghidra": None, "frida": None})
    return run_pipeline(profile, force_restart=restart)


def test_plan_is_side_effect_free(tmp_path) -> None:
    profile = _profile(tmp_path)
    doc = plan(profile)
    assert [s["name"] for s in doc["stages"]] == STAGES
    assert doc["stages"][0]["enabled"] is True
    assert not (profile.workspace / "state.json").exists()
    assert not profile.workspace.exists()


def test_full_mocked_run_orders_stages(tmp_path, monkeypatch) -> None:
    profile = _profile(tmp_path)
    fake = FakeCpp2Il(tmp_path)
    result = _run_with_fakes(profile, monkeypatch, fake)
    order = [s["name"] for s in result["stages"]]
    assert order == STAGES
    assert result["stages"][0]["status"] == "completed"  # validate
    assert result["stages"][1]["status"] == "skipped"  # fixup (no metadata_fixup)
    assert result["stages"][2]["status"] == "completed"  # cpp2il
    assert result["stages"][3]["status"] == "completed"  # normalize
    assert result["stages"][4]["status"] == "skipped"  # frida disabled
    assert result["stages"][5]["status"] == "skipped"  # ghidra disabled
    assert result["stages"][6]["status"] == "completed"  # evidence
    assert (profile.workspace / "normalize" / "method-map.normalized.json").is_file()
    manifest = Path(result["evidence_manifest"])
    assert manifest.is_file()
    assert json.loads(manifest.read_text(encoding="utf-8"))["run_id"] == result["run_id"]


def test_failure_then_resume_reruns_only_failed_stage(tmp_path, monkeypatch) -> None:
    profile = _profile(tmp_path)
    fake = FakeCpp2Il(tmp_path, fail_once=True)
    with pytest.raises(ResultError):
        _run_with_fakes(profile, monkeypatch, fake)
    assert fake.calls == 1
    state_file = profile.workspace / "state.json"
    doc = json.loads(state_file.read_text(encoding="utf-8"))
    failed = next(s for s in doc["stages"] if s["name"] == "cpp2il")
    assert failed["status"] == "failed"
    # resume with a working adapter: only cpp2il and later rerun
    working = FakeCpp2Il(tmp_path)
    result = _run_with_fakes(profile, monkeypatch, working)
    assert working.calls == 1
    statuses = {s["name"]: s["status"] for s in result["stages"]}
    assert statuses["validate"] == "resumed"
    assert statuses["cpp2il"] == "completed"
    assert statuses["normalize"] == "completed"


def test_restart_reruns_everything(tmp_path, monkeypatch) -> None:
    profile = _profile(tmp_path)
    _run_with_fakes(profile, monkeypatch, FakeCpp2Il(tmp_path))
    fake = FakeCpp2Il(tmp_path)
    _run_with_fakes(profile, monkeypatch, fake, restart=True)
    assert fake.calls == 1


def test_evidence_contains_stage_artifacts(tmp_path, monkeypatch) -> None:
    profile = _profile(tmp_path)
    result = _run_with_fakes(profile, monkeypatch, FakeCpp2Il(tmp_path))
    manifest = json.loads(Path(result["evidence_manifest"]).read_text(encoding="utf-8"))
    names = [record["logical_name"] for record in manifest["records"]]
    assert "method-pointer-map.json" in names
    assert "method-map.normalized.json" in names
    for record in manifest["records"]:
        assert len(record["sha256"]) == 64
