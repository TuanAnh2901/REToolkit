"""Mocked pipeline-to-index integration coverage."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

from retoolkit.contracts.profile import Profile, ToolConfig
from retoolkit.core.pipeline import run_pipeline


class _FakeCpp2Il:
    """In-process Cpp2IL double: no child process may be launched."""

    def export_method_map(self, game_assembly: Path, metadata: Path, output_dir: Path):
        from retoolkit.adapters.cpp2il import Cpp2IlResult

        output_dir.mkdir(parents=True, exist_ok=True)
        map_path = output_dir / "method-pointer-map.json"
        map_path.write_text(
            json.dumps(
                [
                    {
                        "assembly": "Assembly-CSharp",
                        "type": "Example.Enemy",
                        "method": "Tick",
                        "signature": "System.Void Example.Enemy::Tick()",
                        "pointer": "0x180001100",
                        "rva": "0x1100",
                    }
                ]
            ),
            encoding="utf-8",
        )
        log_path = output_dir / "cpp2il.log"
        log_path.write_text("mocked", encoding="utf-8")
        return Cpp2IlResult(
            exit_code=0,
            method_count=1,
            map_path=map_path,
            log_path=log_path,
            duration_seconds=0.0,
        )


def _profile(tmp_path: Path) -> Profile:
    game = tmp_path / "game"
    game.mkdir()
    assembly = game / "GameAssembly.dll"
    metadata = game / "global-metadata.dat"
    assembly.write_bytes(b"mocked-game-assembly")
    metadata.write_bytes(b"mocked-global-metadata")
    workspace = tmp_path / "workspace"
    database = workspace / "configured" / "pipeline-index.db"
    stages = {"cpp2il": True, "frida": False, "ghidra": False}
    return Profile(
        name="pipeline-index-test",
        schema_version="1.0.0",
        game_root=game,
        game_assembly=assembly,
        metadata=metadata,
        workspace=workspace,
        index_database=database,
        tools={"cpp2il": ToolConfig(path=tmp_path / "cpp2il.exe")},
        stages=stages,
        raw={"name": "pipeline-index-test", "stages": stages},
    )


def test_pipeline_indexes_normalized_map_without_optional_tools(tmp_path, monkeypatch) -> None:
    from retoolkit.core import pipeline
    from retoolkit.core.capabilities import Capability, report

    profile = _profile(tmp_path)
    fake_cpp2il = _FakeCpp2Il()
    monkeypatch.setattr(
        pipeline,
        "discover",
        lambda **kwargs: [
            Capability(
                name="cpp2il",
                status="present",
                version="mocked",
                path=str(profile.tools["cpp2il"].path),
            )
        ],
    )
    monkeypatch.setattr(pipeline, "report", report)
    monkeypatch.setattr(
        pipeline,
        "_make_adapters",
        lambda profile, capabilities, **kwargs: {
            "cpp2il": fake_cpp2il,
            "ghidra": None,
            "frida": None,
        },
    )

    result = run_pipeline(profile, force_restart=True)

    assert profile.index_database.is_file()
    index_stage = next(stage for stage in result["stages"] if stage["name"] == "index")
    assert index_stage["status"] == "completed"
    assert index_stage["method_count"] == 1
    assert index_stage["database"] == str(profile.index_database)
    assert not Path(f"{profile.index_database}-wal").exists()
    assert not Path(f"{profile.index_database}-shm").exists()

    with sqlite3.connect(profile.index_database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM methods").fetchone()[0] == 1

    manifest = json.loads(Path(result["evidence_manifest"]).read_text(encoding="utf-8"))
    database_records = [
        record for record in manifest["records"] if record["logical_name"] == "retoolkit.db"
    ]
    assert len(database_records) == 1
    assert database_records[0]["stage"] == "index"

    invocations: list[tuple[object, ...]] = []

    def _external_tool_started(*args, **kwargs):
        invocations.append(args)
        raise AssertionError("index-only query started an external tool")

    monkeypatch.setattr(subprocess, "run", _external_tool_started)
    monkeypatch.setattr(subprocess, "Popen", _external_tool_started)
    from retoolkit.commands import target

    monkeypatch.setattr(target, "load_profile", lambda ignored: profile)
    query_result = target.search_targets(Path("unused-profile.json"), method_pattern="Tick")
    assert len(query_result["matches"]) == 1
    assert invocations == []
