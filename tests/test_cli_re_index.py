"""CLI coverage for persistent RE-index build and deterministic target queries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from retoolkit.cli import build_parser, main
from retoolkit.contracts.result import ExitCode


def _profile(tmp_path: Path) -> Path:
    game = tmp_path / "game"
    game.mkdir()
    assembly = game / "GameAssembly.dll"
    assembly.write_bytes(b"fixture-binary")
    workspace = tmp_path / "workspace"
    map_path = workspace / "normalize" / "method-map.normalized.json"
    map_path.parent.mkdir(parents=True)
    map_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "method_count": 2,
                "methods": [
                    {
                        "assembly": "A",
                        "type": "N.T",
                        "method": "M",
                        "signature": "System.Void N.T::M()",
                        "rva": "0x20",
                        "pointer": "0x180000020",
                        "full_identity": "A!System.Void N.T::M()",
                    },
                    {
                        "assembly": "A",
                        "type": "N.T",
                        "method": "M",
                        "signature": "System.Void N.T::M()",
                        "rva": "0x10",
                        "pointer": "0x180000010",
                        "full_identity": "A!System.Void N.T::M()",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    profile = {
        "schema_version": "1.0.0",
        "name": "test-game",
        "game": {
            "root": "game",
            "game_assembly": "game/GameAssembly.dll",
            "metadata": "game/global-metadata.dat",
        },
        "workspace": "workspace",
        "index": {"database": "re-index/retoolkit.db", "query_limit": 100},
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")
    return path


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict, str]:
    code = main(argv)
    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    return code, json.loads(captured.out), captured.err


def test_index_build_parser_contract() -> None:
    args = build_parser().parse_args(["index", "build", "profile.json"])
    assert args.command == "index"
    assert args.index_command == "build"


def test_target_search_parser_contract() -> None:
    args = build_parser().parse_args(
        ["target", "search", "profile.json", "--class", "N.*", "--method", "M"]
    )
    assert args.target_command == "search"
    assert args.type_pattern == "N.*"
    assert args.method_pattern == "M"


def test_index_build_stats_and_target_resolve_are_canonical_json(tmp_path, capsys) -> None:
    profile = _profile(tmp_path)

    code, doc, stderr = _run(["index", "build", str(profile)], capsys)
    assert code == ExitCode.OK
    assert stderr == ""
    assert doc["status"] == "ok"
    assert doc["command"] == "index build"
    assert doc["data"]["method_count"] == 2
    assert Path(doc["data"]["database"]).is_file()

    code, doc, stderr = _run(["index", "stats", str(profile)], capsys)
    assert code == ExitCode.OK
    assert stderr == ""
    assert doc["status"] == "ok"
    assert doc["command"] == "index stats"
    assert doc["data"]["method_count"] == 2

    code, doc, stderr = _run(
        ["target", "resolve", str(profile), "A!System.Void N.T::M()"], capsys
    )
    assert code == ExitCode.OK
    assert stderr == ""
    assert doc["status"] == "ok"
    assert doc["command"] == "target resolve"
    assert doc["data"]["matches"][0]["rva"] == "0x10"


def test_target_search_filters_without_spawning_external_tools(tmp_path, capsys, monkeypatch) -> None:
    profile = _profile(tmp_path)
    assert _run(["index", "build", str(profile)], capsys)[0] == ExitCode.OK

    def fail_if_started(*_args, **_kwargs):
        raise AssertionError("index-only command started an external process")

    monkeypatch.setattr("subprocess.run", fail_if_started)
    code, doc, stderr = _run(
        ["target", "search", str(profile), "--assembly", "A", "--rva", "0x20"], capsys
    )
    assert code == ExitCode.OK
    assert stderr == ""
    assert doc["command"] == "target search"
    assert [match["rva"] for match in doc["data"]["matches"]] == ["0x20"]


def test_target_search_requires_a_selector(tmp_path, capsys) -> None:
    profile = _profile(tmp_path)
    code, doc, _ = _run(["target", "search", str(profile)], capsys)
    assert code == ExitCode.VALIDATION
    assert doc["status"] == "error"
    assert doc["command"] == "target"
    assert "selector" in doc["error"]["message"]
