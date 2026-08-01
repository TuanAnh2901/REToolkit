from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from retoolkit.ghidra import GhidraCacheKey, GhidraProjectCache, GhidraTarget, TargetManifest
from retoolkit.ghidra.targeted import TargetedGhidraRunner


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(binary: Path, rvas, *, method_map: str = "m") -> TargetManifest:
    rows = tuple(
        GhidraTarget(
            target_id=index,
            method_id=index + 1,
            rva=rva,
            address=0x180000000 + rva,
            identity=f"Fixture.Type::Method{index}()",
        )
        for index, rva in enumerate(rvas)
    )
    return TargetManifest(
        schema_version="1.0.0",
        binary_sha256=_sha(binary.read_bytes()),
        method_map_sha256=_sha(method_map.encode("utf-8")),
        image_base=0x180000000,
        targets=rows,
    )


def _runner(fake_tool: Path, tmp_path: Path, monkeypatch) -> TargetedGhidraRunner:
    binary = tmp_path / "GameAssembly.dll"
    binary.write_bytes(b"fixture-binary")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("ImportPreparedProgram.java", "SeedIl2CppFunctions.java", "DecompileBatch.java"):
        (scripts / name).write_text("// fixture", encoding="utf-8")
    behavior = tmp_path / "behavior.txt"
    behavior.write_text("ghidra_emulate\n", encoding="utf-8")
    capture = tmp_path / "commands.jsonl"
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", str(behavior))
    monkeypatch.setenv("FAKETOOL_CAPTURE", str(capture))
    key = GhidraCacheKey(
        binary_sha256=_sha(binary.read_bytes()),
        ghidra_version="11.4",
        loader="PeLoader",
        script_sha256="b" * 64,
        analyzer_profile="targeted-noanalysis",
        image_base=0x180000000,
    )
    return TargetedGhidraRunner(
        headless=fake_tool,
        scripts_dir=scripts,
        cache=GhidraProjectCache(tmp_path / "cache"),
        key=key,
        binary=binary,
        timeout_seconds=2,
    )


def _captured(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_run_imports_once_and_second_run_processes_existing_project(
    fake_tool, tmp_path, monkeypatch
) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)

    first = runner.run(_manifest(runner.binary, [0x1000, 0x2000]))
    second = runner.run(_manifest(runner.binary, [0x3000], method_map="m2"))

    assert [row.mode for row in first.commands] == ["import", "process"]
    assert [row.mode for row in second.commands] == ["process"]
    commands = _captured(tmp_path / "commands.jsonl")
    assert sum("-import" in argv for argv in commands) == 1
    assert sum("-process" in argv for argv in commands) == 2
    assert commands[0].count("-postScript") == 1
    assert commands[1].count("-postScript") == 2


def test_one_batch_uses_one_process_instead_of_one_process_per_method(
    fake_tool, tmp_path, monkeypatch
) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)
    runner.run(_manifest(runner.binary, [0x800], method_map="warmup"))

    result = runner.run(_manifest(runner.binary, range(0x1000, 0x1064), method_map="bulk"))

    assert result.jvm_launches == 1
    assert result.completed == 100
    assert result.commands[0].target_count == 100


def test_cache_hit_starts_no_jvm(fake_tool, tmp_path, monkeypatch) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)
    manifest = _manifest(runner.binary, [0x1000, 0x2000])
    runner.run(manifest)

    cached = runner.run(manifest)

    assert cached.jvm_launches == 0
    assert cached.cache_hits == 2
    assert cached.completed == 2


def test_timeout_preserves_completed_rows_and_resume_sends_only_unfinished(
    fake_tool, tmp_path, monkeypatch
) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)
    runner.run(_manifest(runner.binary, [0x800], method_map="warmup"))
    behavior = tmp_path / "behavior.txt"
    behavior.write_text("ghidra_emulate\nsleep_ms=1000\n", encoding="utf-8")
    monkeypatch.setenv("FAKETOOL_RESULT_LIMIT", "20")
    runner.timeout_seconds = 0.1
    manifest = _manifest(runner.binary, range(0x2000, 0x2032), method_map="timeout")

    partial = runner.run(manifest)

    assert partial.timed_out
    assert partial.completed == 20
    assert len(partial.records) == 20
    assert partial.commands[0].timed_out

    behavior.write_text("ghidra_emulate\n", encoding="utf-8")
    monkeypatch.delenv("FAKETOOL_RESULT_LIMIT")
    runner.timeout_seconds = 2
    resumed = runner.run(manifest, resume=True)

    assert resumed.completed == 50
    assert resumed.cache_hits == 20
    assert resumed.commands[0].target_count == 30
    assert all(row.status == "decompiled" for row in resumed.records)


def test_corrupt_cache_key_metadata_is_not_treated_as_a_hit(fake_tool, tmp_path, monkeypatch) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)
    manifest = _manifest(runner.binary, [0x1000])
    runner.run(manifest)
    project = runner.cache.project(runner.key)
    project.key_metadata.write_text('{"wrong":true}', encoding="utf-8")

    with pytest.raises(RuntimeError, match="different cache key"):
        runner.run(manifest)


def test_batch_size_splits_targets_not_methods_into_individual_processes(
    fake_tool, tmp_path, monkeypatch
) -> None:
    runner = _runner(fake_tool, tmp_path, monkeypatch)
    runner.run(_manifest(runner.binary, [0x800], method_map="warmup"))

    result = runner.run(
        _manifest(runner.binary, range(0x3000, 0x300A), method_map="split"), batch_size=4
    )

    assert [row.target_count for row in result.commands] == [4, 4, 2]
    assert result.jvm_launches == 3

