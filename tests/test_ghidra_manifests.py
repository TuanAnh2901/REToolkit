import json

import pytest

from retoolkit.ghidra.manifests import (
    read_result_records,
    read_target_manifest,
    write_result_records,
    write_target_manifest,
)
from retoolkit.ghidra.models import GhidraRecord, GhidraTarget, TargetManifest


def _manifest(*targets: GhidraTarget) -> TargetManifest:
    return TargetManifest(
        schema_version="1.0.0",
        binary_sha256="a" * 64,
        method_map_sha256="b" * 64,
        image_base=0x180000000,
        targets=targets,
    )


def test_target_manifest_is_sorted_canonical_and_round_trips(tmp_path) -> None:
    manifest = _manifest(
        GhidraTarget(3, 30, 0x30, 0x180000030, "Z!M"),
        GhidraTarget(2, 20, 0x10, 0x180000010, "B!M"),
        GhidraTarget(1, 10, 0x10, 0x180000010, "A!M"),
    )
    path = tmp_path / "nested" / "targets.json"

    write_target_manifest(path, manifest)

    raw = path.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    document = json.loads(raw)
    assert [row["target_id"] for row in document["targets"]] == [1, 2, 3]
    restored = read_target_manifest(path)
    assert [target.target_id for target in restored.targets] == [1, 2, 3]
    assert restored == read_target_manifest(path)


def test_target_manifest_rejects_inconsistent_address_before_write(tmp_path) -> None:
    path = tmp_path / "targets.json"
    with pytest.raises(ValueError, match="address"):
        invalid = _manifest(GhidraTarget(1, 2, 0x10, 0x140000010, "A!M"))
        write_target_manifest(path, invalid)
    assert not path.exists()


def test_target_manifest_rejects_duplicate_ids_before_write(tmp_path) -> None:
    with pytest.raises(ValueError, match="duplicate target_id"):
        invalid = _manifest(
            GhidraTarget(1, 2, 0x10, 0x180000010, "A!M"),
            GhidraTarget(1, 3, 0x20, 0x180000020, "B!M"),
        )
        write_target_manifest(tmp_path / "targets.json", invalid)


def test_result_records_are_sorted_canonical_and_schema_validated(tmp_path) -> None:
    records = (
        GhidraRecord(2, 20, 0x20, 0x180000020, "timeout", duration_ms=90, error="timeout"),
        GhidraRecord(
            1,
            10,
            0x10,
            0x180000010,
            "decompiled",
            function_name="FUN_180000010",
            function_entry_rva=0x10,
            function_end_rva=0x1F,
            pseudocode="return;",
            duration_ms=12,
        ),
    )
    path = tmp_path / "results.jsonl"

    write_result_records(path, records)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["target_id"] for line in lines] == [1, 2]
    assert read_result_records(path) == tuple(sorted(records, key=lambda row: row.target_id))


def test_invalid_result_status_is_rejected_before_write(tmp_path) -> None:
    path = tmp_path / "results.jsonl"
    with pytest.raises(ValueError, match="status"):
        write_result_records(
            path,
            (GhidraRecord(1, 1, 0, 0x180000000, "", duration_ms=0),),
        )
    assert not path.exists()
