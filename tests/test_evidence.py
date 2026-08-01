"""Task 4: evidence schema and append-only artifact writer tests."""

import hashlib
import json

import pytest

from retoolkit.contracts.schema import validate
from retoolkit.core.evidence import EvidenceDir, load_evidence

PAYLOAD = b"evidence payload bytes"


def _make(tmp_path, run_id="run-1"):
    return EvidenceDir(base_dir=tmp_path, run_id=run_id)


def test_add_bytes_hashes_and_manifest_is_schema_valid(tmp_path) -> None:
    ev = _make(tmp_path)
    record = ev.add_bytes(logical_name="out.log", data=PAYLOAD, stage="cpp2il", tool="cpp2il")
    assert record.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert record.size == len(PAYLOAD)
    assert (ev.artifacts_dir / "out.log").read_bytes() == PAYLOAD
    assert validate(ev.manifest, "evidence.schema.json") == []


def test_second_write_preserves_first_and_is_uniquely_named(tmp_path) -> None:
    ev = _make(tmp_path)
    first = ev.add_bytes(logical_name="out.log", data=b"original", stage="cpp2il")
    second = ev.add_bytes(logical_name="out.log", data=b"replacement", stage="cpp2il")
    assert (ev.artifacts_dir / "out.log").read_bytes() == b"original"
    assert (ev.artifacts_dir / "out-1.log").read_bytes() == b"replacement"
    assert first.artifact_path != second.artifact_path
    assert len(ev.records) == 2
    assert validate(ev.manifest, "evidence.schema.json") == []


def test_add_file_records_provenance_and_hash_matches(tmp_path) -> None:
    source = tmp_path / "game" / "global-metadata.dat"
    source.parent.mkdir()
    source.write_bytes(PAYLOAD)
    ev = _make(tmp_path)
    record = ev.add_file(logical_name="metadata.dat", source=source, stage="fixup")
    assert record.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert record.provenance["source_sha256"] == record.sha256
    assert record.provenance["source_path"] == str(source)


def test_partial_temp_write_leaves_no_valid_partial_manifest(tmp_path) -> None:
    ev = _make(tmp_path)
    ev.add_bytes(logical_name="a.txt", data=b"aaa", stage="s")
    # simulate a crash mid-write: stale temp file next to a valid manifest
    stale = ev.manifest_path.with_name(f"{ev.manifest_path.name}.tmp-999-deadbeef")
    stale.write_text('{"schema_version": "1.0.0", "run_id": "run-1", "records": [', encoding="utf-8")
    reloaded = load_evidence(ev.manifest_path)
    assert len(reloaded.records) == 1
    assert validate(reloaded.manifest, "evidence.schema.json") == []


def test_manifest_survives_reload_with_all_records(tmp_path) -> None:
    ev = _make(tmp_path)
    for i in range(3):
        ev.add_bytes(logical_name=f"f{i}.bin", data=f"data-{i}".encode(), stage="s")
    reloaded = load_evidence(ev.manifest_path)
    assert [r.logical_name for r in reloaded.records] == ["f0.bin", "f1.bin", "f2.bin"]
    for record in reloaded.records:
        artifact = tmp_path / "run-1" / record.artifact_path
        assert artifact.exists()


def test_manifest_rejects_corrupt_records(tmp_path) -> None:
    ev = _make(tmp_path)
    ev.add_bytes(logical_name="ok.bin", data=b"ok", stage="s")
    doc = ev.manifest
    doc["records"][0]["sha256"] = "not-a-hash"
    ev.manifest_path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(Exception):
        load_evidence(ev.manifest_path)
