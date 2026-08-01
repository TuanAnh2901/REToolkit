"""Schema-validated, atomic Ghidra target and result serialization."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from typing import Iterable

from retoolkit.contracts.schema import validate
from retoolkit.core.atomic import atomic_write_text

from .models import GhidraRecord, GhidraTarget, TargetManifest


def _canonical_json(document: dict[str, object]) -> str:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _validated(document: dict[str, object], schema_name: str) -> None:
    errors = validate(document, schema_name)
    if errors:
        raise ValueError(f"{schema_name} validation failed: {'; '.join(errors)}")


def target_manifest_document(manifest: TargetManifest) -> dict[str, object]:
    document: dict[str, object] = asdict(manifest)
    document["targets"] = list(document["targets"])
    _validated(document, "ghidra_target_manifest.schema.json")
    return document


def write_target_manifest(path: Path, manifest: TargetManifest) -> None:
    document = target_manifest_document(manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, _canonical_json(document) + "\n")


def read_target_manifest(path: Path) -> TargetManifest:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("target manifest root must be an object")
    _validated(document, "ghidra_target_manifest.schema.json")
    return TargetManifest(
        schema_version=document["schema_version"],
        binary_sha256=document["binary_sha256"],
        method_map_sha256=document["method_map_sha256"],
        image_base=document["image_base"],
        targets=tuple(GhidraTarget(**row) for row in document["targets"]),
    )


def result_record_document(record: GhidraRecord) -> dict[str, object]:
    document: dict[str, object] = asdict(record)
    _validated(document, "ghidra_result.schema.json")
    return document


def write_result_records(path: Path, records: Iterable[GhidraRecord]) -> None:
    ordered = tuple(sorted(tuple(records), key=lambda row: row.target_id))
    ids = [row.target_id for row in ordered]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate target_id in Ghidra results")
    lines = [_canonical_json(result_record_document(record)) for record in ordered]
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, ("\n".join(lines) + "\n") if lines else "")


def read_result_records(path: Path) -> tuple[GhidraRecord, ...]:
    records: list[GhidraRecord] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            document = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid Ghidra result JSON on line {number}: {error}") from error
        if not isinstance(document, dict):
            raise ValueError(f"Ghidra result on line {number} must be an object")
        _validated(document, "ghidra_result.schema.json")
        records.append(GhidraRecord(**document))
    ordered = tuple(sorted(records, key=lambda row: row.target_id))
    if len({row.target_id for row in ordered}) != len(ordered):
        raise ValueError("duplicate target_id in Ghidra results")
    return ordered
