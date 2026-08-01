"""Append-only per-run evidence: hashed artifacts plus a validated manifest.

Layout::

    <evidence_root>/<run_id>/
        manifest.json      # schema-validated, atomically rewritten on each add
        artifacts/         # one immutable file per record

Writing the same logical name twice preserves the first artifact and gives the
second a ``-N`` suffix; old manifest records are never modified.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.core.atomic import atomic_write_bytes, atomic_write_text

SCHEMA = "evidence.schema.json"
SCHEMA_VERSION = "1.0.0"


@dataclass
class EvidenceRecord:
    logical_name: str
    artifact_path: str
    sha256: str
    size: int
    stage: str
    timestamp: str
    tool: str | None = None
    tool_version: str | None = None
    provenance: dict | None = None


@dataclass
class EvidenceDir:
    """A single run's evidence directory with append-only semantics."""

    base_dir: Path
    run_id: str
    records: list[EvidenceRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.dir = self.base_dir / self.run_id
        self.artifacts_dir = self.dir / "artifacts"
        self.manifest_path = self.dir / "manifest.json"
        if self.manifest_path.exists():
            self._load_existing()

    @property
    def manifest(self) -> dict:
        records = []
        for record in self.records:
            record_dict = asdict(record)
            records.append({key: value for key, value in record_dict.items() if value is not None})
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "records": records,
        }

    def _load_existing(self) -> None:
        try:
            doc = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ResultError.internal(
                f"evidence manifest unreadable: {self.manifest_path}: {exc}"
            ) from None
        errors = validate(doc, SCHEMA)
        if errors:
            raise ResultError.internal(
                f"evidence manifest failed validation: {self.manifest_path}", details=errors
            )
        self.records = [EvidenceRecord(**record) for record in doc["records"]]

    def add_bytes(
        self,
        *,
        logical_name: str,
        data: bytes,
        stage: str,
        tool: str | None = None,
        tool_version: str | None = None,
        provenance: dict | None = None,
    ) -> EvidenceRecord:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        stored_name = self._collision_free_name(logical_name)
        artifact_path = self.artifacts_dir / stored_name
        atomic_write_bytes(artifact_path, data)
        record = EvidenceRecord(
            logical_name=logical_name,
            artifact_path=str(artifact_path.relative_to(self.dir)),
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            stage=stage,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool=tool,
            tool_version=tool_version,
            provenance=provenance,
        )
        self.records.append(record)
        self._save_manifest()
        return record

    def add_file(
        self,
        *,
        logical_name: str,
        source: Path,
        stage: str,
        tool: str | None = None,
        tool_version: str | None = None,
    ) -> EvidenceRecord:
        source_bytes = source.read_bytes()
        provenance = {
            "source_path": str(source),
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        }
        return self.add_bytes(
            logical_name=logical_name,
            data=source_bytes,
            stage=stage,
            tool=tool,
            tool_version=tool_version,
            provenance=provenance,
        )

    def _collision_free_name(self, logical_name: str) -> str:
        candidate = logical_name
        counter = 1
        while (self.artifacts_dir / candidate).exists():
            stem, suffix = os.path.splitext(logical_name)
            candidate = f"{stem}-{counter}{suffix}"
            counter += 1
        return candidate

    def _save_manifest(self) -> None:
        text = json.dumps(self.manifest, sort_keys=True, indent=2)
        atomic_write_text(self.manifest_path, text)


def load_evidence(manifest_path: str | Path) -> EvidenceDir:
    path = Path(manifest_path)
    return EvidenceDir(base_dir=path.parent.parent, run_id=path.parent.name)
