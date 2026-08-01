"""Normalization of Cpp2IL method-pointer maps into a stable contract.

Full identity is assembly + type + signature (the signature already embeds
the declaring type and generic arity, matching the runtime resolver's
identity). Entries sort canonically by full identity; conflicting duplicate
full identities (same signature, different RVA) are reported, never silently
overwritten.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate

SCHEMA = "method_map.schema.json"
SCHEMA_VERSION = "1.0.0"
RVA_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class NormalizedMethod:
    assembly: str
    type: str
    method: str
    signature: str
    rva: str
    pointer: str | None
    full_identity: str


def normalize_map(raw: list[dict], *, collision_policy: str = "report") -> dict:
    """Normalize a Cpp2IL method-pointer-map array into the canonical form.

    collision_policy:
      "report"   - conflicting duplicate full identities raise (default)
      "keep_all" - retain every entry; duplicates stay distinguishable by rva
    """
    if collision_policy not in ("report", "keep_all"):
        raise ResultError.validation(
            f"unknown collision_policy {collision_policy!r}; use 'report' or 'keep_all'"
        )
    conflicts: list[dict] = []
    methods: list[NormalizedMethod] = []
    seen: dict[str, tuple[str, int]] = {}
    for index, entry in enumerate(raw):
        errors = _entry_errors(entry, index)
        if errors:
            raise ResultError.validation("method map contains malformed entries", details=errors[:10])
        identity = _full_identity(entry)
        rva = entry["rva"]
        if identity in seen and seen[identity][0] != rva:
            conflicts.append(
                {
                    "full_identity": identity,
                    "records": [
                        {"source_index": seen[identity][1], "rva": seen[identity][0]},
                        {"source_index": index, "rva": rva},
                    ],
                }
            )
            if collision_policy == "report":
                continue
        if identity not in seen or collision_policy == "keep_all":
            if identity not in seen:
                seen[identity] = (rva, index)
            methods.append(
                NormalizedMethod(
                    assembly=entry["assembly"],
                    type=entry["type"],
                    method=entry["method"],
                    signature=entry["signature"],
                    rva=rva,
                    pointer=entry.get("pointer"),
                    full_identity=identity,
                )
            )
    if conflicts and collision_policy == "report":
        raise ResultError.validation(
            "conflicting duplicate full identities in method map "
            "(retain all entries with collision_policy='keep_all' if intended)",
            details=conflicts[:10],
        )
    methods.sort(key=lambda method: method.full_identity)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "source": "method-pointer-map.json",
        "method_count": len(methods),
        "methods": [method.__dict__ for method in methods],
    }
    errors = validate(doc, SCHEMA)
    if errors:
        raise ResultError.internal("normalized method map failed schema validation", details=errors)
    return doc


def normalize_file(map_path: str | Path, *, collision_policy: str = "report") -> dict:
    path = Path(map_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise ResultError.validation(f"method map unreadable: {path}: {exc}") from None
    if not isinstance(raw, list):
        raise ResultError.validation(f"method map must be a JSON array, got {type(raw).__name__}")
    return normalize_map(raw, collision_policy=collision_policy)


def _full_identity(entry: dict) -> str:
    return f"{entry['assembly']}::{entry['signature']}"


def _entry_errors(entry: dict, index: int) -> list[str]:
    errors = []
    for key in ("assembly", "type", "method", "signature", "rva"):
        value = entry.get(key)
        if not isinstance(value, str) or not value:
            errors.append(f"methods[{index}].{key}: missing or empty")
    if "rva" in entry and not RVA_RE.match(str(entry.get("rva", ""))):
        errors.append(f"methods[{index}].rva: not a 0x-prefixed hex string")
    return errors
