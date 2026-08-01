"""Validated imports into the persistent RE index."""

from __future__ import annotations

from typing import Any

from retoolkit.contracts.result import ResultError

from .store import ReIndex


def import_method_map(
    index: ReIndex,
    document: dict[str, Any],
    *,
    run_id: str,
    profile_name: str,
    input_hash: str,
    binary_path: str,
    binary_sha256: str,
    method_map_sha256: str,
) -> int:
    """Insert a normalized method map once, retaining same-identity RVA collisions."""
    methods = document.get("methods")
    if not isinstance(methods, list) or document.get("method_count") != len(methods):
        raise ResultError.validation("normalized method map count mismatch")
    if not all(isinstance(method, dict) for method in methods):
        raise ResultError.validation("normalized method map contains invalid entries")

    with index.transaction():
        index.ensure_run(run_id, profile_name, input_hash)
        binary_id = index.ensure_binary(binary_sha256, binary_path)
        existing = index.find_method_map(binary_id, method_map_sha256)
        if existing is not None:
            return existing
        map_id = index.insert_method_map(binary_id, method_map_sha256, len(methods))
        index.insert_methods(map_id, methods)
        return map_id
