"""Deterministic, injection-safe RE index target queries."""

from __future__ import annotations

from .models import MethodRecord, TargetQuery
from .store import ReIndex


def parse_identity(text: str) -> TargetQuery:
    """Validate an exact stored identity and return its bounded query form."""
    assembly, separator, signature = text.partition("!")
    if not assembly or not separator or not signature:
        raise ValueError("identity must be '<assembly>!<signature>'")
    return TargetQuery(identity=text)


def resolve(index: ReIndex, query: TargetQuery) -> list[MethodRecord]:
    """Return indexed methods matching all supplied selectors in stable order."""
    clauses: list[str] = []
    values: list[object] = []

    _append_exact(clauses, values, "assembly", query.assembly)
    if query.namespace is not None:
        clauses.append("type_name LIKE ? ESCAPE '\\'")
        values.append(_prefix_like(query.namespace))
    _append_like(clauses, values, "type_name", query.type_pattern)
    _append_like(clauses, values, "method_name", query.method_pattern)
    _append_exact(clauses, values, "full_identity", query.identity)
    _append_exact(clauses, values, "rva", query.rva)

    sql = (
        "SELECT id, assembly, type_name, method_name, signature, rva, pointer, collision_key "
        "FROM methods"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY assembly, type_name, signature, rva LIMIT ?"
    values.append(query.limit)
    return [MethodRecord(**dict(row)) for row in index.query(sql, values)]


def _append_exact(
    clauses: list[str], values: list[object], column: str, value: object | None
) -> None:
    if value is not None:
        clauses.append(f"{column} = ?")
        values.append(value)


def _append_like(
    clauses: list[str], values: list[object], column: str, pattern: str | None
) -> None:
    if pattern is not None:
        clauses.append(f"{column} LIKE ? ESCAPE '\\'")
        values.append(_like(pattern))


def _prefix_like(prefix: str) -> str:
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}.%"


def _like(pattern: str) -> str:
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%").replace("?", "_")