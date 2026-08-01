"""RE index typed-record and schema contract tests."""

import pytest

from retoolkit.re_index.models import MethodRecord, TargetQuery
from retoolkit.re_index.schema import MIGRATIONS, SCHEMA_VERSION


def test_schema_v1_contains_required_tables() -> None:
    sql = "\n".join(MIGRATIONS[1])
    for table in (
        "runs",
        "tools",
        "binaries",
        "method_maps",
        "methods",
        "targets",
        "artifacts",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
    assert SCHEMA_VERSION == 2


def test_target_query_rejects_empty_selector() -> None:
    with pytest.raises(ValueError, match="at least one selector"):
        TargetQuery()


def test_method_record_preserves_collision_key() -> None:
    method = MethodRecord(
        1,
        "Assembly-CSharp",
        "N.T",
        "M",
        "System.Void N.T::M()",
        0x1234,
        0x180001234,
        "id#0",
    )
    assert method.rva == 0x1234
    assert method.collision_key == "id#0"
