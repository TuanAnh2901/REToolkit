"""Deterministic, injection-safe RE index target query coverage."""

from __future__ import annotations

import pytest

from retoolkit.re_index.importers import import_method_map
from retoolkit.re_index.models import TargetQuery
from retoolkit.re_index.query import parse_identity, resolve
from retoolkit.re_index.store import ReIndex


@pytest.fixture
def index_fixture(tmp_path) -> ReIndex:
    document = {
        "schema_version": "1.0.0",
        "method_count": 3,
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
            {
                "assembly": "B",
                "type": "N.Two",
                "method": "GetValue",
                "signature": "System.Int32 N.Two::GetValue()",
                "rva": "0x30",
                "pointer": "0x180000030",
                "full_identity": "B!System.Int32 N.Two::GetValue()",
            },
        ],
    }
    index = ReIndex.open(tmp_path / "query.db")
    import_method_map(
        index,
        document,
        run_id="r",
        profile_name="p",
        input_hash="i",
        binary_path="b.dll",
        binary_sha256="b" * 64,
        method_map_sha256="m" * 64,
    )
    try:
        yield index
    finally:
        index.connection.close()


@pytest.mark.parametrize(
    ("query", "expected_rvas"),
    [
        (TargetQuery(identity="A!System.Void N.T::M()"), [0x10, 0x20]),
        (TargetQuery(type_pattern="N.*", method_pattern="M"), [0x10, 0x20]),
        (TargetQuery(namespace="N", method_pattern="Get*"), [0x30]),
        (TargetQuery(rva=0x20), [0x20]),
    ],
)
def test_resolve_filters_and_orders(index_fixture: ReIndex, query: TargetQuery, expected_rvas: list[int]) -> None:
    assert [item.rva for item in resolve(index_fixture, query)] == expected_rvas


def test_resolve_escapes_sql_wildcards_and_never_executes_query_text(index_fixture: ReIndex) -> None:
    result = resolve(index_fixture, TargetQuery(method_pattern="M%' OR 1=1 --"))
    assert result == []
    assert index_fixture.scalar("SELECT COUNT(*) FROM methods") == 3


def test_resolve_honors_limit_after_stable_ordering(index_fixture: ReIndex) -> None:
    result = resolve(index_fixture, TargetQuery(identity="A!System.Void N.T::M()", limit=1))
    assert [item.rva for item in result] == [0x10]


def test_parse_identity_requires_assembly_and_signature() -> None:
    assert parse_identity("A!System.Void N.T::M()") == TargetQuery(
        identity="A!System.Void N.T::M()"
    )
    with pytest.raises(ValueError, match="identity"):
        parse_identity("not-an-identity")
def test_namespace_is_an_exact_prefix_not_a_wildcard(index_fixture: ReIndex) -> None:
    assert resolve(index_fixture, TargetQuery(namespace="N*")) == []


def test_assembly_selector_filters_methods(index_fixture: ReIndex) -> None:
    assert [item.rva for item in resolve(index_fixture, TargetQuery(assembly="B"))] == [0x30]


def test_query_returns_row_shaped_results(index_fixture: ReIndex) -> None:
    rows = index_fixture.query("SELECT rva FROM methods WHERE rva = ?", (0x20,))
    assert [row["rva"] for row in rows] == [0x20]
