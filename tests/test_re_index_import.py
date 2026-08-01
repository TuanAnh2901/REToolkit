"""Method-map import coverage for the RE index."""

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.re_index.importers import import_method_map
from retoolkit.re_index.store import ReIndex


def _document() -> dict:
    return {
        "schema_version": "1.0.0",
        "method_count": 2,
        "methods": [
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
                "assembly": "A",
                "type": "N.T",
                "method": "M",
                "signature": "System.Void N.T::M()",
                "rva": "0x20",
                "pointer": "0x180000020",
                "full_identity": "A!System.Void N.T::M()",
            },
        ],
    }


def _import(index: ReIndex, document: dict) -> int:
    return import_method_map(
        index,
        document,
        run_id="r",
        profile_name="p",
        input_hash="i",
        binary_path="b.dll",
        binary_sha256="b" * 64,
        method_map_sha256="m" * 64,
    )


def test_import_is_idempotent_and_preserves_rva_collisions(tmp_path) -> None:
    document = _document()
    with ReIndex.open(tmp_path / "i.db") as index:
        first = _import(index, document)
        second = _import(index, document)
        assert first == second
        assert index.scalar("SELECT COUNT(*) FROM methods") == 2
        assert index.scalar(
            "SELECT COUNT(*) FROM methods WHERE collision_key = ?",
            ("A!System.Void N.T::M()#0x10",),
        ) == 1


def test_import_rejects_method_count_mismatch(tmp_path) -> None:
    document = _document()
    document["method_count"] = 1
    with ReIndex.open(tmp_path / "i.db") as index:
        with pytest.raises(ResultError, match="count mismatch"):
            _import(index, document)
