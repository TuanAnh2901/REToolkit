"""Task 16: method-map normalization tests."""

import hashlib
import json
from pathlib import Path

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.normalizers.method_map import normalize_file, normalize_map

FIXTURE = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "cpp2il" / "method-map-sample.json").read_text(encoding="utf-8")
)


def test_normalizes_sample_fixture_deterministically() -> None:
    first = normalize_map(FIXTURE)
    second = normalize_map(FIXTURE)
    assert hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest() == (
        hashlib.sha256(json.dumps(second, sort_keys=True).encode()).hexdigest()
    )
    assert first["method_count"] == 3
    assert validate(first, "method_map.schema.json") == []


def test_duplicate_short_names_remain_distinguishable() -> None:
    raw = [
        {"assembly": "A", "type": "Ns1.Foo", "method": "Bar",
         "signature": "System.Void Ns1.Foo::Bar()", "pointer": "0x1", "rva": "0x1"},
        {"assembly": "A", "type": "Ns2.Foo", "method": "Bar",
         "signature": "System.Void Ns2.Foo::Bar()", "pointer": "0x2", "rva": "0x2"},
    ]
    doc = normalize_map(raw)
    identities = [m["full_identity"] for m in doc["methods"]]
    assert len(set(identities)) == 2
    assert identities == sorted(identities)


def test_conflicting_full_identity_reported_not_overwritten() -> None:
    raw = [
        {"assembly": "A", "type": "Ns.Foo", "method": "Bar",
         "signature": "System.Void Ns.Foo::Bar()", "pointer": "0x1", "rva": "0x1"},
        {"assembly": "A", "type": "Ns.Foo", "method": "Bar",
         "signature": "System.Void Ns.Foo::Bar()", "pointer": "0x2", "rva": "0x2"},
    ]
    with pytest.raises(ResultError) as exc:
        normalize_map(raw)
    assert exc.value.exit_code == 1
    details = json.dumps(exc.value.details)
    assert '"0x1"' in details and '"0x2"' in details


def test_exact_duplicate_is_deduplicated() -> None:
    entry = {"assembly": "A", "type": "Ns.Foo", "method": "Bar",
             "signature": "System.Void Ns.Foo::Bar()", "pointer": "0x1", "rva": "0x1"}
    doc = normalize_map([entry, dict(entry)])
    assert doc["method_count"] == 1


def test_malformed_rva_rejected() -> None:
    raw = [{"assembly": "A", "type": "T", "method": "M",
            "signature": "System.Void T::M()", "rva": "not-hex"}]
    with pytest.raises(ResultError):
        normalize_map(raw)


def test_missing_field_rejected() -> None:
    raw = [{"assembly": "A", "type": "T", "method": "M", "rva": "0x1"}]
    with pytest.raises(ResultError):
        normalize_map(raw)


def test_normalize_file_roundtrip(tmp_path) -> None:
    source = tmp_path / "map.json"
    source.write_text(json.dumps(FIXTURE), encoding="utf-8")
    doc = normalize_file(source)
    assert doc["method_count"] == 3


def test_normalize_file_rejects_non_array(tmp_path) -> None:
    source = tmp_path / "map.json"
    source.write_text('{"not": "an array"}', encoding="utf-8")
    with pytest.raises(ResultError):
        normalize_file(source)
