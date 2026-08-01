"""Task 9: capability discovery and doctor tests."""

import pytest

from retoolkit.core.capabilities import Capability, discover, report, require
from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate


def test_report_is_schema_valid() -> None:
    caps = [
        Capability(name="python", status="present", version="3.13.7", path="C:\\py.exe"),
        Capability(name="frida", status="missing"),
        Capability(name="ghidra", status="optional_missing"),
    ]
    doc = report(caps)
    assert validate(doc, "capability.schema.json") == []


def test_require_present_returns_capability() -> None:
    doc = report([Capability(name="frida", status="present", version="17.16.3")])
    assert require(doc, "frida")["version"] == "17.16.3"


def test_require_missing_raises_exit_2() -> None:
    doc = report([Capability(name="ghidra", status="missing")])
    with pytest.raises(ResultError) as exc:
        require(doc, "ghidra")
    assert exc.value.exit_code == 2
    assert "ghidra" in exc.value.message


def test_require_optional_missing_allowed() -> None:
    doc = report([Capability(name="ghidra", status="optional_missing")])
    assert require(doc, "ghidra", optional=True)["status"] == "optional_missing"


def test_cpp2il_probe_missing_for_nonexistent_path() -> None:
    from retoolkit.core.capabilities import probe_cpp2il

    assert probe_cpp2il(r"C:\no\such\cpp2il.exe").status == "missing"


def test_ghidra_probe_missing_for_nonexistent_root() -> None:
    from retoolkit.core.capabilities import probe_ghidra

    assert probe_ghidra(r"C:\no\such\ghidra").status == "optional_missing"


def test_discover_returns_all_seven() -> None:
    caps = discover()
    assert [c.name for c in caps] == [
        "python", "frida", "node", "dotnet", "cpp2il", "ghidra", "x64dbg",
    ]
    assert caps[0].status == "present"  # python always present
