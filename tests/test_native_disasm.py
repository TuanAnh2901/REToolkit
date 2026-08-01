from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.native import NativeAnalyzer, findings_document
from retoolkit.re_index import MethodRecord


def _synthetic_pe() -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x180000000)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x400)
    return bytes(data)


def _native_fixture(tmp_path: Path) -> Path:
    data = bytearray(_synthetic_pe())
    # 0x1100: call 0x1200; jne 0x1117; lea rax,[rip+0x1f2] -> 0x1300;
    # mov eax,0x12345678; ret
    data[0x500:0x513] = bytes.fromhex(
        "e8 fb 00 00 00 75 10 48 8d 05 f2 01 00 00 b8 78 56 34 12 c3"
    )
    data[0x700:0x70E] = b"reward-token\0"
    path = tmp_path / "native.dll"
    path.write_bytes(data)
    return path


def _target() -> MethodRecord:
    return MethodRecord(1, "Assembly", "N.T", "M", "sig", 0x1100, None, "key")


def test_analyzer_extracts_direct_call_branch_and_rip_reference(tmp_path: Path) -> None:
    pytest.importorskip("iced_x86")
    finding = NativeAnalyzer(window_bytes=96).analyze(_native_fixture(tmp_path), [_target()])[0]

    assert finding.status == "decoded"
    assert finding.entry_rva == 0x1100
    assert 0x1200 in finding.direct_calls
    assert finding.conditional_branches == (0x1117,)
    assert finding.rip_references == (0x1300,)
    assert 0x12345678 in finding.immediates
    assert finding.strings == ("reward-token",)
    assert [row["address"] for row in finding.instructions] == sorted(
        row["address"] for row in finding.instructions
    )


def test_missing_decoder_is_typed_capability_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import retoolkit.native.disasm as disasm

    monkeypatch.setattr(disasm, "_load_iced_x86", lambda: None)
    finding = NativeAnalyzer(window_bytes=32).analyze(_native_fixture(tmp_path), [_target()])[0]

    assert finding.status == "decoder_unavailable"
    assert finding.entry_rva == 0x1100
    assert len(finding.bytes_sha256) == 64
    assert finding.instructions == ()


def test_findings_document_is_deterministic_and_schema_valid(tmp_path: Path) -> None:
    import retoolkit.native.disasm as disasm

    analyzer = NativeAnalyzer(window_bytes=32)
    binary = _native_fixture(tmp_path)
    original_loader = disasm._load_iced_x86
    try:
        disasm._load_iced_x86 = lambda: None
        findings = analyzer.analyze(binary, [_target()])
    finally:
        disasm._load_iced_x86 = original_loader

    document = findings_document(findings)
    assert validate(document, "native_findings.schema.json") == []
    assert json.dumps(document, sort_keys=True, separators=(",", ":")) == json.dumps(
        findings_document(findings), sort_keys=True, separators=(",", ":")
    )


@pytest.mark.parametrize("window_bytes", [0, -1, True])
def test_window_size_is_typed_validation_error(window_bytes: int) -> None:
    with pytest.raises(ResultError, match="window_bytes must be a positive integer"):
        NativeAnalyzer(window_bytes=window_bytes)
