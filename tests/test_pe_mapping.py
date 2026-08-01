from __future__ import annotations

import struct
from pathlib import Path

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.native import PeImage


def _synthetic_pe(*, image_base: int = 0x180000000) -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, image_base)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x400)
    return bytes(data)


@pytest.fixture
def pe_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.dll"
    path.write_bytes(_synthetic_pe())
    return path


def test_rva_file_offset_round_trip(pe_fixture: Path) -> None:
    image = PeImage.open(pe_fixture)
    assert image.image_base == 0x180000000
    assert image.rva_to_file_offset(0x1100) == 0x500
    assert image.file_offset_to_rva(0x500) == 0x1100
    assert image.rva_to_va(0x1100) == 0x180001100


def test_unmapped_rva_is_typed_validation_error(pe_fixture: Path) -> None:
    with pytest.raises(ResultError, match="RVA 0x900000 is outside mapped PE sections"):
        PeImage.open(pe_fixture).rva_to_file_offset(0x900000)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.__setitem__(slice(0, 2), b"NZ"), "signature is not MZ"),
        (
            lambda data: struct.pack_into("<H", data, 0x98, 0x10B),
            "is not PE32+",
        ),
        (
            lambda data: struct.pack_into("<I", data, 0x98 + 0xF0 + 16, 0x500),
            "raw data is truncated or outside the file",
        ),
        (
            lambda data: struct.pack_into(
                "<II", data, 0x98 + 0xF0 + 8, 0x100, 0xFFFFFFF0
            ),
            "virtual range overflows 32 bits",
        ),
    ],
)
def test_malformed_pe_is_typed_validation_error(
    tmp_path: Path, mutate, message: str
) -> None:
    data = bytearray(_synthetic_pe())
    mutate(data)
    path = tmp_path / "malformed.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match=message):
        PeImage.open(path)


def test_truncated_header_is_typed_validation_error(tmp_path: Path) -> None:
    path = tmp_path / "truncated.dll"
    path.write_bytes(b"MZ")
    with pytest.raises(ResultError, match="DOS header is truncated"):
        PeImage.open(path)


def test_short_pe32_plus_optional_header_is_rejected(tmp_path: Path) -> None:
    data = bytearray(_synthetic_pe())
    struct.pack_into("<H", data, 0x94, 64)
    path = tmp_path / "short-optional.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match=r"PE32\+ optional header is truncated"):
        PeImage.open(path)


def test_size_of_headers_outside_file_is_rejected(tmp_path: Path) -> None:
    data = bytearray(_synthetic_pe())
    struct.pack_into("<I", data, 0x98 + 60, 0x1000)
    path = tmp_path / "bad-size-of-headers.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match="SizeOfHeaders is outside the file"):
        PeImage.open(path)


def test_section_outside_size_of_image_is_rejected(tmp_path: Path) -> None:
    data = bytearray(_synthetic_pe())
    struct.pack_into("<I", data, 0x98 + 56, 0x1100)
    path = tmp_path / "bad-size-of-image.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match="exceeds SizeOfImage"):
        PeImage.open(path)


def test_overlapping_raw_sections_are_rejected(tmp_path: Path) -> None:
    data = bytearray(_synthetic_pe())
    struct.pack_into("<H", data, 0x86, 2)
    second = 0x98 + 0xF0 + 40
    data[second : second + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, second + 8, 0x200, 0x1800, 0x200, 0x500)
    path = tmp_path / "overlap.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match="raw sections .* overlap"):
        PeImage.open(path)


def test_virtual_only_bytes_have_no_file_mapping(tmp_path: Path) -> None:
    data = bytearray(_synthetic_pe())
    struct.pack_into("<I", data, 0x98 + 0xF0 + 8, 0x500)
    path = tmp_path / "virtual-tail.dll"
    path.write_bytes(data)
    with pytest.raises(ResultError, match="virtual-only section data"):
        PeImage.open(path).rva_to_file_offset(0x1450)


def test_rva_to_va_rejects_uint64_overflow(tmp_path: Path) -> None:
    path = tmp_path / "overflow.dll"
    path.write_bytes(_synthetic_pe(image_base=0xFFFFFFFFFFFFFFF0))
    with pytest.raises(ResultError, match="overflows 64 bits"):
        PeImage.open(path).rva_to_va(0x1100)
