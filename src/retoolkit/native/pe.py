"""Strict, dependency-free PE32+ address mapping."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from retoolkit.contracts.result import ResultError

_UINT32_LIMIT = 1 << 32
_UINT64_MAX = (1 << 64) - 1


def _validation(message: str, *, path: Path) -> ResultError:
    return ResultError.validation(message, details={"path": str(path)})


def _require_range(data: bytes, offset: int, size: int, label: str, path: Path) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise _validation(f"{label} is truncated or outside the file", path=path)


@dataclass(frozen=True)
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(
            self.virtual_size, self.raw_size
        )

    def contains_file_offset(self, offset: int) -> bool:
        return self.raw_offset <= offset < self.raw_offset + self.raw_size


@dataclass(frozen=True)
class PeImage:
    path: Path
    image_base: int
    machine: int
    sections: tuple[PeSection, ...]

    @classmethod
    def open(cls, path: Path) -> "PeImage":
        path = Path(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise _validation(f"could not read PE file: {exc}", path=path) from exc

        _require_range(data, 0, 0x40, "DOS header", path)
        if data[:2] != b"MZ":
            raise _validation("DOS header signature is not MZ", path=path)
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        _require_range(data, pe_offset, 24, "PE/COFF header", path)
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise _validation("PE signature is invalid", path=path)

        machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", data, pe_offset + 4
        )
        if machine != 0x8664:
            raise _validation(f"PE machine 0x{machine:x} is not AMD64", path=path)
        if section_count == 0:
            raise _validation("PE has no sections", path=path)

        optional_offset = pe_offset + 24
        _require_range(data, optional_offset, optional_size, "PE optional header", path)
        if optional_size < 112:
            raise _validation("PE32+ optional header is truncated", path=path)
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        if magic != 0x20B:
            raise _validation(f"optional header magic 0x{magic:x} is not PE32+", path=path)
        image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
        size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        if size_of_headers == 0 or size_of_headers > len(data):
            raise _validation("SizeOfHeaders is outside the file", path=path)

        section_offset = optional_offset + optional_size
        table_size = section_count * 40
        _require_range(data, section_offset, table_size, "section table", path)
        if section_offset + table_size > size_of_headers:
            raise _validation("SizeOfHeaders does not cover the section table", path=path)
        sections: list[PeSection] = []
        for index in range(section_count):
            offset = section_offset + index * 40
            raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise _validation(f"section {index} name is not ASCII", path=path) from exc
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, offset + 8
            )
            mapped_size = max(virtual_size, raw_size)
            if virtual_address + mapped_size > _UINT32_LIMIT:
                raise _validation(f"section {name!r} virtual range overflows 32 bits", path=path)
            if mapped_size and virtual_address + mapped_size > size_of_image:
                raise _validation(f"section {name!r} exceeds SizeOfImage", path=path)
            if raw_offset + raw_size > _UINT32_LIMIT:
                raise _validation(f"section {name!r} raw range overflows 32 bits", path=path)
            if raw_size:
                _require_range(data, raw_offset, raw_size, f"section {name!r} raw data", path)
            sections.append(PeSection(name, virtual_address, virtual_size, raw_offset, raw_size))

        _reject_overlaps(sections, path)
        return cls(path=path, image_base=image_base, machine=machine, sections=tuple(sections))

    def rva_to_file_offset(self, rva: int) -> int:
        if not isinstance(rva, int) or isinstance(rva, bool) or not 0 <= rva < _UINT32_LIMIT:
            raise ResultError.validation(f"RVA {rva!r} is outside the 32-bit address space")
        for section in self.sections:
            if section.contains_rva(rva):
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise ResultError.validation(
                        f"RVA 0x{rva:x} is in virtual-only section data",
                        details={"path": str(self.path), "section": section.name},
                    )
                return section.raw_offset + delta
        raise ResultError.validation(
            f"RVA 0x{rva:x} is outside mapped PE sections",
            details={"path": str(self.path)},
        )

    def file_offset_to_rva(self, offset: int) -> int:
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ResultError.validation(f"file offset {offset!r} must be a non-negative integer")
        for section in self.sections:
            if section.contains_file_offset(offset):
                return section.virtual_address + (offset - section.raw_offset)
        raise ResultError.validation(
            f"file offset 0x{offset:x} is outside mapped PE sections",
            details={"path": str(self.path)},
        )

    def rva_to_va(self, rva: int) -> int:
        if not isinstance(rva, int) or isinstance(rva, bool) or not 0 <= rva < _UINT32_LIMIT:
            raise ResultError.validation(f"RVA {rva!r} is outside the 32-bit address space")
        if self.image_base > _UINT64_MAX - rva:
            raise ResultError.validation(f"VA for RVA 0x{rva:x} overflows 64 bits")
        return self.image_base + rva


def _reject_overlaps(sections: list[PeSection], path: Path) -> None:
    raw = sorted((s.raw_offset, s.raw_offset + s.raw_size, s.name) for s in sections if s.raw_size)
    for (_, previous_end, previous_name), (start, _, name) in zip(raw, raw[1:]):
        if start < previous_end:
            raise _validation(
                f"raw sections {previous_name!r} and {name!r} overlap", path=path
            )
