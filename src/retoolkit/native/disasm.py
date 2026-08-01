"""Bounded x86-64 instruction and reference extraction."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.re_index import MethodRecord

from .models import StaticFinding
from .pe import PeImage, PeSection


def _load_iced_x86() -> Any | None:
    try:
        import iced_x86
    except ImportError:
        return None
    return iced_x86


class NativeAnalyzer:
    def __init__(self, *, window_bytes: int = 256) -> None:
        if (
            not isinstance(window_bytes, int)
            or isinstance(window_bytes, bool)
            or window_bytes <= 0
        ):
            raise ResultError.validation("window_bytes must be a positive integer")
        self.window_bytes = window_bytes

    def analyze(self, binary: Path, targets: list[MethodRecord]) -> list[StaticFinding]:
        image = PeImage.open(binary)
        decoder = _load_iced_x86()
        data = image.path.read_bytes()
        return [
            _analyze_one(image, data, decoder, target, self.window_bytes)
            for target in targets
        ]


def findings_document(findings: list[StaticFinding]) -> dict[str, Any]:
    document = {
        "schema_version": "1.0",
        "findings": [
            finding.to_dict()
            for finding in sorted(findings, key=lambda item: (item.entry_rva, item.method_id))
        ],
    }
    errors = validate(document, "native_findings.schema.json")
    if errors:
        raise ResultError.internal(
            "native findings failed schema validation", details={"errors": errors}
        )
    return document


def _analyze_one(
    image: PeImage,
    data: bytes,
    iced: Any | None,
    target: MethodRecord,
    window_bytes: int,
) -> StaticFinding:
    file_offset = image.rva_to_file_offset(target.rva)
    section = _section_for_rva(image, target.rva)
    available = section.raw_size - (target.rva - section.virtual_address)
    code = data[file_offset : file_offset + min(window_bytes, available)]
    digest = hashlib.sha256(code).hexdigest()
    if iced is None:
        return StaticFinding(
            method_id=target.id,
            entry_rva=target.rva,
            bytes_sha256=digest,
            instructions=(),
            direct_calls=(),
            conditional_branches=(),
            rip_references=(),
            immediates=(),
            strings=(),
            status="decoder_unavailable",
        )

    formatter = iced.Formatter(iced.FormatterSyntax.INTEL)
    decoder = iced.Decoder(64, code, ip=image.rva_to_va(target.rva))
    instructions: list[dict[str, Any]] = []
    direct_calls: set[int] = set()
    conditional_branches: set[int] = set()
    rip_references: set[int] = set()
    immediates: set[int] = set()

    for instruction in decoder:
        if instruction.code == iced.Code.INVALID:
            break
        rva = _va_to_rva(image, instruction.ip)
        encoded = code[rva - target.rva : rva - target.rva + instruction.len]
        instructions.append(
            {
                "address": instruction.ip,
                "rva": rva,
                "bytes": encoded.hex(),
                "mnemonic": str(instruction).split()[0].lower(),
                "text": formatter.format(instruction),
            }
        )
        if instruction.flow_control == iced.FlowControl.CALL:
            call_rva = _mapped_va_to_rva(image, instruction.near_branch_target)
            if call_rva is not None:
                direct_calls.add(call_rva)
        elif instruction.flow_control == iced.FlowControl.CONDITIONAL_BRANCH:
            branch_rva = _mapped_va_to_rva(image, instruction.near_branch_target)
            if branch_rva is not None:
                conditional_branches.add(branch_rva)
        if instruction.is_ip_rel_memory_operand:
            reference_rva = _mapped_va_to_rva(image, instruction.ip_rel_memory_address)
            if reference_rva is not None:
                rip_references.add(reference_rva)
        for operand_index in range(instruction.op_count):
            if instruction.op_kind(operand_index) in _immediate_kinds(iced):
                immediates.add(instruction.immediate(operand_index))

    strings = {
        value
        for rva in rip_references
        if (value := _read_ascii_string(image, data, rva)) is not None
    }
    return StaticFinding(
        method_id=target.id,
        entry_rva=target.rva,
        bytes_sha256=digest,
        instructions=tuple(sorted(instructions, key=lambda row: int(row["address"]))),
        direct_calls=tuple(sorted(direct_calls)),
        conditional_branches=tuple(sorted(conditional_branches)),
        rip_references=tuple(sorted(rip_references)),
        immediates=tuple(sorted(immediates)),
        strings=tuple(sorted(strings)),
        status="decoded",
    )


def _section_for_rva(image: PeImage, rva: int) -> PeSection:
    for section in image.sections:
        if section.contains_rva(rva):
            return section
    raise ResultError.validation(f"RVA 0x{rva:x} is outside mapped PE sections")


def _va_to_rva(image: PeImage, va: int) -> int:
    if va < image.image_base:
        raise ResultError.validation(f"VA 0x{va:x} is below the PE image base")
    return va - image.image_base


def _mapped_va_to_rva(image: PeImage, va: int) -> int | None:
    if va < image.image_base:
        return None
    rva = va - image.image_base
    if any(section.contains_rva(rva) for section in image.sections):
        return rva
    return None


def _immediate_kinds(iced: Any) -> frozenset[int]:
    return frozenset(
        {
            iced.OpKind.IMMEDIATE8,
            iced.OpKind.IMMEDIATE8_2ND,
            iced.OpKind.IMMEDIATE16,
            iced.OpKind.IMMEDIATE32,
            iced.OpKind.IMMEDIATE64,
            iced.OpKind.IMMEDIATE8TO16,
            iced.OpKind.IMMEDIATE8TO32,
            iced.OpKind.IMMEDIATE8TO64,
            iced.OpKind.IMMEDIATE32TO64,
        }
    )


def _read_ascii_string(image: PeImage, data: bytes, rva: int) -> str | None:
    try:
        offset = image.rva_to_file_offset(rva)
    except ResultError:
        return None
    raw = data[offset : offset + 256]
    end = raw.find(b"\0")
    if end < 4:
        return None
    candidate = raw[:end]
    if not all(0x20 <= byte <= 0x7E for byte in candidate):
        return None
    return candidate.decode("ascii")
