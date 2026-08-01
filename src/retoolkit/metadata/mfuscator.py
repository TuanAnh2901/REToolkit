"""Config-driven Mfuscator metadata fixup: rebuilds a custom obfuscated
header into a standard IL2CPP v31 file.

All game-specific values (key, field positions, biases, mutations, section
rules) come from the profile's metadata_fixup data, validated against
metadata_fixup.schema.json. This module contains only the generic transform
engine.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.metadata.mfuscator_contract import (
    MfuscatorContract,
    MutationContract,
    PayloadTransformContract,
    SectionContract,
)
from retoolkit.metadata.mfuscator_validate import ValidationReport, validate_candidate
from retoolkit.metadata.xxtea import decrypt_header

SCHEMA = "metadata_fixup.schema.json"


@dataclass
class PayloadTransform:
    initial: int
    step: int


@dataclass
class SectionRule:
    index: int
    name: str
    custom_offset_field: int
    custom_size_field: int
    payload_transform: PayloadTransform | None = None


@dataclass
class Mutation:
    kind: str
    a: int | None = None
    b: int | None = None
    offset: int | None = None
    value: int | None = None


@dataclass
class FixupConfig:
    header_prefix: bytes
    header_offset: int
    header_length: int
    payload_start: int
    preserved_tail_start: int
    source_bias: int
    metadata_magic: int
    metadata_version: int
    xxtea_key: bytes
    mutations: list[Mutation] = field(default_factory=list)
    sections: list[SectionRule] = field(default_factory=list)
    known_good_hash: str | None = None

    @classmethod
    def from_doc(cls, doc: dict) -> "FixupConfig":
        errors = validate(doc, SCHEMA)
        if errors:
            raise ResultError.validation(
                "metadata fixup configuration failed validation", details=errors
            )
        sections = []
        for section in doc["sections"]:
            transform = None
            if section.get("payload_transform"):
                transform = PayloadTransform(**section["payload_transform"])
            sections.append(
                SectionRule(
                    index=section["index"],
                    name=section["name"],
                    custom_offset_field=section["custom_offset_field"],
                    custom_size_field=section["custom_size_field"],
                    payload_transform=transform,
                )
            )
        return cls(
            header_prefix=bytes.fromhex(doc["header_prefix"]),
            header_offset=doc["header_offset"],
            header_length=doc["header_length"],
            payload_start=doc["payload_start"],
            preserved_tail_start=doc["preserved_tail_start"],
            source_bias=doc["source_bias"],
            metadata_magic=doc["metadata_magic"],
            metadata_version=doc["metadata_version"],
            xxtea_key=doc["xxtea_key"].encode("ascii"),
            mutations=[Mutation(**mutation) for mutation in doc.get("mutations", [])],
            sections=sections,
            known_good_hash=doc.get("known_good_hash"),
        )

    @classmethod
    def from_profile(cls, profile_raw: dict) -> "FixupConfig":
        try:
            doc = profile_raw["metadata_fixup"]
        except KeyError:
            raise ResultError.validation("profile has no metadata_fixup section") from None
        return cls.from_doc(doc)

    def to_contract(self, *, name: str = "profile") -> MfuscatorContract:
        ordered_sections = sorted(self.sections, key=lambda section: section.index)
        return MfuscatorContract(
            name=name,
            metadata_magic=self.metadata_magic,
            metadata_version=self.metadata_version,
            header_prefix=self.header_prefix,
            header_offset=self.header_offset,
            header_length=self.header_length,
            payload_start=self.payload_start,
            preserved_tail_start=self.preserved_tail_start,
            source_bias=self.source_bias,
            xxtea_key=self.xxtea_key,
            mutations=tuple(
                MutationContract(
                    kind=mutation.kind,
                    a=mutation.a,
                    b=mutation.b,
                    offset=mutation.offset,
                    value=mutation.value,
                )
                for mutation in self.mutations
            ),
            sections=tuple(
                SectionContract(
                    name=section.name,
                    custom_offset_field=section.custom_offset_field,
                    custom_size_field=section.custom_size_field,
                    payload_transform=(
                        PayloadTransformContract(
                            initial=section.payload_transform.initial,
                            step=section.payload_transform.step,
                        )
                        if section.payload_transform is not None
                        else None
                    ),
                )
                for section in ordered_sections
            ),
        )


def _u32(buffer: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buffer, offset)[0]


def _apply_mutations(header: bytearray, mutations: list[Mutation]) -> None:
    for mutation in mutations:
        if mutation.kind == "swap":
            header[mutation.a], header[mutation.b] = header[mutation.b], header[mutation.a]
        elif mutation.kind == "xor":
            header[mutation.offset] ^= mutation.value
        else:  # pragma: no cover - schema restricts kinds
            raise ValueError(f"unknown mutation kind {mutation.kind}")


def _apply_contract_mutations(
    header: bytearray, mutations: tuple[MutationContract, ...]
) -> None:
    for mutation in mutations:
        if mutation.kind == "swap":
            if mutation.a is None or mutation.b is None:
                raise ResultError.validation("swap mutation is missing a or b")
            header[mutation.a], header[mutation.b] = header[mutation.b], header[mutation.a]
        elif mutation.kind == "xor":
            if mutation.offset is None or mutation.value is None:
                raise ResultError.validation("xor mutation is missing offset or value")
            header[mutation.offset] ^= mutation.value
        else:
            raise ResultError.validation(f"unknown mutation kind {mutation.kind}")


def rebuild_with_report(
    data: bytes, contract: MfuscatorContract
) -> tuple[bytes, ValidationReport]:
    """Rebuild metadata through an explicit loader contract and validate it."""
    if not data.startswith(contract.header_prefix):
        raise ResultError.validation(
            f"input is not an obfuscated metadata file (missing prefix "
            f"{contract.header_prefix.hex()})"
        )
    header_end = contract.header_offset + contract.header_length
    if len(data) < header_end:
        raise ResultError.validation(
            f"input truncated: {len(data)} bytes, need at least {header_end}"
        )

    encrypted = data[contract.header_offset:header_end]
    try:
        decrypted = bytearray(decrypt_header(encrypted, contract.xxtea_key))
    except ValueError as exc:
        raise ResultError.validation(f"header decrypt failed: {exc}") from None
    _apply_contract_mutations(decrypted, contract.mutations)

    descriptors: list[tuple[int, int]] = []
    for section in contract.sections:
        if section.custom_offset_field + 4 > len(decrypted) or section.custom_size_field + 4 > len(decrypted):
            raise ResultError.validation(
                f"section {section.name}: field offsets out of bounds for decrypted header"
            )
        offset = _u32(decrypted, section.custom_offset_field) + contract.source_bias
        size = _u32(decrypted, section.custom_size_field)
        descriptors.append((offset, size))

    report = validate_candidate(data, contract, descriptors)
    if not report.accepted:
        errors = [
            {
                "code": finding.code,
                "section": finding.section,
                "message": finding.message,
            }
            for finding in report.findings
            if finding.severity == "error"
        ]
        raise ResultError.validation(
            "metadata candidate failed structural validation", details=errors
        )

    standard_header = bytearray(
        struct.pack("<II", contract.metadata_magic, contract.metadata_version)
    )
    for offset, size in descriptors:
        standard_header += struct.pack("<II", offset, size)

    payload = bytearray(data[contract.payload_start:])
    for section, (offset, size) in zip(contract.sections, descriptors):
        if section.payload_transform is None:
            continue
        relative = offset - contract.payload_start
        if relative < 0 or relative + size > len(payload):
            raise ResultError.validation(
                f"section {section.name} lies before the payload region"
            )
        transform = section.payload_transform
        for index in range(size):
            payload[relative + index] ^= (transform.initial + transform.step * index) & 0xFF

    rebuilt = (
        bytes(standard_header)
        + data[contract.preserved_tail_start : contract.payload_start]
        + bytes(payload)
    )
    return rebuilt, report


def rebuild_metadata(
    data: bytes, config: FixupConfig | MfuscatorContract
) -> bytes:
    """Rebuild obfuscated metadata into a standard header + payload file."""
    try:
        contract = config if isinstance(config, MfuscatorContract) else config.to_contract()
    except ValueError as exc:
        raise ResultError.validation(f"metadata contract is invalid: {exc}") from None
    rebuilt, _ = rebuild_with_report(data, contract)
    return rebuilt


def rebuild_file(input_path: Path, output_path: Path, config: FixupConfig) -> dict:
    """Rebuild one metadata file and report artifact metadata."""
    data = input_path.read_bytes()
    rebuilt = rebuild_metadata(data, config)
    output_path.write_bytes(rebuilt)
    return {
        "input_size": len(data),
        "output_size": len(rebuilt),
        "sha256": hashlib.sha256(rebuilt).hexdigest(),
        "matches_known_good": config.known_good_hash == hashlib.sha256(rebuilt).hexdigest(),
    }
