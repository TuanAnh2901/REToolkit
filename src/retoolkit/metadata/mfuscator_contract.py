"""Serializable contracts describing a Mfuscator metadata loader layout."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Literal


@dataclass(frozen=True)
class PayloadTransformContract:
    initial: int
    step: int


@dataclass(frozen=True)
class MutationContract:
    kind: str
    a: int | None = None
    b: int | None = None
    offset: int | None = None
    value: int | None = None


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    value: int | str
    support: int = 1
    confidence: Literal["confirmed", "inferred"] = "inferred"


@dataclass(frozen=True)
class ExportAlias:
    canonical: str
    alias: str
    return_type: str
    parameters: str


@dataclass(frozen=True)
class SectionContract:
    name: str
    custom_offset_field: int
    custom_size_field: int
    record_size: int | None = None
    alignment: int = 4
    payload_transform: PayloadTransformContract | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("section name is empty")
        if self.custom_offset_field < 0 or self.custom_size_field < 0:
            raise ValueError(f"section {self.name}: negative header field offset")
        if self.record_size is not None and self.record_size <= 0:
            raise ValueError(f"section {self.name}: record_size must be positive")
        if self.alignment <= 0:
            raise ValueError(f"section {self.name}: alignment must be positive")


@dataclass(frozen=True)
class MfuscatorContract:
    name: str
    metadata_magic: int
    metadata_version: int
    header_prefix: bytes
    header_offset: int
    header_length: int
    payload_start: int
    preserved_tail_start: int
    source_bias: int
    xxtea_key: bytes
    sections: tuple[SectionContract, ...]
    mutations: tuple[MutationContract, ...] = ()
    export_aliases: tuple[ExportAlias, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("contract name is empty")
        if self.header_offset < 0 or self.header_length <= 0:
            raise ValueError("header range is invalid")
        if self.payload_start < 0 or self.preserved_tail_start < 0:
            raise ValueError("payload range is invalid")
        if len(self.xxtea_key) != 16:
            raise ValueError("xxtea_key must contain exactly 16 bytes")
        names = [section.name for section in self.sections]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"duplicate section name: {duplicates[0]}")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["header_prefix"] = self.header_prefix.hex()
        result["xxtea_key"] = self.xxtea_key.decode("ascii")
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MfuscatorContract":
        sections = tuple(
            SectionContract(
                name=item["name"],
                custom_offset_field=item["custom_offset_field"],
                custom_size_field=item["custom_size_field"],
                record_size=item.get("record_size"),
                alignment=item.get("alignment", 4),
                payload_transform=(
                    PayloadTransformContract(**item["payload_transform"])
                    if item.get("payload_transform") is not None
                    else None
                ),
            )
            for item in data["sections"]
        )
        return cls(
            name=data["name"],
            metadata_magic=data["metadata_magic"],
            metadata_version=data["metadata_version"],
            header_prefix=bytes.fromhex(data["header_prefix"]),
            header_offset=data["header_offset"],
            header_length=data["header_length"],
            payload_start=data["payload_start"],
            preserved_tail_start=data["preserved_tail_start"],
            source_bias=data["source_bias"],
            xxtea_key=data["xxtea_key"].encode("ascii"),
            sections=sections,
            mutations=tuple(MutationContract(**item) for item in data.get("mutations", ())),
            export_aliases=tuple(ExportAlias(**item) for item in data.get("export_aliases", ())),
            evidence=tuple(Evidence(**item) for item in data.get("evidence", ())),
        )

    @classmethod
    def from_json(cls, text: str) -> "MfuscatorContract":
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("contract JSON root must be an object")
        return cls.from_dict(parsed)
