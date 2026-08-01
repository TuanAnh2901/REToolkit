"""Typed, deterministic Ghidra cache and interchange records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re


_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_MAX_U64 = (1 << 64) - 1


def _hash(value: str, field: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


def _text(value: str, field: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{field} must not be empty")
    return value


def _uint64(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_U64:
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    return value


@dataclass(frozen=True)
class GhidraCacheKey:
    """All semantic inputs that make a persistent Ghidra project reusable."""

    binary_sha256: str
    ghidra_version: str
    loader: str
    script_sha256: str
    analyzer_profile: str
    image_base: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "binary_sha256", _hash(self.binary_sha256, "binary_sha256"))
        object.__setattr__(self, "script_sha256", _hash(self.script_sha256, "script_sha256"))
        _text(self.ghidra_version, "ghidra_version")
        _text(self.loader, "loader")
        _text(self.analyzer_profile, "analyzer_profile")
        _uint64(self.image_base, "image_base")

    def digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GhidraTarget:
    target_id: int
    method_id: int
    rva: int
    address: int
    identity: str

    def __post_init__(self) -> None:
        if isinstance(self.target_id, bool) or not isinstance(self.target_id, int) or self.target_id < 0:
            raise ValueError("target_id must be a non-negative integer")
        if isinstance(self.method_id, bool) or not isinstance(self.method_id, int) or self.method_id < 1:
            raise ValueError("method_id must be a positive integer")
        _uint64(self.rva, "rva")
        _uint64(self.address, "address")
        _text(self.identity, "identity")


@dataclass(frozen=True)
class TargetManifest:
    schema_version: str
    binary_sha256: str
    method_map_sha256: str
    image_base: int
    targets: tuple[GhidraTarget, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise ValueError("unsupported target manifest schema_version")
        object.__setattr__(self, "binary_sha256", _hash(self.binary_sha256, "binary_sha256"))
        object.__setattr__(
            self,
            "method_map_sha256",
            _hash(self.method_map_sha256, "method_map_sha256"),
        )
        _uint64(self.image_base, "image_base")
        targets = tuple(sorted(tuple(self.targets), key=lambda row: (row.rva, row.identity, row.target_id)))
        ids = [row.target_id for row in targets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate target_id in target manifest")
        for target in targets:
            if target.address != self.image_base + target.rva:
                raise ValueError(
                    f"target {target.target_id} address does not equal image_base + rva"
                )
            if target.address > _MAX_U64:
                raise ValueError(f"target {target.target_id} address overflows 64 bits")
        object.__setattr__(self, "targets", targets)


@dataclass(frozen=True)
class GhidraRecord:
    """A single durable result row emitted for a requested target."""

    target_id: int
    method_id: int
    rva: int
    address: int
    status: str
    function_name: str | None = None
    function_entry_rva: int | None = None
    function_end_rva: int | None = None
    pseudocode: str | None = None
    error: str | None = None
    duration_ms: int = 0

    def __post_init__(self) -> None:
        GhidraTarget(self.target_id, self.method_id, self.rva, self.address, "result")
        _text(self.status, "status")
        if self.function_entry_rva is not None:
            _uint64(self.function_entry_rva, "function_entry_rva")
        if self.function_end_rva is not None:
            _uint64(self.function_end_rva, "function_end_rva")
        if (
            self.function_entry_rva is not None
            and self.function_end_rva is not None
            and self.function_end_rva < self.function_entry_rva
        ):
            raise ValueError("function_end_rva must not precede function_entry_rva")
        if isinstance(self.duration_ms, bool) or not isinstance(self.duration_ms, int) or self.duration_ms < 0:
            raise ValueError("duration_ms must be a non-negative integer")
