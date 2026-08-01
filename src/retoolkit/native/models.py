"""Typed records emitted by bounded native analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StaticFinding:
    method_id: int
    entry_rva: int
    bytes_sha256: str
    instructions: tuple[dict[str, Any], ...]
    direct_calls: tuple[int, ...]
    conditional_branches: tuple[int, ...]
    rip_references: tuple[int, ...]
    immediates: tuple[int, ...]
    strings: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "method_id": self.method_id,
            "entry_rva": self.entry_rva,
            "bytes_sha256": self.bytes_sha256,
            "instructions": [dict(row) for row in self.instructions],
            "direct_calls": list(self.direct_calls),
            "conditional_branches": list(self.conditional_branches),
            "rip_references": list(self.rip_references),
            "immediates": list(self.immediates),
            "strings": list(self.strings),
            "status": self.status,
        }
