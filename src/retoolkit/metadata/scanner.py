"""Pure byte-buffer metadata magic scanning with bounds checks.

Detects standard IL2CPP metadata signatures (magic ``AF 1B B1 FA`` plus a
plausible version) in a byte buffer. Never writes files and never scans
process memory; callers decide what buffer to scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import unpack_from

MAGIC = b"\xAF\x1B\xB1\xFA"
MIN_VERSION = 20
MAX_VERSION = 200
HEADER_SIZE = 8


@dataclass
class MetadataHit:
    offset: int
    version: int


def find_metadata_signatures(buffer: bytes, *, min_version: int = MIN_VERSION, max_version: int = MAX_VERSION) -> list[MetadataHit]:
    """Return every offset where a full magic+version header fits, skipping
    truncated tail positions and rejecting implausible versions."""
    hits: list[MetadataHit] = []
    if len(buffer) < HEADER_SIZE:
        return hits
    limit = len(buffer) - HEADER_SIZE
    index = 0
    while index <= limit:
        position = buffer.find(MAGIC, index)
        if position < 0 or position > limit:
            break
        version = unpack_from("<I", buffer, position + 4)[0]
        if min_version <= version <= max_version:
            hits.append(MetadataHit(offset=position, version=version))
        index = position + 1
    return hits


def version_at(buffer: bytes, offset: int) -> int | None:
    """Version at offset if a valid signature sits there, else None."""
    if offset < 0 or offset + HEADER_SIZE > len(buffer):
        return None
    if buffer[offset : offset + 4] != MAGIC:
        return None
    version = unpack_from("<I", buffer, offset + 4)[0]
    if MIN_VERSION <= version <= MAX_VERSION:
        return version
    return None
