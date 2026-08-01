"""Shared primitives for safe file system writes."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via a unique temp file in the same directory, then atomically
    replace. A crash mid-write leaves only an unreferenced .tmp file."""
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))
