"""Deterministic Ghidra base-project cache paths and publication lifecycle."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Iterator

from retoolkit.core.atomic import atomic_write_text

from .models import GhidraCacheKey


_CACHE_SCHEMA_VERSION = "1.0.0"
_REPLICA_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _canonical_json(document: dict[str, object]) -> str:
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


@dataclass(frozen=True)
class CachedProject:
    root: Path
    key: GhidraCacheKey

    @property
    def project_file(self) -> Path:
        return self.root / "project.gpr"

    @property
    def repository_dir(self) -> Path:
        return self.root / "project.rep"

    @property
    def key_metadata(self) -> Path:
        return self.root / "cache-key.json"

    @property
    def import_marker(self) -> Path:
        return self.root / "import-complete.json"

    @property
    def lock_file(self) -> Path:
        return self.root / ".lock"

    @property
    def replicas_dir(self) -> Path:
        return self.root / "replicas"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.replicas_dir.mkdir(exist_ok=True)
        expected: dict[str, object] = {
            **asdict(self.key),
            "digest": self.key.digest(),
            "schema_version": _CACHE_SCHEMA_VERSION,
        }
        if self.key_metadata.exists():
            try:
                actual = json.loads(self.key_metadata.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise RuntimeError(f"invalid Ghidra cache key metadata: {error}") from error
            if actual != expected:
                raise RuntimeError("Ghidra cache directory contains a different cache key")
            return
        atomic_write_text(self.key_metadata, _canonical_json(expected))

    @contextmanager
    def acquire_lock(self, *, timeout_seconds: float = 30.0) -> Iterator[None]:
        """Acquire the cache's inter-process publication lock."""
        self.initialize()
        deadline = time.monotonic() + timeout_seconds
        descriptor: int | None = None
        while descriptor is None:
            try:
                descriptor = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out acquiring Ghidra cache lock {self.lock_file}")
                time.sleep(0.05)
        try:
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            yield
        finally:
            os.close(descriptor)
            self.lock_file.unlink(missing_ok=True)

    def replica(self, name: str) -> Path:
        if not _REPLICA_NAME.fullmatch(name):
            raise ValueError("replica name must be one safe path component")
        return self.replicas_dir / name

    def publish_import(self, *, exit_code: int, expected_program: Path) -> None:
        """Publish the success marker after Ghidra has created the full base project."""
        self.initialize()
        if exit_code != 0:
            raise RuntimeError(f"Ghidra import failed with exit code {exit_code}")
        if not self.project_file.is_file() or not self.repository_dir.is_dir():
            raise FileNotFoundError("expected Ghidra project.gpr and project.rep were not created")
        resolved_root = self.root.resolve()
        resolved_program = expected_program.resolve()
        try:
            relative = resolved_program.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError("expected Ghidra program must be inside the cached project") from error
        if not resolved_program.exists():
            raise FileNotFoundError(f"expected Ghidra program was not created: {expected_program}")
        marker: dict[str, object] = {
            "schema_version": _CACHE_SCHEMA_VERSION,
            "cache_key": self.key.digest(),
            "expected_program": relative.as_posix(),
            "completed_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        atomic_write_text(self.import_marker, _canonical_json(marker))

    def is_import_complete(self) -> bool:
        if not self.import_marker.is_file() or not self.project_file.is_file() or not self.repository_dir.is_dir():
            return False
        try:
            marker = json.loads(self.import_marker.read_text(encoding="utf-8"))
            if marker.get("schema_version") != _CACHE_SCHEMA_VERSION:
                return False
            relative = Path(marker["expected_program"])
            expected = (self.root / relative).resolve()
            expected.relative_to(self.root.resolve())
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return False
        except ValueError:
            return False
        return marker.get("cache_key") == self.key.digest() and expected.exists()


class GhidraProjectCache:
    def __init__(self, root: Path) -> None:
        self.root = root

    def project(self, key: GhidraCacheKey) -> CachedProject:
        return CachedProject(self.root / key.digest(), key)
