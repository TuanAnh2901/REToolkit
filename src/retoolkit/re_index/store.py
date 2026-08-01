"""Transactional SQLite access for the persistent RE index."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from retoolkit.contracts.result import ResultError

from .schema import MIGRATIONS, SCHEMA_VERSION


class ReIndex:
    """A versioned SQLite index with explicit transactional writes."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self.connection = connection
        self.connection.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path) -> "ReIndex":
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        index = cls(path, connection)
        try:
            index._migrate()
        except BaseException:
            connection.close()
            raise
        return index

    @property
    def user_version(self) -> int:
        return int(self.scalar("PRAGMA user_version"))

    def execute(self, statement: str, parameters: Sequence[Any] = ()) -> sqlite3.Cursor:
        return self.connection.execute(statement, parameters)

    def scalar(self, statement: str, parameters: Sequence[Any] = ()) -> Any:
        row = self.execute(statement, parameters).fetchone()
        return None if row is None else row[0]

    @contextmanager
    def transaction(self) -> Iterator["ReIndex"]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def __enter__(self) -> "ReIndex":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        current = self.user_version
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"RE index schema {current} is newer than supported version {SCHEMA_VERSION}"
            )
        if current == SCHEMA_VERSION:
            return
        with self.transaction():
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for script in MIGRATIONS[version]:
                    self._execute_script(script)

    def _execute_script(self, script: str) -> None:
        """Execute a migration without allowing sqlite ``executescript`` to commit it."""
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                self.connection.execute(statement)
                statement = ""
        if statement.strip():
            self.connection.execute(statement)

    def ensure_run(self, run_id: str, profile_name: str, input_hash: str) -> None:
        self.execute(
            "INSERT OR IGNORE INTO runs (id, profile_name, input_hash, created_utc) VALUES (?, ?, ?, ?)",
            (run_id, profile_name, input_hash, _utc_now()),
        )

    def ensure_binary(self, sha256: str, path: str) -> int:
        self.execute("INSERT OR IGNORE INTO binaries (sha256, path) VALUES (?, ?)", (sha256, path))
        binary_id = self.scalar("SELECT id FROM binaries WHERE sha256 = ?", (sha256,))
        assert binary_id is not None
        return int(binary_id)

    def find_method_map(self, binary_id: int, sha256: str) -> int | None:
        map_id = self.scalar(
            "SELECT id FROM method_maps WHERE binary_id = ? AND sha256 = ?", (binary_id, sha256)
        )
        return None if map_id is None else int(map_id)

    def insert_method_map(self, binary_id: int, sha256: str, method_count: int) -> int:
        cursor = self.execute(
            "INSERT INTO method_maps (binary_id, sha256, method_count, imported_utc) VALUES (?, ?, ?, ?)",
            (binary_id, sha256, method_count, _utc_now()),
        )
        assert cursor.lastrowid is not None
        return int(cursor.lastrowid)

    def insert_methods(self, method_map_id: int, methods: list[dict[str, Any]]) -> None:
        rows = (_method_row(method_map_id, method) for method in methods)
        statement = (
            "INSERT INTO methods (method_map_id, assembly, type_name, method_name, signature, rva, "
            "pointer, full_identity, collision_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        while batch := _take(rows, 5000):
            self.connection.executemany(statement, batch)


def _method_row(method_map_id: int, method: dict[str, Any]) -> tuple[Any, ...]:
    try:
        assembly = _required_text(method, "assembly")
        type_name = _required_text(method, "type")
        method_name = _required_text(method, "method")
        signature = _required_text(method, "signature")
        full_identity = _required_text(method, "full_identity")
        rva = _hex_value(method["rva"], "rva")
        pointer = None if method.get("pointer") is None else _hex_value(method["pointer"], "pointer")
    except KeyError as exc:
        raise ResultError.validation(f"method map entry is missing {exc.args[0]}") from None
    return (
        method_map_id,
        assembly,
        type_name,
        method_name,
        signature,
        rva,
        pointer,
        full_identity,
        f"{full_identity}#0x{rva:x}",
    )


def _required_text(method: dict[str, Any], field: str) -> str:
    value = method.get(field)
    if not isinstance(value, str) or not value:
        raise ResultError.validation(f"method map entry has invalid {field}")
    return value


def _hex_value(value: Any, field: str) -> int:
    if not isinstance(value, str):
        raise ResultError.validation(f"method map entry has invalid {field}")
    try:
        return int(value, 16)
    except ValueError:
        raise ResultError.validation(f"method map entry has invalid {field}") from None


def _take(rows: Iterator[tuple[Any, ...]], size: int) -> list[tuple[Any, ...]]:
    batch: list[tuple[Any, ...]] = []
    for _ in range(size):
        try:
            batch.append(next(rows))
        except StopIteration:
            break
    return batch


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
