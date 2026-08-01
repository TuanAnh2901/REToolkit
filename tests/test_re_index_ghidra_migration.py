import sqlite3
from pathlib import Path

import pytest

from retoolkit.re_index.schema import MIGRATIONS
from retoolkit.re_index.store import ReIndex


def _create_v1_fixture(path) -> None:
    schema = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "re_index_v1.sql"
    ).read_text(encoding="utf-8")
    connection = sqlite3.connect(path)
    try:
        connection.executescript(schema)
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?)",
            ("r", "p", "input", "2026-08-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO binaries VALUES (?, ?, ?, ?, ?)",
            (1, "a" * 64, "GameAssembly.dll", 0x180000000, "x86_64"),
        )
        connection.execute(
            "INSERT INTO method_maps VALUES (?, ?, ?, ?, ?)",
            (1, 1, "b" * 64, 1, "2026-08-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO methods VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, 1, "A", "N.T", "M", "void M()", 0x10, 0x180000010, "A!M", "A!M#0x10"),
        )
        connection.commit()
    finally:
        connection.close()


def test_v1_migrates_to_v2_without_losing_methods_and_is_idempotent(tmp_path) -> None:
    database = tmp_path / "index.db"
    _create_v1_fixture(database)

    with ReIndex.open(database) as index:
        assert index.user_version == 5
        assert index.scalar("SELECT COUNT(*) FROM methods") == 1
        expected_tables = {
            "functions",
            "static_findings",
            "edges",
            "ghidra_runs",
            "decompilations",
        }
        actual_tables = {
            row[0]
            for row in index.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert expected_tables <= actual_tables
        schema_before = tuple(
            tuple(row)
            for row in index.query(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )

    with ReIndex.open(database) as index:
        schema_after = tuple(
            tuple(row)
            for row in index.query(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        )
        assert index.user_version == 5
        assert index.scalar("SELECT COUNT(*) FROM methods") == 1
        assert schema_after == schema_before


def test_failed_v2_migration_rolls_back_schema_and_version(tmp_path, monkeypatch) -> None:
    database = tmp_path / "index.db"
    _create_v1_fixture(database)
    monkeypatch.setitem(
        MIGRATIONS,
        2,
        (
            "CREATE TABLE migration_probe (id INTEGER);\n"
            "THIS IS NOT VALID SQL;\n"
            "PRAGMA user_version = 2;\n",
        ),
    )

    with pytest.raises(sqlite3.OperationalError):
        ReIndex.open(database)

    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'migration_probe'"
        ).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM methods").fetchone()[0] == 1
    finally:
        connection.close()
