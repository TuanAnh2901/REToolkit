"""Transactional persistence coverage for the RE index."""

import pytest

from retoolkit.re_index.store import ReIndex


def test_open_migrates_empty_database(tmp_path) -> None:
    with ReIndex.open(tmp_path / "retoolkit.db") as index:
        assert index.user_version == 3
        assert index.scalar("SELECT COUNT(*) FROM methods") == 0


def test_failed_transaction_rolls_back(tmp_path) -> None:
    with ReIndex.open(tmp_path / "retoolkit.db") as index:
        with pytest.raises(RuntimeError, match="stop"):
            with index.transaction():
                index.execute(
                    "INSERT INTO runs VALUES (?, ?, ?, ?)",
                    ("r", "p", "h", "2026-08-01T00:00:00Z"),
                )
                raise RuntimeError("stop")
        assert index.scalar("SELECT COUNT(*) FROM runs") == 0


def test_open_rejects_database_newer_than_supported_schema(tmp_path) -> None:
    database = tmp_path / "newer.db"
    with ReIndex.open(database) as index:
        index.execute("PRAGMA user_version = 4")
        index.connection.commit()

    with pytest.raises(RuntimeError, match="newer"):
        ReIndex.open(database)
