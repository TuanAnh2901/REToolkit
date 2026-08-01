"""Versioned SQLite migrations for the persistent RE index."""

from pathlib import Path


SCHEMA_VERSION = 2


def _load_migration(filename: str) -> str:
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / filename
    return schema_path.read_text(encoding="utf-8")


# Each version contains one or more ordered SQL scripts.  Keeping scripts grouped
# by version lets the store apply every missing version atomically.
MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (_load_migration("re_index_v1.sql"),),
    2: (_load_migration("re_index_v2.sql"),),
}
