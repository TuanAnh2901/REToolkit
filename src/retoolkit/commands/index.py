"""Index-build and index-statistics CLI commands."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from retoolkit.contracts.profile import Profile, load_profile
from retoolkit.contracts.result import Result, ResultError
from retoolkit.core.state import hash_inputs
from retoolkit.re_index.importers import import_method_map
from retoolkit.re_index.store import ReIndex


def register_index_commands(sub: argparse._SubParsersAction) -> None:
    """Register the ``index`` command tree on the root CLI parser."""
    parser = sub.add_parser("index", help="persistent RE-index operations")
    commands = parser.add_subparsers(dest="index_command", required=True)
    build = commands.add_parser("build", help="import the normalized method map")
    build.add_argument("profile", help="path to profile.json")
    build.set_defaults(handler=_cmd_build)
    stats = commands.add_parser("stats", help="report persistent RE-index counts")
    stats.add_argument("profile", help="path to profile.json")
    stats.set_defaults(handler=_cmd_stats)


def build_index(profile_path: Path) -> dict[str, object]:
    """Import one normalized method map into the profile workspace index."""
    profile = load_profile(profile_path)
    map_path = profile.workspace / "normalize" / "method-map.normalized.json"
    document = _read_method_map(map_path)
    binary_sha = _sha256_file(profile.game_assembly)
    map_sha = _sha256_file(map_path)
    db_path = database_path(profile)
    with ReIndex.open(db_path) as index:
        map_id = import_method_map(
            index,
            document,
            run_id=_make_run_id(),
            profile_name=profile.name,
            input_hash=hash_inputs([binary_sha, map_sha]),
            binary_path=str(profile.game_assembly),
            binary_sha256=binary_sha,
            method_map_sha256=map_sha,
        )
        count = int(
            index.scalar("SELECT COUNT(*) FROM methods WHERE method_map_id = ?", (map_id,))
        )
    return {"database": str(db_path), "method_map_id": map_id, "method_count": count}


def index_stats(profile_path: Path) -> dict[str, object]:
    """Return counts already present in the profile workspace index."""
    profile = load_profile(profile_path)
    db_path = database_path(profile)
    if not db_path.is_file():
        raise ResultError.validation(f"RE index database not found: {db_path}; run 'index build' first")
    with ReIndex.open(db_path) as index:
        return {
            "database": str(db_path),
            "schema_version": index.user_version,
            "run_count": int(index.scalar("SELECT COUNT(*) FROM runs")),
            "method_map_count": int(index.scalar("SELECT COUNT(*) FROM method_maps")),
            "method_count": int(index.scalar("SELECT COUNT(*) FROM methods")),
        }


def database_path(profile: Profile) -> Path:
    """Return the index database path rooted under the resolved workspace."""
    return profile.workspace / "re-index" / "retoolkit.db"


def _cmd_build(args: argparse.Namespace) -> Result:
    return Result.ok("index build", build_index(Path(args.profile)))


def _cmd_stats(args: argparse.Namespace) -> Result:
    return Result.ok("index stats", index_stats(Path(args.profile)))


def _read_method_map(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ResultError.validation(f"normalized method map not found: {path}") from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise ResultError.validation(f"normalized method map is invalid JSON: {path}: {exc}") from None
    if not isinstance(document, dict):
        raise ResultError.validation(f"normalized method map root must be an object: {path}")
    return document


def _sha256_file(path: Path) -> str:
    try:
        with path.open("rb") as source:
            digest = hashlib.sha256()
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise ResultError.validation(f"input file unreadable: {path}: {exc}") from None
    return digest.hexdigest()


def _make_run_id() -> str:
    """Build a deterministic-format unique run ID without invoking external tools."""
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    return f"index-{stamp}"
