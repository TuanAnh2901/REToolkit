"""Index-only target resolution and search CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from retoolkit.commands.index import database_path
from retoolkit.contracts.profile import Profile, load_profile
from retoolkit.contracts.result import Result, ResultError
from retoolkit.re_index.models import MethodRecord, TargetQuery
from retoolkit.re_index.query import parse_identity, resolve
from retoolkit.re_index.store import ReIndex


def register_target_commands(sub: argparse._SubParsersAction) -> None:
    """Register the ``target`` command tree on the root CLI parser."""
    parser = sub.add_parser("target", help="query methods already present in the RE index")
    commands = parser.add_subparsers(dest="target_command", required=True)
    resolve_parser = commands.add_parser("resolve", help="resolve one exact method identity")
    resolve_parser.add_argument("profile", help="path to profile.json")
    resolve_parser.add_argument("identity", help="exact '<assembly>!<signature>' identity")
    resolve_parser.add_argument("--limit", type=_limit, default=None, help="maximum matches (1..10000)")
    resolve_parser.set_defaults(handler=_cmd_resolve)

    search = commands.add_parser("search", help="search indexed methods using bounded selectors")
    search.add_argument("profile", help="path to profile.json")
    search.add_argument("--assembly", help="exact assembly name")
    search.add_argument("--namespace", help="exact namespace prefix")
    search.add_argument("--class", dest="type_pattern", help="class/type wildcard pattern")
    search.add_argument("--method", dest="method_pattern", help="method wildcard pattern")
    search.add_argument("--rva", type=_rva, help="exact hexadecimal or decimal RVA")
    search.add_argument("--limit", type=_limit, default=None, help="maximum matches (1..10000)")
    search.set_defaults(handler=_cmd_search)


def resolve_target(profile_path: Path, identity: str, *, limit: int | None = None) -> dict[str, object]:
    """Resolve an exact managed identity from an existing persistent index."""
    profile = load_profile(profile_path)
    try:
        query = parse_identity(identity)
        query = TargetQuery(identity=query.identity, limit=_query_limit(profile.raw, limit))
    except ValueError as exc:
        raise ResultError.validation(str(exc)) from None
    return _resolve(profile_path, profile, query)


def search_targets(
    profile_path: Path,
    *,
    assembly: str | None = None,
    namespace: str | None = None,
    type_pattern: str | None = None,
    method_pattern: str | None = None,
    rva: int | None = None,
    limit: int | None = None,
) -> dict[str, object]:
    """Search indexed methods without launching Cpp2IL, Ghidra, or Frida."""
    profile = load_profile(profile_path)
    try:
        query = TargetQuery(
            assembly=assembly,
            namespace=namespace,
            type_pattern=type_pattern,
            method_pattern=method_pattern,
            rva=rva,
            limit=_query_limit(profile.raw, limit),
        )
    except ValueError as exc:
        raise ResultError.validation(str(exc)) from None
    return _resolve(profile_path, profile, query)


def _resolve(profile_path: Path, profile: Profile, query: TargetQuery) -> dict[str, object]:
    db_path = database_path(profile)
    if not db_path.is_file():
        raise ResultError.validation(f"RE index database not found: {db_path}; run 'index build' first")
    with ReIndex.open(db_path) as index:
        matches = resolve(index, query)
    return {
        "database": str(db_path),
        "profile": str(profile_path),
        "matches": [_match_data(match) for match in matches],
    }


def _query_limit(raw: dict[str, Any], supplied: int | None) -> int:
    if supplied is not None:
        return supplied
    index = raw.get("index", {})
    value = index.get("query_limit", 100) if isinstance(index, dict) else 100
    try:
        return int(value)
    except (TypeError, ValueError):
        return 100


def _match_data(match: MethodRecord) -> dict[str, object]:
    return {
        "id": match.id,
        "assembly": match.assembly,
        "type": match.type_name,
        "method": match.method_name,
        "signature": match.signature,
        "rva": f"0x{match.rva:x}",
        "pointer": None if match.pointer is None else f"0x{match.pointer:x}",
        "collision_key": match.collision_key,
    }


def _cmd_resolve(args: argparse.Namespace) -> Result:
    return Result.ok(
        "target resolve", resolve_target(Path(args.profile), args.identity, limit=args.limit)
    )


def _cmd_search(args: argparse.Namespace) -> Result:
    return Result.ok(
        "target search",
        search_targets(
            Path(args.profile),
            assembly=args.assembly,
            namespace=args.namespace,
            type_pattern=args.type_pattern,
            method_pattern=args.method_pattern,
            rva=args.rva,
            limit=args.limit,
        ),
    )


def _limit(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be an integer") from exc
    if not 1 <= value <= 10_000:
        raise argparse.ArgumentTypeError("limit must be between 1 and 10000")
    return value


def _rva(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("RVA must be hexadecimal or decimal") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("RVA must be non-negative")
    return value
