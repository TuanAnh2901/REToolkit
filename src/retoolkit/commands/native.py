from __future__ import annotations
import argparse
from retoolkit.contracts.result import Result

def _scan(args: argparse.Namespace) -> Result:
    return Result.ok("native scan", {"profile": args.profile, "query": args.query, "window_bytes": args.window_bytes, "status": "planned"})

def register_native_commands(sub: argparse._SubParsersAction) -> None:
    parser=sub.add_parser("native", help="fast native analysis")
    commands=parser.add_subparsers(dest="native_command", required=True)
    scan=commands.add_parser("scan")
    scan.add_argument("profile"); scan.add_argument("--query", required=True); scan.add_argument("--window-bytes", type=int, default=256)
    scan.set_defaults(handler=_scan)
