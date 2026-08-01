from __future__ import annotations
import argparse
from retoolkit.contracts.result import Result

def select_mode(count: int, settings: dict) -> str:
    if count <= int(settings.get("targeted_max_targets", 256)): return "targeted"
    if count <= int(settings.get("parallel_max_targets", 5000)): return "parallel"
    return "gui"

def _command(args: argparse.Namespace) -> Result:
    return Result.ok(f"ghidra {args.ghidra_command}", {"profile": args.profile, "mode": getattr(args, "mode", None), "status": "planned"})

def register_ghidra_commands(sub: argparse._SubParsersAction) -> None:
    parser=sub.add_parser("ghidra", help="Ghidra analysis modes")
    commands=parser.add_subparsers(dest="ghidra_command", required=True)
    for name in ("prepare", "benchmark", "prepare-gui", "import-gui"):
        p=commands.add_parser(name); p.add_argument("profile")
        if name == "benchmark": p.add_argument("--targets", required=True); p.add_argument("--workers", default="1,2,4"); p.add_argument("--batch-size", type=int, default=128)
        elif name == "prepare-gui": p.add_argument("--query", required=True); p.add_argument("--output", required=True)
        elif name == "import-gui": p.add_argument("--bundle", required=True); p.add_argument("--verify-only", action="store_true")
        p.set_defaults(handler=_command)
    analyze=commands.add_parser("analyze"); analyze.add_argument("profile"); analyze.add_argument("--query", required=True); analyze.add_argument("--mode", choices=("auto","targeted","parallel","gui"), default="auto"); analyze.set_defaults(handler=_command)
