from __future__ import annotations
import argparse
from retoolkit.contracts.result import Result
def _run(args): return Result.ok("dossier",{"profile":args.profile,"target_id":args.target_id,"depth":args.depth,"status":"planned"})
def register_dossier_commands(sub):
 p=sub.add_parser("dossier",help="target evidence dossier"); p.add_argument("profile"); p.add_argument("target_id",type=int); p.add_argument("--depth",choices=("fast","balanced","deep"),default="fast"); p.set_defaults(handler=_run)
