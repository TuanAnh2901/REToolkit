from __future__ import annotations
from retoolkit.contracts.result import Result
from retoolkit.analysis.orchestrator import AnalysisOrchestrator
def _run(args):
    plan=AnalysisOrchestrator().plan(args.query,depth=args.depth)
    return Result.ok("analyze",{"plan":plan.to_dict(),"plan_only":args.plan_only})
def register_analyze_commands(sub):
    p=sub.add_parser("analyze",help="query-driven analysis"); p.add_argument("profile"); p.add_argument("--query",required=True); p.add_argument("--depth",choices=("fast","balanced","deep"),default="fast"); p.add_argument("--plan-only",action="store_true"); p.add_argument("--resume",action="store_true"); p.set_defaults(handler=_run)
