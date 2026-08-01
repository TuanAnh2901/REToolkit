from __future__ import annotations
from dataclasses import dataclass,asdict
import hashlib,json
@dataclass(frozen=True)
class AnalysisStep:
    kind:str; target_ids:tuple[int,...]; input_hash:str; reason:str
@dataclass(frozen=True)
class AnalysisPlan:
    steps:tuple[AnalysisStep,...]
    def to_dict(self): return {"schema_version":"1.0.0","steps":[asdict(s)|{"target_ids":list(s.target_ids)} for s in self.steps]}
class AnalysisOrchestrator:
    def __init__(self,index=None): self.index=index
    def plan(self,query,*,depth="fast"):
        if depth not in {"fast","balanced","deep"}: raise ValueError(f"unknown depth {depth}")
        digest=hashlib.sha256(str(query).encode()).hexdigest(); kinds=["resolve","native","correlate","dossier"]
        if depth in {"balanced","deep"}: kinds.insert(2,"ghidra-cache")
        if depth=="deep": kinds.insert(3,"runtime")
        return AnalysisPlan(tuple(AnalysisStep(k,(),digest,"requested depth") for k in kinds))
    def run(self,plan,*,resume=False): return {"schema_version":"1.0.0","status":"planned","steps":plan.to_dict()["steps"]}
