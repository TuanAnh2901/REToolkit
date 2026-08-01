from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Literal
Confidence=Literal["candidate","probable","high","confirmed","conflict"]
@dataclass(frozen=True)
class EvidenceRef:
    kind:str; artifact_id:int|None; record_id:int|None; observed:bool; summary:str
@dataclass(frozen=True)
class Claim:
    name:str; value:object; confidence:Confidence; evidence:tuple[EvidenceRef,...]; conflicts:tuple[EvidenceRef,...]=()
@dataclass(frozen=True)
class CorrelatedTarget:
    target_id:int; method:object; address_claim:Claim; function_claim:Claim|None; callers:tuple[Claim,...]; callees:tuple[Claim,...]; runtime:tuple[Claim,...]
    def to_dict(self): return asdict(self)
