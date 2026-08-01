from dataclasses import dataclass
@dataclass(frozen=True)
class RecoveryCandidate:
 target_id:int; identity:str; rva:int; profile_priority:int=0; runtime_hits:int=0; caller_count:int=0; string_reference_count:int=0; native_size:int|None=None
def ranking_key(c): return (-c.profile_priority,-int(c.runtime_hits>0),-c.runtime_hits,-c.caller_count,-c.string_reference_count,c.native_size if c.native_size is not None else 2**63,c.identity,c.rva)
def rank_candidates(candidates): return sorted(candidates,key=ranking_key)
