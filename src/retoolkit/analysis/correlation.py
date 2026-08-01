from __future__ import annotations
from .models import Claim, CorrelatedTarget, EvidenceRef
from retoolkit.re_index.models import MethodRecord
def address_confidence(kinds:set[str], conflicts=()):
    if conflicts:return "conflict"
    if {"frida-runtime-hit","cpp2il-method-map"}<=kinds:return "confirmed"
    if {"ghidra-function","native-entry"}<=kinds:return "high"
    if {"cpp2il-method-map","native-entry"}<=kinds:return "probable"
    return "candidate"
class Correlator:
    def __init__(self,index): self.index=index
    def correlate_target(self,target_id:int)->CorrelatedTarget:
        row=self.index.query("SELECT m.id,m.assembly,m.type_name,m.method_name,m.signature,m.rva,m.pointer,m.collision_key FROM targets t JOIN methods m ON m.id=t.method_id WHERE t.id=?",(target_id,))
        if not row: raise ValueError(f"target {target_id} not found")
        method=MethodRecord(**dict(row[0])); evidence=[EvidenceRef("cpp2il-method-map",None,method.id,True,method.signature),EvidenceRef("native-entry",None,method.id,True,f"RVA 0x{method.rva:x}")]
        claim=Claim("address",method.rva,address_confidence({e.kind for e in evidence}),tuple(evidence))
        return CorrelatedTarget(target_id,method,claim,None,(),(),())
