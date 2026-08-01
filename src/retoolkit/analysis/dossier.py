from __future__ import annotations
import hashlib,json
from .correlation import Correlator
DEPTH_REQUIREMENTS={"fast":frozenset({"method-map","native"}),"balanced":frozenset({"method-map","native","one-deep-source"}),"deep":frozenset({"method-map","native","ghidra","runtime","graph-depth"})}
class DossierService:
    def __init__(self,index): self.index=index; self.last_cache_hit=False; self._cache={}
    def build(self,target_id:int,*,depth="fast"):
        if depth not in DEPTH_REQUIREMENTS: raise ValueError(f"unknown dossier depth {depth!r}")
        key=(target_id,depth); self.last_cache_hit=key in self._cache
        if self.last_cache_hit:return self._cache[key]
        c=Correlator(self.index).correlate_target(target_id)
        doc={"schema_version":"1.0.0","target":{"id":target_id,"method":c.method.signature},"addresses":{"rva":f"0x{c.method.rva:x}","confidence":c.address_claim.confidence},"managed":{"assembly":c.method.assembly,"type":c.method.type_name},"native":{},"graph":{"callers":[],"callees":[]},"runtime":[],"claims":[c.address_claim.to_dict() if hasattr(c.address_claim,'to_dict') else {"name":c.address_claim.name,"confidence":c.address_claim.confidence}],"provenance":{"depth":depth},"missing_evidence":sorted(DEPTH_REQUIREMENTS[depth]-{"method-map","native"})}
        self._cache[key]=doc; return doc
    def build_bytes(self,target_id:int,*,depth="fast"): return json.dumps(self.build(target_id,depth=depth),sort_keys=True,separators=(",",":" )).encode()
