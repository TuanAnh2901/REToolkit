from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
@dataclass(frozen=True)
class WorkItem:
 id:int; request_id:str; target_id:int; operation:str; priority:int; state:str; attempt:int=0; worker_id:str|None=None
class WorkQueue:
 def __init__(self): self.items=[]; self.next_id=1
 def enqueue(self, target_id, operation, priority=0, request_id="default", input_hash=""):
  for x in self.items:
   if (x.request_id,x.target_id,x.operation)==(request_id,target_id,operation) and x.state != "failed": return x
  x=WorkItem(self.next_id,request_id,target_id,operation,priority,"pending"); self.next_id+=1; self.items.append(x); return x
 def get(self,item_id): return next(x for x in self.items if x.id==item_id)
 def claim(self,worker_id):
  pending=sorted((x for x in self.items if x.state=="pending"),key=lambda x:(-x.priority,x.id))
  if not pending:return None
  old=pending[0]; new=WorkItem(old.id,old.request_id,old.target_id,old.operation,old.priority,"running",old.attempt+1,worker_id); self.items[self.items.index(old)]=new; return new
 def recover_interrupted(self,active_workers=set()):
  self.items=[WorkItem(x.id,x.request_id,x.target_id,x.operation,x.priority,"pending" if x.state=="running" and x.worker_id not in active_workers else x.state,x.attempt,None if x.worker_id not in active_workers else x.worker_id) for x in self.items]
