from dataclasses import dataclass
import re
@dataclass(frozen=True)
class Cpp2IlFailure:
 identity:str; category:str; raw_line:str; target_id:int|None=None
def parse_failures(text):
 out=[]
 for line in text.splitlines():
  m=re.search(r"Skipping (.+?): Decompilation failed",line)
  if m: out.append(Cpp2IlFailure(m.group(1),"decompilation_failed",line)); continue
  m=re.search(r"Method (.+?) is too big",line)
  if m: out.append(Cpp2IlFailure(m.group(1),"too_big",line)); continue
  if "missing pointer" in line.lower(): out.append(Cpp2IlFailure(line,"missing_pointer",line))
 return out
