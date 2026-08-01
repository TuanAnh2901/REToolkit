from __future__ import annotations
from dataclasses import asdict, dataclass
import json
@dataclass(frozen=True)
class TraceRecipe:
    target_ids: tuple[int, ...]
    duration_seconds: int
    capture: tuple[str, ...] = ("call-count",)
    sample_every: int = 1
    max_events_per_target: int = 1000
    max_events_total: int = 10000
    backtrace_depth: int = 16
    def __post_init__(self):
        object.__setattr__(self, "target_ids", tuple(sorted(set(self.target_ids))))
        if not self.target_ids: raise ValueError("target_ids must not be empty")
        if not 1 <= self.duration_seconds <= 3600: raise ValueError("duration_seconds must be between 1 and 3600")
        if self.sample_every < 1: raise ValueError("sample_every must be positive")
    def to_dict(self): return asdict(self) | {"target_ids": list(self.target_ids), "capture": list(self.capture)}
    def to_json(self): return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
@dataclass(frozen=True)
class RuntimeEvent:
    schema_version: str; session_id: str; sequence: int; target_id: int; method_id: int; thread_id: int | None; module_base: int; runtime_address: int; rva: int; event_kind: str; payload: dict; timestamp: float
    def to_dict(self): return asdict(self)
@dataclass(frozen=True)
class TraceSummary:
    schema_version: str; session_id: str; status: str; event_count: int; dropped_count: int; duration_seconds: float; resolve_status: str = "resolved"
    def to_dict(self): return asdict(self)
