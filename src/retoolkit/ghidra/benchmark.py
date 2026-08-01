"""Benchmark record helpers; measurement remains explicit and reproducible."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import json
from pathlib import Path
from retoolkit.core.atomic import atomic_write_text

@dataclass(frozen=True)
class BenchmarkRecord:
    worker_count: int
    batch_size: int
    elapsed_seconds: float
    completed: int
    failed: int = 0
    jvm_launches: int = 0
    cpu_seconds: float = 0.0
    working_set_bytes: int = 0
    disk_bytes: int = 0
    @property
    def throughput(self) -> float: return self.completed / self.elapsed_seconds if self.elapsed_seconds > 0 else 0.0
    def efficiency(self, single: 'BenchmarkRecord') -> float:
        return self.throughput / (single.throughput * self.worker_count) if single.throughput and self.worker_count else 0.0

def write_benchmark(path: Path, records: list[BenchmarkRecord], *, optimum: BenchmarkRecord | None = None) -> None:
    doc = {"schema_version": "1.0.0", "records": [asdict(r) | {"throughput": r.throughput} for r in records], "optimum": asdict(optimum) if optimum else None}
    atomic_write_text(path, json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
