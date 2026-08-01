"""Deterministic target sharding and conservative worker selection."""
from __future__ import annotations
from dataclasses import dataclass
from .models import GhidraTarget

@dataclass(frozen=True)
class HostResources:
    logical_cpus: int
    available_bytes: int
    measured_worker_bytes: int

@dataclass(frozen=True)
class Batch:
    targets: tuple[GhidraTarget, ...]

@dataclass(frozen=True)
class WorkerPlan:
    worker_id: int
    batches: tuple[Batch, ...]

@dataclass(frozen=True)
class GhidraPlan:
    workers: tuple[WorkerPlan, ...]
    worker_count: int
    target_ids: tuple[int, ...]
    @property
    def jvm_launches(self) -> int:
        return sum(len(worker.batches) for worker in self.workers)

def choose_workers(resources: HostResources, *, configured_max: int) -> int:
    if configured_max < 1 or resources.logical_cpus < 1:
        raise ValueError("worker limits must be positive")
    cpu_limit = max(1, resources.logical_cpus - 2)
    memory_limit = max(1, resources.available_bytes // max(resources.measured_worker_bytes, 1))
    return max(1, min(configured_max, cpu_limit, memory_limit))

class GhidraPlanner:
    def plan(self, targets, *, mode: str = "parallel", workers: int = 1,
             batch_size: int = 128, resources: HostResources | None = None,
             configured_max: int | None = None) -> GhidraPlan:
        if mode not in {"parallel", "serial"}: raise ValueError("mode must be parallel or serial")
        if batch_size < 1: raise ValueError("batch_size must be positive")
        ordered = tuple(sorted(targets, key=lambda t: (t.rva, t.identity, t.target_id)))
        count = workers if resources is None else choose_workers(resources, configured_max=configured_max or workers)
        count = max(1, min(count, max(1, len(ordered))))
        batches = [Batch(ordered[i:i + batch_size]) for i in range(0, len(ordered), batch_size)]
        slots = [[] for _ in range(count)]
        for index, batch in enumerate(batches): slots[index % count].append(batch)
        plans = tuple(WorkerPlan(i, tuple(slots[i])) for i in range(count))
        return GhidraPlan(plans, count, tuple(t.target_id for t in ordered))
