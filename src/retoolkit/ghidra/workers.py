"""Concurrent worker coordination and deterministic shard merging."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable
from .models import GhidraRecord
from .planner import GhidraPlan, WorkerPlan

@dataclass(frozen=True)
class WorkerResult:
    worker_id: int
    records: tuple[GhidraRecord, ...]

def merge_shards(shards: list[WorkerResult], *, expected_target_ids: tuple[int, ...]) -> tuple[GhidraRecord, ...]:
    rows: dict[int, GhidraRecord] = {}
    for shard in shards:
        for row in shard.records:
            old = rows.get(row.target_id)
            if old is not None and old != row: raise ValueError(f"conflicting duplicate target {row.target_id}")
            rows[row.target_id] = row
    missing = set(expected_target_ids) - rows.keys()
    if missing: raise ValueError(f"missing target records: {sorted(missing)}")
    return tuple(rows[target_id] for target_id in sorted(expected_target_ids))

class GhidraExecutor:
    def __init__(self, runner: Callable[[WorkerPlan, bool], tuple[GhidraRecord, ...]]): self.runner = runner
    def execute(self, plan: GhidraPlan, *, resume: bool = False) -> tuple[GhidraRecord, ...]:
        with ThreadPoolExecutor(max_workers=plan.worker_count) as pool:
            futures = [pool.submit(self.runner, worker, resume) for worker in plan.workers]
            shards = [WorkerResult(worker.worker_id, future.result()) for worker, future in zip(plan.workers, futures)]
        return merge_shards(shards, expected_target_ids=plan.target_ids)
