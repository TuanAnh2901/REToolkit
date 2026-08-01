"""Atomic linear pipeline state and per-workspace locking.

State lives at ``<workspace>/state.json`` and is always replaced atomically.
Resume semantics: a stage is skippable only when its status is ``completed``
and its recorded per-stage input hash equals the hash computed for the current
run. A changed global input hash (profile/tools/inputs) makes the whole state
stale and requires an explicit ``--restart``.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate
from retoolkit.core.atomic import atomic_write_text

SCHEMA = "state.schema.json"
SCHEMA_VERSION = "1.0.0"
STATE_FILE = "state.json"
LOCK_FILE = ".retoolkit.lock"

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


@dataclass
class StageState:
    name: str
    status: str = STATUS_PENDING
    input_hash: str | None = None
    evidence: str | None = None

    @classmethod
    def from_dict(cls, doc: dict) -> "StageState":
        return cls(name=doc["name"], status=doc["status"], input_hash=doc.get("input_hash"), evidence=doc.get("evidence"))

    def to_dict(self) -> dict:
        result = {"name": self.name, "status": self.status}
        if self.input_hash:
            result["input_hash"] = self.input_hash
        if self.evidence:
            result["evidence"] = self.evidence
        return result


@dataclass
class PipelineState:
    workspace: Path
    run_id: str
    input_hash: str
    stages: list[StageState] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = self.workspace / STATE_FILE

    @classmethod
    def load_or_create(
        cls,
        workspace: Path,
        stages: list[str],
        input_hash: str,
        *,
        run_id: str | None = None,
        force_restart: bool = False,
    ) -> "PipelineState":
        workspace.mkdir(parents=True, exist_ok=True)
        path = workspace / STATE_FILE
        if path.exists() and not force_restart:
            state = cls._load(path, workspace)
            if state.input_hash != input_hash:
                raise ResultError.validation(
                    "pipeline state is stale (inputs, profile, or tool versions changed); "
                    "rerun with --restart to discard it",
                    details={"state": str(path), "recorded_hash": state.input_hash, "current_hash": input_hash},
                )
            return state
        run_id = run_id or _make_run_id()
        state = cls(workspace=workspace, run_id=run_id, input_hash=input_hash)
        state.stages = [StageState(name=stage) for stage in stages]
        state.save()
        return state

    @classmethod
    def _load(cls, path: Path, workspace: Path) -> "PipelineState":
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ResultError.validation(
                f"pipeline state is corrupt or unreadable: {path}: {exc}; "
                "rerun with --restart to discard it"
            ) from None
        errors = validate(doc, SCHEMA)
        if errors:
            raise ResultError.validation(
                f"pipeline state failed validation: {path}; rerun with --restart to discard it",
                details=errors,
            )
        return cls(
            workspace=workspace,
            run_id=doc["run_id"],
            input_hash=doc["input_hash"],
            stages=[StageState.from_dict(stage) for stage in doc["stages"]],
        )

    def save(self) -> None:
        doc = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "input_hash": self.input_hash,
            "workspace": str(self.workspace),
            "stages": [stage.to_dict() for stage in self.stages],
        }
        atomic_write_text(self.path, json.dumps(doc, sort_keys=True, indent=2))

    def stage(self, name: str) -> StageState:
        for stage in self.stages:
            if stage.name == name:
                return stage
        raise KeyError(f"no stage named {name}")

    def can_skip(self, name: str, current_input_hash: str) -> bool:
        stage = self.stage(name)
        return stage.status == STATUS_COMPLETED and stage.input_hash == current_input_hash

    def set_status(
        self,
        name: str,
        status: str,
        *,
        input_hash: str | None = None,
        evidence: str | None = None,
    ) -> None:
        stage = self.stage(name)
        stage.status = status
        if input_hash is not None:
            stage.input_hash = input_hash
        if evidence is not None:
            stage.evidence = evidence
        self.save()

    def first_incomplete(self, input_hashes: dict[str, str]) -> str | None:
        for stage in self.stages:
            if not self.can_skip(stage.name, input_hashes.get(stage.name, "")):
                return stage.name
        return None


def _make_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{os.getpid()}"


class WorkspaceLock:
    """Exclusive workspace lock via O_EXCL lock file. Held by a live PID it
    reports a conflict (exit 4); a stale lock from a dead PID is stolen."""

    def __init__(self, workspace: Path) -> None:
        self.path = workspace / LOCK_FILE

    def __enter__(self) -> "WorkspaceLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                holder = self._read_holder()
                if holder is not None and not _pid_alive(holder["pid"]):
                    self.path.unlink(missing_ok=True)
                    continue
                raise ResultError.lock_conflict(
                    "workspace is locked by another retoolkit process",
                    details={"lock_path": str(self.path), "holder": holder},
                ) from None
            os.write(fd, json.dumps({"pid": os.getpid(), "created": datetime.now(timezone.utc).isoformat()}).encode())
            os.close(fd)
            return

    def release(self) -> None:
        self.path.unlink(missing_ok=True)

    def _read_holder(self) -> dict | None:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None


def _pid_alive(pid: int) -> bool:
    # os.kill(pid, 0) can hang on Windows when the process exists; use
    # OpenProcess instead.
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError):
        return False


def hash_inputs(parts: list[str]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\x00")
    return digest.hexdigest()
