"""Task 5: atomic linear pipeline state and locking tests."""

import json

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.core.state import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_RUNNING,
    WorkspaceLock,
    hash_inputs,
)
from retoolkit.core.state import PipelineState

STAGES = ["validate", "fixup", "cpp2il", "normalize"]


def _h(value):
    return hash_inputs([value])


def test_create_save_load_roundtrip_is_schema_valid(tmp_path) -> None:
    state = PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    assert state.first_incomplete({}) == "validate"
    state.set_status("validate", STATUS_COMPLETED, input_hash=_h("validate"))
    state.set_status("cpp2il", STATUS_FAILED)
    loaded = PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    assert loaded.stage("validate").status == STATUS_COMPLETED
    assert loaded.stage("cpp2il").status == STATUS_FAILED


def test_resume_skips_only_completed_with_matching_hash(tmp_path) -> None:
    state = PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    state.set_status("validate", STATUS_COMPLETED, input_hash=_h("validate"))
    state.set_status("fixup", STATUS_COMPLETED, input_hash=_h("fixup"))
    state.set_status("cpp2il", STATUS_FAILED)
    hashes = {"validate": _h("validate"), "fixup": _h("fixup"), "cpp2il": _h("cpp2il")}
    assert state.first_incomplete(hashes) == "cpp2il"
    assert state.can_skip("validate", _h("validate"))
    assert not state.can_skip("cpp2il", _h("cpp2il"))


def test_changed_stage_input_hash_forces_rerun(tmp_path) -> None:
    state = PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    state.set_status("validate", STATUS_COMPLETED, input_hash=_h("old-validate"))
    assert not state.can_skip("validate", _h("new-validate"))
    assert state.first_incomplete({"validate": _h("new-validate")}) == "validate"


def test_interrupted_running_stage_is_rerun(tmp_path) -> None:
    state = PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    state.set_status("cpp2il", STATUS_RUNNING)
    assert not state.can_skip("cpp2il", _h("cpp2il"))


def test_stale_global_hash_rejected_with_restart_hint(tmp_path) -> None:
    PipelineState.load_or_create(tmp_path, STAGES, _h("old-inputs"))
    with pytest.raises(ResultError) as exc:
        PipelineState.load_or_create(tmp_path, STAGES, _h("new-inputs"))
    assert exc.value.exit_code == 1
    assert "--restart" in exc.value.message


def test_force_restart_discards_stale_state(tmp_path) -> None:
    PipelineState.load_or_create(tmp_path, STAGES, _h("old-inputs"))
    state = PipelineState.load_or_create(tmp_path, STAGES, _h("new-inputs"), force_restart=True)
    assert state.input_hash == _h("new-inputs")
    assert state.first_incomplete({}) == "validate"


def test_corrupt_state_rejected_with_restart_hint(tmp_path) -> None:
    PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    state_file = tmp_path / "state.json"
    state_file.write_text('{"schema_version": "1.0.0", "stages": [', encoding="utf-8")
    with pytest.raises(ResultError) as exc:
        PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    assert exc.value.exit_code == 1
    assert "--restart" in exc.value.message


def test_schema_violating_state_rejected(tmp_path) -> None:
    PipelineState.load_or_create(tmp_path, STAGES, _h("in"))
    doc = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    doc["stages"][0]["status"] = "bogus-status"
    (tmp_path / "state.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ResultError):
        PipelineState.load_or_create(tmp_path, STAGES, _h("in"))


def test_lock_conflict_raises_exit_4(tmp_path) -> None:
    first = WorkspaceLock(tmp_path)
    first.acquire()
    try:
        second = WorkspaceLock(tmp_path)
        with pytest.raises(ResultError) as exc:
            second.acquire()
        assert exc.value.exit_code == 4
    finally:
        first.release()


def test_stale_lock_from_dead_pid_is_stolen(tmp_path) -> None:
    lock = WorkspaceLock(tmp_path)
    lock.path.write_text(json.dumps({"pid": 99999999, "created": "2026-01-01T00:00:00+00:00"}), encoding="utf-8")
    lock.acquire()  # must not raise
    lock.release()
    assert not lock.path.exists()
