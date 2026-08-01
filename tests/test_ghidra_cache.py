from dataclasses import asdict, replace
import json

import pytest

from retoolkit.ghidra.cache import GhidraProjectCache
from retoolkit.ghidra.models import GhidraCacheKey


def _key() -> GhidraCacheKey:
    return GhidraCacheKey(
        binary_sha256="a" * 64,
        ghidra_version="11.4",
        loader="PeLoader",
        script_sha256="b" * 64,
        analyzer_profile="minimal",
        image_base=0x180000000,
    )


def test_cache_key_changes_for_every_semantic_input() -> None:
    base = _key()
    assert base.digest() == GhidraCacheKey(**asdict(base)).digest()
    for field, value in {
        "binary_sha256": "d" * 64,
        "ghidra_version": "11.5",
        "loader": "Raw Binary",
        "script_sha256": "c" * 64,
        "analyzer_profile": "balanced",
        "image_base": 0x140000000,
    }.items():
        assert replace(base, **{field: value}).digest() != base.digest()


def test_project_has_deterministic_owned_paths_and_key_metadata(tmp_path) -> None:
    project = GhidraProjectCache(tmp_path).project(_key())
    project.initialize()

    assert project.root == tmp_path / _key().digest()
    assert project.project_file == project.root / "project.gpr"
    assert project.repository_dir == project.root / "project.rep"
    assert project.key_metadata == project.root / "cache-key.json"
    assert project.import_marker == project.root / "import-complete.json"
    assert project.lock_file == project.root / ".lock"
    assert project.replicas_dir == project.root / "replicas"
    assert project.replicas_dir.is_dir()
    assert json.loads(project.key_metadata.read_text(encoding="utf-8")) == {
        **asdict(_key()),
        "digest": _key().digest(),
        "schema_version": "1.0.0",
    }


def test_import_marker_published_only_for_successful_existing_project(tmp_path) -> None:
    project = GhidraProjectCache(tmp_path).project(_key())
    project.initialize()

    with pytest.raises(RuntimeError, match="exit code 7"):
        project.publish_import(exit_code=7, expected_program=project.repository_dir / "A")
    assert not project.import_marker.exists()

    project.project_file.touch()
    project.repository_dir.mkdir()
    expected = project.repository_dir / "A"
    with pytest.raises(FileNotFoundError, match="expected Ghidra program"):
        project.publish_import(exit_code=0, expected_program=expected)
    assert not project.import_marker.exists()

    expected.touch()
    project.publish_import(exit_code=0, expected_program=expected)
    marker = json.loads(project.import_marker.read_text(encoding="utf-8"))
    assert marker["cache_key"] == _key().digest()
    assert marker["expected_program"] == "project.rep/A"
    assert project.is_import_complete()


def test_replica_path_rejects_unsafe_names(tmp_path) -> None:
    project = GhidraProjectCache(tmp_path).project(_key())
    project.initialize()
    assert project.replica("worker-01") == project.replicas_dir / "worker-01"
    for value in ("", "../escape", "a/b", ".", "C:"):
        with pytest.raises(ValueError, match="replica"):
            project.replica(value)


def test_project_lock_has_bounded_exclusive_lifetime(tmp_path) -> None:
    project = GhidraProjectCache(tmp_path).project(_key())
    with project.acquire_lock():
        assert project.lock_file.is_file()
        with pytest.raises(TimeoutError, match="cache lock"):
            with project.acquire_lock(timeout_seconds=0):
                pass
    assert not project.lock_file.exists()
