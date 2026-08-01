"""Task 3: versioned profile schema and portable loader tests."""

import json

import pytest

from retoolkit.contracts.profile import load_profile
from retoolkit.contracts.result import ResultError

MINIMAL = {
    "schema_version": "1.0.0",
    "name": "test-game",
    "game": {
        "root": "${GAME_ROOT}",
        "game_assembly": "${GAME_ROOT}/GameAssembly.dll",
        "metadata": "${GAME_ROOT}/Data/global-metadata.dat",
    },
    "workspace": "${WORKSPACE}",
    "tools": {
        "cpp2il": {"path": "${CPP2IL}", "timeout_seconds": 30},
    },
    "stages": {"cpp2il": True},
}


def _write(tmp_path, doc, name="profile.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _env(tmp_path):
    return {
        "GAME_ROOT": str(tmp_path / "game dir with spaces"),
        "WORKSPACE": str(tmp_path / "workspace"),
        "CPP2IL": str(tmp_path / "cpp2il.exe"),
    }


def test_valid_minimal_profile_resolves(tmp_path) -> None:
    path = _write(tmp_path, MINIMAL)
    profile = load_profile(path, env=_env(tmp_path))
    assert profile.name == "test-game"
    assert profile.game_root == (tmp_path / "game dir with spaces").resolve()
    assert profile.game_assembly == (tmp_path / "game dir with spaces" / "GameAssembly.dll").resolve()
    assert profile.workspace == (tmp_path / "workspace").resolve()
    assert profile.tools["cpp2il"].timeout_seconds == 30
    assert profile.stages == {"fixup": False, "cpp2il": True, "frida": False, "ghidra": False}


def test_unknown_key_rejected_with_field_error(tmp_path) -> None:
    doc = dict(MINIMAL, unknwon_key="typo")
    path = _write(tmp_path, doc)
    with pytest.raises(ResultError) as exc:
        load_profile(path, env=_env(tmp_path))
    assert exc.value.exit_code == 1
    assert "unknwon_key" in str(exc.value.details)


def test_missing_schema_version_rejected(tmp_path) -> None:
    doc = {k: v for k, v in MINIMAL.items() if k != "schema_version"}
    path = _write(tmp_path, doc)
    with pytest.raises(ResultError):
        load_profile(path, env=_env(tmp_path))


def test_absolute_committed_path_rejected_in_fixture_mode(tmp_path) -> None:
    doc = json.loads(json.dumps(MINIMAL))
    doc["workspace"] = r"C:\Users\someone\absolute-workspace"
    path = _write(tmp_path, doc)
    with pytest.raises(ResultError) as exc:
        load_profile(path, env=_env(tmp_path), reject_absolute=True)
    assert "absolute path" in exc.value.message
    assert exc.value.exit_code == 1


def test_missing_env_var_reported(tmp_path) -> None:
    path = _write(tmp_path, MINIMAL)
    with pytest.raises(ResultError) as exc:
        load_profile(path, env={})  # no GAME_ROOT
    assert "GAME_ROOT" in exc.value.message


def test_relative_path_escaping_profile_dir_rejected(tmp_path) -> None:
    doc = json.loads(json.dumps(MINIMAL))
    doc["workspace"] = "../../outside"
    path = _write(tmp_path, doc)
    with pytest.raises(ResultError) as exc:
        load_profile(path, env=_env(tmp_path))
    assert "escapes" in exc.value.message


def test_relative_path_within_profile_dir_ok(tmp_path) -> None:
    doc = json.loads(json.dumps(MINIMAL))
    doc["game"] = {
        "root": "game",
        "game_assembly": "game/GameAssembly.dll",
        "metadata": "game/global-metadata.dat",
    }
    doc["workspace"] = "work"
    del doc["tools"]  # no env templates in this test
    (tmp_path / "game").mkdir()
    (tmp_path / "work").mkdir()
    path = _write(tmp_path, doc)
    profile = load_profile(path, env={})
    assert profile.game_root == (tmp_path / "game").resolve()


def test_validation_error_details_are_field_level(tmp_path) -> None:
    doc = json.loads(json.dumps(MINIMAL))
    doc["stages"] = {"cooking": True}  # unknown stage name
    path = _write(tmp_path, doc)
    with pytest.raises(ResultError) as exc:
        load_profile(path, env=_env(tmp_path))
    details = " ".join(str(d) for d in exc.value.details)
    assert "cooking" in details
