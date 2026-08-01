"""Acceptance: deterministic CLI contracts, stdout purity, portability."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PY = sys.executable


def _cli(*args, env_extra=None, cwd=None) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [PY, "-m", "retoolkit", *args],
        capture_output=True, text=True, cwd=cwd or REPO_ROOT, env=env, timeout=120,
    )


def test_cli_stdout_is_single_json_document() -> None:
    for argv in (["--version"], ["doctor"], ["_err-test", "--code", "timeout"]):
        proc = _cli(*argv)
        stdout = proc.stdout.strip()
        assert stdout.count("\n") == 0, f"{argv}: expected one JSON line"
        payload = json.loads(stdout)
        assert payload["schema_version"] == "1.0.0"


def test_exit_codes_are_stable() -> None:
    assert _cli("--version").returncode == 0
    assert _cli("_err-test", "--code", "timeout").returncode == 3
    assert _cli("_err-test", "--code", "lock_conflict").returncode == 4
    assert _cli("_err-test", "--code", "internal").returncode == 5
    assert _cli("nonexistent-command").returncode == 1


def test_canonical_output_is_byte_deterministic() -> None:
    first = _cli("doctor").stdout
    second = _cli("doctor").stdout
    assert first == second


def test_plan_is_zero_mutation(tmp_path) -> None:
    env = {
        "RETOOLKIT_GAME_ROOT": str(tmp_path),
        "RETOOLKIT_WORKSPACE": str(tmp_path / "ws"),
        "RETOOLKIT_CPP2IL": str(tmp_path / "cpp2il.exe"),
        "RETOOLKIT_CPP2IL_PLUGINS": str(tmp_path / "plugins"),
        "RETOOLKIT_GHIDRA": str(tmp_path / "ghidra"),
    }
    before = {p.name: p for p in tmp_path.iterdir()}
    proc = _cli("pipeline", "plan", "profiles/everlusting/profile.json", env_extra=env)
    assert proc.returncode == 0
    after = {p.name for p in tmp_path.iterdir()}
    assert set(before) == after  # nothing created in the profile root


def test_profile_fixture_mode_rejects_literal_absolute(tmp_path) -> None:
    profile = tmp_path / "bad.json"
    profile.write_text(
        json.dumps({
            "schema_version": "1.0.0", "name": "bad",
            "game": {"root": r"C:\committed", "game_assembly": "x", "metadata": "y"},
            "workspace": "ws",
        }),
        encoding="utf-8",
    )
    proc = _cli("profile", "validate", str(profile), "--fixture")
    assert proc.returncode == 1
    assert "not portable" in json.loads(proc.stdout)["error"]["message"]


def test_spaced_paths_work_end_to_end(tmp_path) -> None:
    spaced = tmp_path / "my workspace"
    spaced.mkdir()
    profile = spaced / "profile.json"
    profile.write_text(
        json.dumps({
            "schema_version": "1.0.0", "name": "spaced",
            "game": {"root": "${G}", "game_assembly": "${G}/GameAssembly.dll", "metadata": "${G}/m.dat"},
            "workspace": "${W}",
            "stages": {"cpp2il": False},
        }),
        encoding="utf-8",
    )
    proc = _cli("profile", "validate", str(profile), env_extra={"G": str(spaced), "W": str(spaced / "w")})
    assert proc.returncode == 0
    resolved = json.loads(proc.stdout)["data"]["resolved"]
    assert resolved["game_root"] == str(spaced)
