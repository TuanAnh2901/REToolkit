"""Acceptance: scope-content scans (no secrets, no proprietary files, no
game-specific constants in core, profile/fixture sync)."""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

GAME_KEY = "fc48e86b730833ef"
GAME_RVAS = ("0x434A60", "0x4268D0", "0x5CAFA0")


def _walk(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def test_no_shell_true_in_src() -> None:
    offenders = []
    for path in _walk(SRC):
        if path.suffix == ".py":
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"shell\s*=\s*True", text):
                offenders.append(str(path))
    assert offenders == []


def test_no_game_specific_constants_in_core() -> None:
    offenders = []
    for path in _walk(SRC):
        text = path.read_text(encoding="utf-8", errors="replace")
        if GAME_KEY in text:
            offenders.append(f"{path}: metadata key literal")
        for rva in GAME_RVAS:
            if rva in text:
                offenders.append(f"{path}: game RVA literal {rva}")
    assert offenders == []


def test_no_absolute_paths_in_committed_profiles() -> None:
    offenders = []
    for path in _walk(REPO_ROOT / "profiles"):
        if path.suffix == ".json":
            text = path.read_text(encoding="utf-8")
            if re.search(r'[A-Za-z]:\\', text):
                offenders.append(str(path))
    assert offenders == []


def test_no_large_or_proprietary_files_committed() -> None:
    large = []
    for path in _walk(REPO_ROOT):
        rel = path.relative_to(REPO_ROOT)
        if ".git" in rel.parts or "__pycache__" in rel.parts or path.suffix == ".pyc":
            continue
        if path.stat().st_size > 1_000_000:
            large.append(f"{rel} ({path.stat().st_size} bytes)")
    assert large == [], f"large files committed: {large}"


def test_no_credential_patterns() -> None:
    patterns = [r"-----BEGIN (?:RSA |EC |)PRIVATE KEY", r"sk-[A-Za-z0-9]{20,}"]
    offenders = []
    for path in _walk(REPO_ROOT):
        rel = path.relative_to(REPO_ROOT)
        if ".git" in rel.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in patterns:
            if re.search(pattern, text):
                offenders.append(f"{rel}: {pattern}")
    assert offenders == []


def test_profile_fixup_matches_fixture() -> None:
    profile = json.loads((REPO_ROOT / "profiles" / "everlusting" / "profile.json").read_text(encoding="utf-8"))
    fixture = json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "everlusting" / "fixup-config.json").read_text(encoding="utf-8")
    )
    assert profile["metadata_fixup"] == fixture


def test_resolver_is_resolve_only() -> None:
    source = (SRC / "retoolkit" / "runtime" / "resolver.js").read_text(encoding="utf-8")
    assert "Interceptor." not in source
    assert "Memory.write" not in source
    assert "writeByteArray" not in source
    assert "NativeCallback" not in source
