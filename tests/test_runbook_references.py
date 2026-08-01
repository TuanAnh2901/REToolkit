"""Task 21: runbook reference validation.

Checks that every file/tool path referenced in the runbooks resolves, and
that the documented artifact verification commands actually run against
fixture output.
"""

import base64
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOKS = REPO_ROOT / "docs" / "runbooks"


def _run_powershell(command: str) -> subprocess.CompletedProcess:
    # -EncodedCommand avoids quoting loss when the command text is itself a
    # nested py -c invocation with quotes
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=60,
    )

PATH_REFERENCE = re.compile(r"`([^`]+\.(?:c|txt|json|dll|dat|bat|exe|java))`")

# artifacts resolved by the profile/workspace at runtime, not repo files
RUNTIME_ARTIFACTS = {
    "GameAssembly.dll",
    "method-map.normalized.json",
    "global-metadata.dat",
}


def _referenced_paths(runbook: Path) -> list[str]:
    text = runbook.read_text(encoding="utf-8")
    paths = []
    for line in text.splitlines():
        for match in PATH_REFERENCE.finditer(line):
            candidate = match.group(1)
            if "<" in candidate or candidate.startswith(("D:", "C:")):
                continue  # operator-supplied placeholder or machine path
            paths.append(candidate)
    return paths


@pytest.mark.parametrize("runbook", sorted(RUNBOOKS.glob("*.md")))
def test_runbook_references_resolve(runbook: Path) -> None:
    for reference in _referenced_paths(runbook):
        if reference in RUNTIME_ARTIFACTS:
            continue
        candidate = REPO_ROOT / reference
        assert candidate.exists() or candidate.is_dir(), f"{runbook.name}: {reference} missing"


def test_ghidra_runbook_verification_command_runs_on_fixture(tmp_path) -> None:
    runbook = (RUNBOOKS / "ghidra-gui.md").read_text(encoding="utf-8")
    verify_match = re.search(r"```powershell\n(.+?)\n```", runbook, re.DOTALL)
    assert verify_match, "runbook must end with a powershell verification block"
    command = verify_match.group(1).replace("<workspace>", str(tmp_path))
    artifact = tmp_path / "ghidra-gui" / "decompile-0x180434a60.c"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        "int f() { return 1; }\n/* padded decompile output for the fixture verification */\n"
        "/* second padded line so the artifact comfortably exceeds the 100-byte threshold */\n",
        encoding="utf-8",
    )
    proc = _run_powershell(command)
    assert proc.returncode == 0, proc.stderr


def test_x64dbg_runbook_verification_command_handles_missing_dir(tmp_path) -> None:
    runbook = (RUNBOOKS / "x64dbg.md").read_text(encoding="utf-8")
    verify_match = re.search(r"```powershell\n(.+?)\n```", runbook, re.DOTALL)
    command = verify_match.group(1).replace("<workspace>", str(tmp_path))
    proc = _run_powershell(command)
    assert proc.returncode == 1  # no captures yet -> documented non-zero


def test_runbooks_have_stop_conditions_and_verification() -> None:
    for runbook in RUNBOOKS.glob("*.md"):
        text = runbook.read_text(encoding="utf-8")
        assert "Stop conditions" in text, f"{runbook.name} lacks stop conditions"
        assert "verification" in text.lower(), f"{runbook.name} lacks verification command"
        assert "Prerequisites" in text, f"{runbook.name} lacks prerequisites"
