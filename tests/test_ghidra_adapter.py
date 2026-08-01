"""Task 11: Ghidra headless adapter tests against the FakeTool process double."""

import json
import shutil

import pytest

from retoolkit.adapters.ghidra import GhidraAdapter
from retoolkit.contracts.result import ResultError

LOG_TEMPLATE = """INFO  DecompileTargets.java> TARGET 180434a60
INFO  DecompileTargets.java> FUNCTION set_timeScale @ 180434a60
long UnityEngine_Time_set_timeScale(long param_1) {{
    return param_1 & 0x1;
}}
INFO  DecompileTargets.java> TARGET 1804268d0
INFO  DecompileTargets.java> FUNCTION_NOT_FOUND
"""


def _make_ghidra_root(tmp_path, fake_tool) -> None:
    support = tmp_path / "ghidra" / "support"
    support.mkdir(parents=True)
    # CreateProcess ignores file extension; a PE image named .bat runs fine,
    # so the FakeTool double stands in for analyzeHeadless.bat.
    shutil.copy2(fake_tool, support / "analyzeHeadless.bat")
    (tmp_path / "ghidra" / "Ghidra" / "application.properties").parent.mkdir(parents=True)
    (tmp_path / "ghidra" / "Ghidra" / "application.properties").write_text(
        "application.version=12.1.2", encoding="utf-8"
    )


def _write_log_behavior(tmp_path, work) -> str:
    lines = [f"append_line|{work}|analyzeHeadless.log|{line}" for line in LOG_TEMPLATE.splitlines()]
    path = tmp_path / "behavior.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _write_behavior(tmp_path, work, lines) -> str:
    path = tmp_path / "behavior.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_missing_install_raises_exit_2(tmp_path) -> None:
    with pytest.raises(ResultError) as exc:
        GhidraAdapter(tmp_path / "nope", scripts_dir=tmp_path)
    assert exc.value.exit_code == 2
    assert "analyzeHeadless" in exc.value.message


def test_refuses_existing_project_mutation(tmp_path, fake_tool, monkeypatch) -> None:
    _make_ghidra_root(tmp_path, fake_tool)
    work = tmp_path / "work"
    work.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "DecompileTargets.java").write_text("// script", encoding="utf-8")
    existing_project = tmp_path / "user-projects"
    existing_project.mkdir()
    (existing_project / "Everlusting.rep").mkdir()
    binary = tmp_path / "GameAssembly.dll"
    binary.write_bytes(b"x")
    adapter = GhidraAdapter(tmp_path / "ghidra", scripts_dir=scripts, timeout_seconds=30)
    with pytest.raises(ResultError) as exc:
        adapter.decompile_rvas(
            binary=binary,
            project_dir=existing_project,
            project_name="Everlusting",
            rvas=[0x434A60],
            output_dir=work,
        )
    assert exc.value.exit_code == 1
    assert "existing" in exc.value.message
    # source project untouched
    assert (existing_project / "Everlusting.rep").is_dir()


def test_successful_targeted_decompile(fake_tool, tmp_path, monkeypatch) -> None:
    _make_ghidra_root(tmp_path, fake_tool)
    work = tmp_path / "work"
    work.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "DecompileTargets.java").write_text("// script", encoding="utf-8")
    binary = tmp_path / "GameAssembly.dll"
    binary.write_bytes(b"x")
    log_path = work / "analyzeHeadless.log"
    behavior = _write_log_behavior(tmp_path, work)
    monkeypatch.setenv("FAKETOOL_BEHAVIOR", behavior)
    adapter = GhidraAdapter(tmp_path / "ghidra", scripts_dir=scripts, timeout_seconds=30)
    result = adapter.decompile_rvas(
        binary=binary,
        project_dir=tmp_path / "projects",
        project_name="fresh",
        rvas=[0x434A60, 0x4268D0],
        output_dir=work,
    )
    assert len(result.artifacts) == 2
    first = result.artifacts[0]
    assert first.status == "decompiled"
    assert first.function == "set_timeScale"
    assert first.path is not None and first.path.name == "decompile-180434a60.txt"
    assert first.sha256
    assert result.artifacts[1].status == "not_found"
    # argv recorded by the fake (in its cwd = output_dir); args exclude the
    # executable itself, so argv[0] is the first real argument (project_dir)
    argv = json.loads((work / "fake-argv.json").read_text(encoding="utf-8"))
    assert argv[0] == str(tmp_path / "projects")
    assert argv[-1] == str(log_path)
    assert argv.index("180434a60") < argv.index("1804268d0")
    assert "-postScript" in argv and "DecompileTargets.java" in argv
    assert "-noanalysis" in argv
