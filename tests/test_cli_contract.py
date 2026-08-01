"""Task 2: CLI result/error/exit-code contract tests.

Every success and error path must emit exactly one JSON document on stdout,
with the exact exit code, and keep diagnostics on stderr.
"""

import json
import struct

import pytest

from retoolkit.cli import main
from retoolkit.contracts.result import ExitCode, ResultError
from retoolkit.metadata.xxtea import encrypt_header

INTERNAL_MSG = "synthetic internal error (test-only path)"


def _run(argv: list[str], capsys) -> tuple[int, dict, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    stdout = captured.out.strip()
    assert stdout.count("\n") <= 1, f"expected single JSON line, got: {stdout!r}"
    assert stdout, "stdout must not be empty"
    payload = json.loads(stdout)
    return code, payload, captured.out, captured.err


def test_success_version(capsys) -> None:
    code, payload, _, _ = _run(["--version"], capsys)
    assert code == ExitCode.OK
    assert payload["status"] == "ok"
    assert payload["schema_version"] == "1.0.0"
    assert payload["command"] == "version"
    assert "version" in payload["data"]


def test_internal_error_maps_to_5_with_traceback_on_stderr(capsys) -> None:
    code, payload, _, err = _run(["_err-test", "--code", "internal"], capsys)
    assert code == ExitCode.INTERNAL
    assert payload["status"] == "error"
    assert payload["error"]["code"] == "internal"
    assert "Traceback" in err


def test_every_exit_code_maps_to_canonical_error(capsys) -> None:
    expected = {
        "validation": ExitCode.VALIDATION,
        "missing_capability": ExitCode.MISSING_CAPABILITY,
        "timeout": ExitCode.TIMEOUT,
        "lock_conflict": ExitCode.LOCK_CONFLICT,
        "internal": ExitCode.INTERNAL,
    }
    for code_name, exit_code in expected.items():
        code, payload, _, _ = _run(["_err-test", "--code", code_name], capsys)
        assert code == exit_code, code_name
        assert payload["error"]["code"] == code_name, code_name


def test_interrupt_maps_to_130(capsys) -> None:
    code, payload, _, _ = _run(["_err-test", "--code", "interrupted"], capsys)
    assert code == ExitCode.INTERRUPTED
    assert payload["error"]["code"] == "interrupted"


def test_usage_error_is_validation_not_prose(capsys) -> None:
    code, payload, _, err = _run(["nonexistent-command"], capsys)
    assert code == ExitCode.VALIDATION
    assert payload["status"] == "error"
    assert "usage error" in payload["error"]["message"]


def test_diagnostics_never_on_stdout(capsys) -> None:
    _, payload, stdout, _ = _run(["_err-test", "--code", "timeout"], capsys)
    assert payload["status"] == "error"
    assert "Traceback" not in stdout


def test_result_error_exit_code_lookup() -> None:
    assert ResultError.validation("x").exit_code == ExitCode.VALIDATION
    assert ResultError.missing_capability("x").exit_code == ExitCode.MISSING_CAPABILITY
    assert ResultError.timeout("x").exit_code == ExitCode.TIMEOUT
    assert ResultError.lock_conflict("x").exit_code == ExitCode.LOCK_CONFLICT
    assert ResultError.internal("x").exit_code == ExitCode.INTERNAL


def test_mfuscator_inspect_writes_contract_and_report_to_selected_directory(
    tmp_path, capsys
) -> None:
    config = {
        "schema_version": "1.0.0",
        "header_prefix": "61626364",
        "header_offset": 4,
        "header_length": 64,
        "payload_start": 68,
        "preserved_tail_start": 16,
        "source_bias": 0,
        "metadata_magic": 0xFAB11BAF,
        "metadata_version": 31,
        "xxtea_key": "0123456789abcdef",
        "mutations": [],
        "sections": [
            {
                "index": 0,
                "name": "methods",
                "custom_offset_field": 4,
                "custom_size_field": 8,
            }
        ],
    }
    config_path = tmp_path / "fixup.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    header = bytearray(64)
    struct.pack_into("<II", header, 4, 80, 8)
    metadata = b"abcd" + encrypt_header(bytes(header), b"0123456789abcdef") + b"\0" * 64
    metadata_path = tmp_path / "metadata.dat"
    metadata_path.write_bytes(metadata)
    output = tmp_path / "Analysis2"

    code, payload, _, _ = _run(
        [
            "mfuscator",
            "inspect",
            "--metadata",
            str(metadata_path),
            "--config",
            str(config_path),
            "--output-dir",
            str(output),
        ],
        capsys,
    )

    assert code == ExitCode.OK
    assert payload["status"] == "ok"
    assert (output / "mfuscator-contract.json").is_file()
    assert (output / "mfuscator-analysis.json").is_file()
    assert (output / "global-metadata.rebuilt.dat").is_file()


def test_mfuscator_inspect_rejects_existing_analysis_directory(tmp_path, capsys) -> None:
    output = tmp_path / "Analysis"
    output.mkdir()

    code, payload, _, _ = _run(
        [
            "mfuscator",
            "inspect",
            "--metadata",
            str(tmp_path / "missing.dat"),
            "--config",
            str(tmp_path / "missing.json"),
            "--output-dir",
            str(output),
        ],
        capsys,
    )

    assert code == ExitCode.VALIDATION
    assert payload["error"]["code"] == "validation"
    assert "Analysis" in payload["error"]["message"]
