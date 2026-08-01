"""CLI entry point. All stdout is exactly one JSON document; diagnostics and
tracebacks go to stderr. Exit codes follow the contract in contracts/result.py."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

from retoolkit import __version__
from retoolkit.commands.index import register_index_commands
from retoolkit.commands.target import register_target_commands
from retoolkit.commands.native import register_native_commands
from retoolkit.commands.ghidra import register_ghidra_commands
from retoolkit.commands.dossier import register_dossier_commands
from retoolkit.contracts.result import ERROR_CODES, ExitCode, Result, ResultError


class _Parser(argparse.ArgumentParser):
    """Argparse variant that routes usage errors through the JSON contract
    instead of printing prose to stdout."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise ResultError.validation(f"usage error: {message}")


class _VersionAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        result = Result.ok("version", {"version": __version__})
        print(result.to_json())
        parser.exit(int(ExitCode.OK))


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="retoolkit",
        description="Unity IL2CPP reverse-engineering toolkit. "
        "All stdout is one JSON document.",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON (default; retained for explicitness)"
    )
    parser.add_argument(
        "--version",
        action=_VersionAction,
        nargs=0,
        help="print version as JSON and exit",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    register_native_commands(sub)
    register_ghidra_commands(sub)
    register_dossier_commands(sub)
    register_index_commands(sub)
    register_target_commands(sub)

    # Hidden command used by tests/QA to exercise error paths deterministically.
    p_err = sub.add_parser("_err-test", help=argparse.SUPPRESS)
    p_err.add_argument(
        "--code",
        required=True,
        choices=sorted(ERROR_CODES.values()) + ["interrupted"],
        help="synthetic error code to raise",
    )
    p_err.set_defaults(handler=_cmd_err_test)

    p_profile = sub.add_parser("profile", help="profile operations")
    psub = p_profile.add_subparsers(dest="profile_command", required=True)
    pv = psub.add_parser("validate", help="validate a profile file and resolve its paths")
    pv.add_argument("path", help="path to profile.json")
    pv.add_argument(
        "--fixture",
        action="store_true",
        help="reject absolute committed paths (portability check for committed profiles)",
    )
    pv.set_defaults(handler=_cmd_profile_validate)

    p_doctor = sub.add_parser("doctor", help="probe local tool capabilities")
    p_doctor.add_argument("--cpp2il-path", help="explicit Cpp2IL executable path")
    p_doctor.add_argument("--ghidra-root", help="explicit extracted Ghidra root")
    p_doctor.set_defaults(handler=_cmd_doctor)

    p_mfuscator = sub.add_parser("mfuscator", help="Mfuscator metadata operations")
    msub = p_mfuscator.add_subparsers(dest="mfuscator_command", required=True)
    p_inspect = msub.add_parser(
        "inspect", help="rebuild metadata and emit a source-assisted loader report"
    )
    p_inspect.add_argument("--metadata", required=True, help="protected global-metadata.dat")
    source_group = p_inspect.add_mutually_exclusive_group()
    source_group.add_argument("--config", help="metadata_fixup JSON document")
    source_group.add_argument("--profile", help="REToolkit profile containing metadata_fixup")
    p_inspect.add_argument("--modified-header", help="modified GlobalMetadataFileInternals.h")
    p_inspect.add_argument("--modified-runtime", help="modified GlobalMetadata.cpp")
    p_inspect.add_argument("--original-api", help="original il2cpp-api-functions.h")
    p_inspect.add_argument("--modified-api", help="modified il2cpp-api-functions.h")
    p_inspect.add_argument("--output-dir", required=True, help="new analysis output directory")
    p_inspect.set_defaults(handler=_cmd_mfuscator_inspect)

    p_pipeline = sub.add_parser("pipeline", help="linear analysis pipeline")
    psub2 = p_pipeline.add_subparsers(dest="pipeline_command", required=True)
    p_plan = psub2.add_parser("plan", help="list ordered stages without side effects")
    p_plan.add_argument("profile", help="path to profile.json")
    p_plan.set_defaults(handler=_cmd_pipeline_plan)
    for subcommand in ("run", "resume", "restart"):
        parser_run = psub2.add_parser(subcommand, help=f"{subcommand} the pipeline")
        parser_run.add_argument("profile", help="path to profile.json")
        parser_run.set_defaults(handler=_cmd_pipeline_run, pipeline_action=subcommand)

    return parser


def _cmd_profile_validate(args: argparse.Namespace) -> Result:
    from retoolkit.contracts.profile import load_profile

    profile = load_profile(Path(args.path), reject_absolute=args.fixture)
    data = {
        "name": profile.name,
        "schema_version": profile.schema_version,
        "resolved": {
            "game_root": str(profile.game_root),
            "game_assembly": str(profile.game_assembly),
            "metadata": str(profile.metadata),
            "workspace": str(profile.workspace),
        },
        "tools": sorted(profile.tools),
        "stages": profile.stages,
    }
    return Result.ok("profile validate", data)


def _cmd_doctor(args: argparse.Namespace) -> Result:
    import os

    from retoolkit.core.capabilities import discover, report

    cpp2il_path = args.cpp2il_path or os.environ.get("RETOOLKIT_CPP2IL")
    ghidra_root = args.ghidra_root or os.environ.get("RETOOLKIT_GHIDRA")
    capabilities = discover(cpp2il_path=cpp2il_path, ghidra_root=ghidra_root)
    return Result.ok("doctor", report(capabilities))


def _read_json_object(path: Path) -> dict:
    import json

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ResultError.validation(f"JSON file not found: {path}") from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise ResultError.validation(f"invalid JSON file {path}: {exc}") from None
    if not isinstance(value, dict):
        raise ResultError.validation(f"JSON root must be an object: {path}")
    return value


def _read_text(path: str | None, label: str) -> str | None:
    if path is None:
        return None
    source_path = Path(path)
    try:
        return source_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ResultError.validation(f"{label} file not found: {source_path}") from None
    except UnicodeDecodeError as exc:
        raise ResultError.validation(f"{label} is not UTF-8: {source_path}: {exc}") from None


def _cmd_mfuscator_inspect(args: argparse.Namespace) -> Result:
    import hashlib
    import json

    from retoolkit.core.atomic import atomic_write_bytes, atomic_write_text
    from retoolkit.metadata.mfuscator import FixupConfig, rebuild_with_report
    from retoolkit.metadata.mfuscator_source import enrich_contract_from_sources

    output_dir = Path(args.output_dir).resolve()
    if any(part.casefold() == "analysis" for part in output_dir.parts):
        raise ResultError.validation(
            f"output directory may not use an existing Analysis path: {output_dir}"
        )

    config_path = Path(args.config) if args.config else None
    if args.profile:
        config_path = Path(args.profile)
    if config_path is None:
        config_path = Path(__file__).resolve().parents[2] / "profiles" / "everlusting" / "profile.json"
    config_document = _read_json_object(config_path)
    fixup_document = config_document.get("metadata_fixup", config_document)
    if not isinstance(fixup_document, dict):
        raise ResultError.validation(f"metadata_fixup must be an object: {config_path}")
    config = FixupConfig.from_doc(fixup_document)
    contract = config.to_contract(name=config_path.stem)

    modified_header = _read_text(args.modified_header, "modified header")
    modified_runtime = _read_text(args.modified_runtime, "modified runtime")
    original_api = _read_text(args.original_api, "original API")
    modified_api = _read_text(args.modified_api, "modified API")
    field_map: dict[str, int] = {}
    if (modified_header is None) != (modified_runtime is None):
        raise ResultError.validation(
            "--modified-header and --modified-runtime must be supplied together"
        )
    if modified_header is not None and modified_runtime is not None:
        try:
            contract, field_map = enrich_contract_from_sources(
                contract,
                modified_header,
                modified_runtime,
                original_api,
                modified_api,
            )
        except ValueError as exc:
            raise ResultError.validation(f"source-assisted inference failed: {exc}") from None

    metadata_path = Path(args.metadata)
    try:
        metadata = metadata_path.read_bytes()
    except FileNotFoundError:
        raise ResultError.validation(f"metadata file not found: {metadata_path}") from None
    rebuilt, validation = rebuild_with_report(metadata, contract)

    output_dir.mkdir(parents=True, exist_ok=True)
    contract_path = output_dir / "mfuscator-contract.json"
    report_path = output_dir / "mfuscator-analysis.json"
    rebuilt_path = output_dir / "global-metadata.rebuilt.dat"
    analysis = {
        "contract": contract.name,
        "input": str(metadata_path.resolve()),
        "input_sha256": hashlib.sha256(metadata).hexdigest(),
        "rebuilt_sha256": hashlib.sha256(rebuilt).hexdigest(),
        "header_field_count": len(field_map),
        "header_fields": field_map,
        "source_bias": contract.source_bias,
        "evidence": [
            {
                "kind": item.kind,
                "source": item.source,
                "value": item.value,
                "support": item.support,
                "confidence": item.confidence,
            }
            for item in contract.evidence
        ],
        "export_aliases": [
            {
                "canonical": item.canonical,
                "alias": item.alias,
                "return_type": item.return_type,
                "parameters": item.parameters,
            }
            for item in contract.export_aliases
        ],
        "validation": validation.to_dict(),
    }
    atomic_write_text(contract_path, contract.to_json() + "\n")
    atomic_write_text(report_path, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    atomic_write_bytes(rebuilt_path, rebuilt)
    return Result.ok(
        "mfuscator inspect",
        {
            "contract": str(contract_path),
            "report": str(report_path),
            "rebuilt_metadata": str(rebuilt_path),
            "accepted": validation.accepted,
            "score": validation.score,
        },
    )


def _cmd_pipeline_plan(args: argparse.Namespace) -> Result:
    from retoolkit.contracts.profile import load_profile
    from retoolkit.core.pipeline import plan

    profile = load_profile(Path(args.profile))
    return Result.ok("pipeline plan", plan(profile))


def _cmd_pipeline_run(args: argparse.Namespace) -> Result:
    from retoolkit.contracts.profile import load_profile
    from retoolkit.core.pipeline import run_pipeline

    profile = load_profile(Path(args.profile))
    data = run_pipeline(profile, force_restart=args.pipeline_action == "restart")
    return Result.ok(f"pipeline {args.pipeline_action}", data)


def _cmd_err_test(args: argparse.Namespace) -> Result:
    if args.code == "interrupted":
        raise KeyboardInterrupt()
    if args.code == "internal":
        raise RuntimeError("synthetic internal error (test-only path)")
    raise ResultError(args.code, f"synthetic {args.code} error (test-only path)")


def _command_name(args: argparse.Namespace | None) -> str:
    if args is None:
        return ""
    return str(getattr(args, "command", "") or "")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args: argparse.Namespace | None = None
    try:
        # --json is a documented no-op (stdout is always JSON); accept it anywhere.
        if argv is None:
            argv = sys.argv[1:]
        argv = [token for token in argv if token != "--json"]
        args = parser.parse_args(argv)
        handler: Callable[[argparse.Namespace], Result] = args.handler
        result = handler(args)
        print(result.to_json())
        return int(result.exit_code)
    except SystemExit as exc:
        # --version terminates parsing via parser.exit with the canonical code.
        if isinstance(exc.code, int) and exc.code in (int(ExitCode.OK), int(ExitCode.INTERRUPTED)):
            return exc.code
        raise
    except KeyboardInterrupt:
        result = Result.from_error(
            _command_name(args), ResultError(ERROR_CODES[ExitCode.INTERRUPTED], "interrupted")
        )
        print(result.to_json())
        return int(ExitCode.INTERRUPTED)
    except ResultError as err:
        result = Result.from_error(_command_name(args), err)
        print(result.to_json())
        return int(result.exit_code)
    except Exception as err:  # noqa: BLE001 - the contract requires mapping every failure
        traceback.print_exc(file=sys.stderr)
        result = Result.from_error(_command_name(args), err)
        print(result.to_json())
        return int(result.exit_code)


if __name__ == "__main__":
    sys.exit(main())
