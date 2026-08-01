"""Probe a local Cpp2IL build and record the observed CLI contract.

Read-only against the game; everything runs against temp copies. Emits one
JSON document on stdout: either a full observed contract (go) or a
classification of why the tool is unusable (missing / incompatible).

Usage:
  py -3.13 scripts/probe_cpp2il.py
      --exe <path>
      [--game-assembly <path> --metadata <path> --unity-version <v>]
      [--plugin-dir <path>] [--output-to <dir>]
      [--export-method-map]      # default; runs the full export probe
      [--version-only]           # quick classification without full export
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

CRASH_EXIT = -532462766  # 0xE0434352 unhandled .NET exception
CRASH_SIGNATURE = "Reflection-based serialization has been disabled"


def classify(exe: Path) -> str:
    if not exe.is_file():
        return "missing"
    return "ok"


def run_probe(args: argparse.Namespace) -> dict:
    exe = Path(args.exe)
    state = classify(exe)
    if state != "ok":
        return {
            "schema_version": "1.0.0",
            "classification": state,
            "exe": str(exe),
            "message": "Cpp2IL executable not found",
            "install_guidance": "Configure tools.cpp2il.path in the profile to a Cpp2IL executable.",
        }

    if args.version_only:
        proc = subprocess.run(
            [str(exe), "--version"], capture_output=True, text=True, timeout=30
        )
        return {
            "schema_version": "1.0.0",
            "classification": "ok",
            "exe": str(exe),
            "version_probe": {"exit_code": proc.returncode},
        }

    if not (args.game_assembly and args.metadata):
        sys.stderr.write("--game-assembly and --metadata required unless --version-only\n")
        raise SystemExit(2)

    output_to = Path(args.output_to)
    output_to.mkdir(parents=True, exist_ok=True)
    argv = [
        str(exe),
        "--force-binary-path",
        str(Path(args.game_assembly)),
        "--force-metadata-path",
        str(Path(args.metadata)),
        "--force-unity-version",
        args.unity_version,
        "--export-method-map",
        "--output-to",
        str(output_to),
    ]
    cwd = Path(args.plugin_dir).parent if args.plugin_dir else None
    started = time.monotonic()
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, timeout=args.timeout)
    duration = round(time.monotonic() - started, 3)

    combined = proc.stdout + proc.stderr
    if proc.returncode == CRASH_EXIT and CRASH_SIGNATURE in combined:
        return {
            "schema_version": "1.0.0",
            "classification": "incompatible",
            "exe": str(exe),
            "exit_code": proc.returncode,
            "duration_seconds": duration,
            "message": "Cpp2IL --export-method-map crashes: reflection-based JSON serialization "
            "is disabled (PublishTrimmed build). Use a non-trimmed local build and set "
            "System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault=true in its "
            "Cpp2IL.runtimeconfig.json (see research/cpp2il-contract.md).",
        }

    map_path = output_to / "method-pointer-map.json"
    entries = []
    if map_path.is_file():
        with open(map_path, encoding="utf-8") as handle:
            entries = json.load(handle)

    return {
        "schema_version": "1.0.0",
        "classification": "ok" if proc.returncode == 0 else "failed",
        "exe": str(exe),
        "exit_code": proc.returncode,
        "duration_seconds": duration,
        "method_count": len(entries),
        "output_file": str(map_path),
        "output_size_bytes": map_path.stat().st_size if map_path.is_file() else None,
        "argv": argv,
        "plugin_dir": str(Path(args.plugin_dir).resolve()) if args.plugin_dir else None,
        "message": "observed method map export" if proc.returncode == 0 else "non-zero exit",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe local Cpp2IL contract.")
    parser.add_argument("--exe", required=True)
    parser.add_argument("--game-assembly")
    parser.add_argument("--metadata")
    parser.add_argument("--unity-version", default="6000.1.4f1")
    parser.add_argument("--plugin-dir")
    parser.add_argument("--output-to", default="cpp2il-probe-out")
    parser.add_argument("--version-only", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    print(json.dumps(run_probe(args), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
