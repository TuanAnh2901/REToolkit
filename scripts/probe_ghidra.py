"""Probe Ghidra headless availability and record the observed contract.

Ghidra is operator-installed; the toolkit never bundles it. When the
extracted root (or RETOOLKIT_GHIDRA) is absent this emits a deterministic
missing-capability contract with install guidance.

Usage:
  py -3.13 scripts/probe_ghidra.py [--root <ghidra-root>] [--out <contract.json>]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HEADLESS_REL = "support/analyzeHeadless.bat"


def find_root(explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_root = os.environ.get("RETOOLKIT_GHIDRA")
    if env_root:
        candidates.append(Path(env_root))
    for candidate in candidates:
        if (candidate / HEADLESS_REL).is_file():
            return candidate
    return None


def probe_version(root: Path) -> str | None:
    version_file = root / "Ghidra" / "application.properties"
    try:
        text = version_file.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"application.version\s*=\s*([^\s]+)", text)
    return match.group(1) if match else None


def run_probe(root_arg: str | None) -> dict:
    root = find_root(root_arg)
    if root is None:
        return {
            "schema_version": "1.0.0",
            "classification": "missing",
            "installed": False,
            "headless_path": None,
            "version": None,
            "install_guidance": (
                "Ghidra is not installed. Extract the archive (Java 21+), verify its "
                "SHA-256 first, then set tools.ghidra.path in the profile or "
                "RETOOLKIT_GHIDRA to the extracted root. Expected headless script: "
                f"<root>/{HEADLESS_REL}"
            ),
        }
    headless = root / HEADLESS_REL
    version = probe_version(root)
    return {
        "schema_version": "1.0.0",
        "classification": "ok",
        "installed": True,
        "root": str(root),
        "headless_path": str(headless),
        "version": version,
        "message": "analyzeHeadless found; targeted RVA runs are live-gated",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe Ghidra headless contract.")
    parser.add_argument("--root", help="path to extracted Ghidra root")
    args = parser.parse_args(argv)
    print(json.dumps(run_probe(args.root), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
