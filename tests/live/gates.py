"""Shared live-gate helpers: deterministic opt-in for real tool/game runs."""

from __future__ import annotations

import os


def gate_enabled(name: str) -> tuple[bool, str]:
    """Return (enabled, reason). Live tests skip deterministically when the
    matching RETOOLKIT_LIVE_<NAME> variable is not exactly '1'."""
    var = f"RETOOLKIT_LIVE_{name.upper()}"
    if os.environ.get(var) != "1":
        return False, f"{var} not set to 1"
    return True, ""
