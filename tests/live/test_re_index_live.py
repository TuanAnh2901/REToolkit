"""Current-build RE-index acceptance gate.

This test is deliberately opt-in.  It imports the normalized map already
present in the selected profile workspace and compares the result with the
known current-build count.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from retoolkit.commands.index import build_index
from tests.live.gates import gate_enabled


@pytest.mark.live
def test_current_build_indexes_all_methods() -> None:
    enabled, reason = gate_enabled("cpp2il")
    if not enabled:
        pytest.skip(reason)
    value = os.environ.get("RETOOLKIT_PROFILE")
    if not value:
        pytest.skip("RETOOLKIT_PROFILE not set")
    profile = Path(value)
    if not profile.is_file():
        pytest.skip(f"RETOOLKIT_PROFILE path missing: {profile}")

    result = build_index(profile)

    assert result["method_count"] == 206366
