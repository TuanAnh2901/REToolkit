"""Process-tree termination shared by adapters (Windows-first)."""

from __future__ import annotations

import os
import subprocess


def kill_process_tree(pid: int) -> None:
    """Kill a process and its children via taskkill /T /F; best-effort."""
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.kill(pid, 9)
        except OSError:
            pass
