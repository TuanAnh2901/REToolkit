"""Generic Frida runner: spawn/attach, script load, JSONL message capture,
sentinel completion, timeout, and deterministic cleanup.

The frida module is injected so tests use a fake device/session/script
without a live process. Script parameters are prepended to the script source
as ``globalThis.__RETOOLKIT_PARAMS`` (no RPC round-trip needed).

Cleanup contract: attach mode detaches the session; spawn mode additionally
kills the spawned child. Timeout raises ResultError.timeout (exit 3) after
cleanup.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from retoolkit.contracts.result import ResultError


@dataclass
class FridaRunConfig:
    mode: str  # "attach" | "spawn"
    target: Any  # pid (int) for attach, process name for spawn
    script_source: str
    script_params: dict = field(default_factory=dict)
    timeout_seconds: float = 30.0
    sentinel: str = "__retoolkit_done__"


@dataclass
class FridaRunResult:
    messages: list[dict] = field(default_factory=list)
    sentinel_seen: bool = False


def _sentinel_markers(message: dict) -> list[str]:
    """Candidate sentinel strings from a frida message: top-level payload
    string, or the values of a payload dict."""
    payload = message.get("payload", {})
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, dict):
        return [str(value) for value in payload.values()]
    return []


class FridaRunner:
    """Executes one script against one target and collects its messages."""

    def __init__(self, frida_module: Any) -> None:
        self._frida = frida_module

    def run(self, config: FridaRunConfig) -> FridaRunResult:
        device = self._frida.get_device(
            self._frida.get_usb_device_id()
            if hasattr(self._frida, "get_usb_device_id")
            else None
        )
        spawned_pid: int | None = None
        session = None
        try:
            if config.mode == "spawn":
                spawned_pid = device.spawn(config.target)
                session = device.attach(spawned_pid)
            else:
                session = device.attach(config.target)

            source = self._preamble(config.script_params) + config.script_source
            script = session.create_script(source)
            result = FridaRunResult()
            completed = threading.Event()

            def on_message(message: dict, data: Any) -> None:
                entry = {"message": message}
                if data is not None:
                    try:
                        entry["data"] = data.decode("utf-8", errors="replace")
                    except AttributeError:
                        entry["data"] = str(data)
                result.messages.append(entry)
                if config.sentinel in _sentinel_markers(message):
                    result.sentinel_seen = True
                    completed.set()

            script.on("message", on_message)
            script.load()
            if config.mode == "spawn":
                device.resume(spawned_pid)

            completed.wait(config.timeout_seconds)
            if not result.sentinel_seen:
                raise ResultError.timeout(
                    f"frida script did not reach sentinel '{config.sentinel}' "
                    f"within {config.timeout_seconds}s"
                )
            return result
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
            if spawned_pid is not None:
                try:
                    device.kill(spawned_pid)
                except Exception:
                    pass

    @staticmethod
    def _preamble(params: dict) -> str:
        encoded = json.dumps(params, sort_keys=True)
        return f"globalThis.__RETOOLKIT_PARAMS = {encoded};\n"
