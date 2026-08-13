"""Resolver-aware Frida adapter: composes the shared resolver with a
read-only trace script, selects the target process, and records JSONL
evidence. All shipped scripts are resolve-only (no hooks, no memory writes).
"""

from __future__ import annotations

import json
from pathlib import Path

from retoolkit.adapters.frida_runner import FridaRunConfig, FridaRunner
from retoolkit.contracts.result import ResultError

RESOLVER_PATH = Path(__file__).resolve().parent.parent / "runtime" / "resolver.js"
SENTINEL = "__retoolkit_done__"


class FridaAdapter:
    def __init__(
        self,
        frida_module=None,
        *,
        resolver_source: str | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        self._frida = frida_module
        self._resolver_source = resolver_source
        self.timeout_seconds = timeout_seconds

    def _device(self):
        if self._frida is None:
            import frida

            self._frida = frida
        device_id = (self._frida.get_usb_device_id()
                      if hasattr(self._frida, "get_usb_device_id") else None)
        if device_id:
            return self._frida.get_device(device_id)
        if hasattr(self._frida, "get_local_device"):
            return self._frida.get_local_device()
        return self._frida.get_device(None)

    def select_pid(self, target: str | int) -> int:
        if isinstance(target, int):
            return target
        device = self._device()
        processes = list(device.enumerate_processes())
        matches = [proc for proc in processes if target.lower() in proc.name.lower()]
        if len(matches) == 1:
            return matches[0].pid
        candidates = [{"pid": proc.pid, "name": proc.name} for proc in matches]
        if len(matches) > 1:
            raise ResultError.validation(
                f"ambiguous process selection for '{target}'; pass an explicit pid",
                details={"candidates": candidates},
            )
        raise ResultError.validation(
            f"no process matches '{target}'", details={"processes": len(processes)}
        )

    def run_trace(
        self,
        *,
        target: str | int,
        trace_script: Path | str,
        params: dict,
        mode: str = "attach",
        sentinel: str = SENTINEL,
        on_message=None,
    ) -> list[dict]:
        # Attach/spawn callers may construct the adapter without injecting a
        # Frida module. Resolve it here before handing control to the generic
        # runner; otherwise FridaRunner receives None and fails before device
        # selection.
        if self._frida is None:
            import frida
            self._frida = frida
        script_source = (self._resolver_source or RESOLVER_PATH.read_text(encoding="utf-8"))
        trace_source = Path(trace_script).read_text(encoding="utf-8")
        combined = script_source + "\n" + trace_source
        pid = self.select_pid(target)
        config = FridaRunConfig(
            mode=mode,
            target=pid,
            script_source=combined,
            script_params=params,
            timeout_seconds=self.timeout_seconds,
            sentinel=sentinel,
        )
        result = FridaRunner(self._frida).run(config, on_message=on_message)
        return result.messages

    @staticmethod
    def write_jsonl(messages: list[dict], path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(message, sort_keys=True) for message in messages]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
