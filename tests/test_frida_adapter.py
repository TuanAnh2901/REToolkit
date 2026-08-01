"""Task 13: resolver-aware Frida adapter tests."""

import json

import pytest

from retoolkit.adapters.frida import FridaAdapter
from retoolkit.contracts.result import ResultError
from tests.fakes.frida import FakeDevice, FakeFrida

SENTINEL_MSG = {"type": "send", "payload": {"type": "trace", "event": "__retoolkit_done__"}}


def _adapter(tmp_path, messages, processes=None, target_factory=None):
    device = FakeDevice(messages, "__retoolkit_done__", processes=processes)
    frida = FakeFrida(device)
    adapter = FridaAdapter(frida, timeout_seconds=5)
    trace = tmp_path / "trace.js"
    trace.write_text("send({type: 'trace', event: 'probe'});\n", encoding="utf-8")
    return adapter, device, trace


def test_composes_resolver_and_trace_in_order(tmp_path) -> None:
    from retoolkit.adapters.frida import RESOLVER_PATH

    messages = [
        {"type": "send", "payload": {"event": "first"}},
        SENTINEL_MSG,
    ]
    adapter, device, trace = _adapter(tmp_path, messages, processes=[{"pid": 7, "name": "game.exe"}])
    adapter.run_trace(target="game.exe", trace_script=trace, params={"targets": [["A.B", "M", 0]]})
    source = device.sessions[0]._script.source
    assert "retoolkitResolver" in source
    assert "globalThis.__RETOOLKIT_PARAMS" in source
    assert source.index("globalThis.__RETOOLKIT_PARAMS") < source.index("retoolkitResolver")
    assert source.endswith("send({type: 'trace', event: 'probe'});\n")
    assert device.attached == [7]
    assert device.sessions[0].detached


def test_ambiguous_process_raises_exit_1_with_candidates(tmp_path) -> None:
    messages = [SENTINEL_MSG]
    adapter, device, trace = _adapter(
        tmp_path,
        messages,
        processes=[
            {"pid": 1, "name": "game.exe"},
            {"pid": 2, "name": "game_launcher.exe"},
        ],
    )
    with pytest.raises(ResultError) as exc:
        adapter.run_trace(target="game", trace_script=trace, params={})
    assert exc.value.exit_code == 1
    assert "ambiguous" in exc.value.message
    assert len(exc.value.details["candidates"]) == 2
    assert device.attached == []  # no attach happened


def test_explicit_pid_skips_selection(tmp_path) -> None:
    messages = [SENTINEL_MSG]
    adapter, device, trace = _adapter(tmp_path, messages)
    adapter.run_trace(target=99, trace_script=trace, params={})
    assert device.attached == [99]


def test_write_jsonl_records_evidence(tmp_path) -> None:
    messages = [
        {"type": "send", "payload": {"event": "a"}},
        SENTINEL_MSG,
    ]
    out = tmp_path / "evidence" / "trace.jsonl"
    FridaAdapter.write_jsonl(messages, out)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["payload"]["event"] == "a"
    assert json.loads(lines[1])["payload"]["event"] == "__retoolkit_done__"


def test_timeout_propagates_exit_3(tmp_path) -> None:
    messages = [{"type": "send", "payload": {"event": "never"}}]
    adapter, device, trace = _adapter(tmp_path, messages, processes=[{"pid": 5, "name": "game.exe"}])
    adapter.timeout_seconds = 0.2
    with pytest.raises(ResultError) as exc:
        adapter.run_trace(target="game.exe", trace_script=trace, params={})
    assert exc.value.exit_code == 3
    assert device.sessions[0].detached
