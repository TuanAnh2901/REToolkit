"""Task 8: Frida runner lifecycle tests using an injectable fake frida module."""

import pytest

from retoolkit.adapters.frida_runner import FridaRunConfig, FridaRunner
from retoolkit.contracts.result import ResultError
from tests.fakes.frida import FakeDevice, FakeFrida


def _run(config, frida):
    return FridaRunner(frida).run(config)


def test_attach_mode_ordered_jsonl_and_clean_detach() -> None:
    messages = [
        {"type": "send", "payload": {"event": "first"}},
        {"type": "send", "payload": {"event": "second"}},
        {"type": "send", "payload": {"event": "__retoolkit_done__"}},
    ]
    device = FakeDevice(messages, "__retoolkit_done__")
    frida = FakeFrida(device)
    result = _run(
        FridaRunConfig(mode="attach", target=1234, script_source="// js", timeout_seconds=5),
        frida,
    )
    assert result.sentinel_seen
    assert [m["message"]["payload"]["event"] for m in result.messages] == [
        "first",
        "second",
        "__retoolkit_done__",
    ]
    session = device.sessions[0]
    assert session.detached
    assert device.killed == []  # attach mode never kills


def test_spawn_mode_resumes_and_kills_child() -> None:
    messages = [{"type": "send", "payload": {"event": "__retoolkit_done__"}}]
    device = FakeDevice(messages, "__retoolkit_done__")
    frida = FakeFrida(device)
    _run(FridaRunConfig(mode="spawn", target="game.exe", script_source="// js", timeout_seconds=5), frida)
    assert device.spawned == ["game.exe"]
    assert device.resumed == [4242]
    assert device.killed == [4242]
    assert device.sessions[0].detached


def test_params_prepended_as_json() -> None:
    messages = [{"type": "send", "payload": {"event": "__retoolkit_done__"}}]
    device = FakeDevice(messages, "__retoolkit_done__")
    frida = FakeFrida(device)
    _run(
        FridaRunConfig(
            mode="attach",
            target=1,
            script_source="const p = __RETOOLKIT_PARAMS;",
            script_params={"rv": "0x5CAFA0", "z": 1, "a": "x"},
            timeout_seconds=5,
        ),
        frida,
    )
    source = device.sessions[0]._script.source
    assert "globalThis.__RETOOLKIT_PARAMS = {\"a\": \"x\", \"rv\": \"0x5CAFA0\", \"z\": 1};" in source
    assert "const p = __RETOOLKIT_PARAMS;" in source


def test_timeout_raises_exit_3_and_cleans_up() -> None:
    messages = [{"type": "send", "payload": {"event": "never-sentinel"}}]
    device = FakeDevice(messages, "__retoolkit_done__")
    frida = FakeFrida(device)
    with pytest.raises(ResultError) as exc:
        _run(FridaRunConfig(mode="spawn", target="game.exe", script_source="// js", timeout_seconds=0.2), frida)
    assert exc.value.exit_code == 3
    assert "sentinel" in exc.value.message
    session = device.sessions[0]
    assert session.detached
    assert device.killed == [4242]
