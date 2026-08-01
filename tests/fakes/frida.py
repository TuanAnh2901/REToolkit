"""Shared fake frida device/session/script for adapter tests."""

import threading
from types import SimpleNamespace


class FakeScript:
    def __init__(self, messages, sentinel, delay=0.0):
        self._messages = messages
        self._sentinel = sentinel
        self._delay = delay
        self.loaded = False
        self._handler = None
        self.source = None

    def on(self, event, handler):
        self._handler = handler

    def load(self):
        self.loaded = True
        if self._delay:
            threading.Timer(self._delay, self._emit).start()
        else:
            threading.Thread(target=self._emit, daemon=True).start()

    def _emit(self):
        for message in self._messages:
            self._handler(message, None)
            if self._sentinel in str(message):
                break


class FakeSession:
    def __init__(self, script):
        self._script = script
        self.detached = False

    def create_script(self, source):
        self._script.source = source
        return self._script

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, messages, sentinel, delay=0.0, processes=None):
        self._messages = messages
        self._sentinel = sentinel
        self._delay = delay
        self.processes = processes or []
        self.spawned = []
        self.resumed = []
        self.killed = []
        self.attached = []
        self.sessions = []

    def enumerate_processes(self):
        return [SimpleNamespace(**proc) if isinstance(proc, dict) else proc for proc in self.processes]

    def spawn(self, target):
        pid = 4242
        self.spawned.append(target)
        return pid

    def resume(self, pid):
        self.resumed.append(pid)

    def kill(self, pid):
        self.killed.append(pid)

    def attach(self, target):
        self.attached.append(target)
        script = FakeScript(self._messages, self._sentinel, delay=self._delay)
        session = FakeSession(script)
        self.sessions.append(session)
        return session


class FakeFrida:
    def __init__(self, device):
        self._device = device

    def get_usb_device_id(self):
        return "fake-usb"

    def get_device(self, device_id=None):
        return self._device
