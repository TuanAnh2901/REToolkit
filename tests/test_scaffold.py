"""Task 1 smoke test: package imports, exposes its version, and enforces Python 3.13."""

import sys

import retoolkit
import retoolkit.__main__ as entry


def test_version_exposed() -> None:
    assert isinstance(retoolkit.__version__, str)
    assert retoolkit.__version__.count(".") >= 1


def test_unsupported_interpreter_fails_fast(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 12, 10))
    code = entry._guard()
    out = capsys.readouterr()
    assert code != 0
    assert "Python 3.13" in out.err
    assert "3.12" in out.err

