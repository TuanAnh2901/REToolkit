"""CLI result contract: one JSON document on stdout, diagnostics on stderr.

Exit codes are part of the public contract:
    0    success
    1    validation failure (bad input, bad state, unsafe path)
    2    missing required capability (tool not found)
    3    timeout (external process exceeded its budget)
    4    lock/conflict (workspace already in use)
    5    internal error (unexpected exception)
    130  interrupted (KeyboardInterrupt)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class ExitCode(IntEnum):
    OK = 0
    VALIDATION = 1
    MISSING_CAPABILITY = 2
    TIMEOUT = 3
    LOCK_CONFLICT = 4
    INTERNAL = 5
    INTERRUPTED = 130


ERROR_CODES: dict[ExitCode, str] = {
    ExitCode.VALIDATION: "validation",
    ExitCode.MISSING_CAPABILITY: "missing_capability",
    ExitCode.TIMEOUT: "timeout",
    ExitCode.LOCK_CONFLICT: "lock_conflict",
    ExitCode.INTERNAL: "internal",
    ExitCode.INTERRUPTED: "interrupted",
}

SCHEMA_VERSION = "1.0.0"


class ResultError(Exception):
    """Error carrying a machine-readable code and a user-facing message.

    Raised anywhere in the toolkit; the CLI layer converts it into the
    canonical JSON error result and maps it to the matching exit code.
    """

    def __init__(self, code: str, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    @classmethod
    def validation(cls, message: str, *, details: Any = None) -> "ResultError":
        return cls(ERROR_CODES[ExitCode.VALIDATION], message, details=details)

    @classmethod
    def missing_capability(cls, message: str, *, details: Any = None) -> "ResultError":
        return cls(ERROR_CODES[ExitCode.MISSING_CAPABILITY], message, details=details)

    @classmethod
    def timeout(cls, message: str, *, details: Any = None) -> "ResultError":
        return cls(ERROR_CODES[ExitCode.TIMEOUT], message, details=details)

    @classmethod
    def lock_conflict(cls, message: str, *, details: Any = None) -> "ResultError":
        return cls(ERROR_CODES[ExitCode.LOCK_CONFLICT], message, details=details)

    @classmethod
    def internal(cls, message: str, *, details: Any = None) -> "ResultError":
        return cls(ERROR_CODES[ExitCode.INTERNAL], message, details=details)

    @property
    def exit_code(self) -> int:
        for code, name in ERROR_CODES.items():
            if name == self.code:
                return int(code)
        return int(ExitCode.INTERNAL)


@dataclass
class Result:
    """Canonical CLI result document. Serialized with sorted keys for
    byte-deterministic output across runs."""

    status: str = "ok"
    command: str = ""
    exit_code: int = ExitCode.OK
    data: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)

    @classmethod
    def ok(cls, command: str, data: dict[str, Any] | None = None) -> "Result":
        return cls(status="ok", command=command, exit_code=int(ExitCode.OK), data=data or {})

    @classmethod
    def from_error(
        cls, command: str, err: ResultError | Exception, *, exit_code: int | None = None
    ) -> "Result":
        if isinstance(err, ResultError):
            code = err.code
            message = err.message
            details = err.details
            ec = exit_code if exit_code is not None else err.exit_code
        else:
            code = ERROR_CODES[ExitCode.INTERNAL]
            message = f"{type(err).__name__}: {err}"
            details = None
            ec = exit_code if exit_code is not None else int(ExitCode.INTERNAL)
        error = {"code": code, "message": message}
        if details is not None:
            error["details"] = details
        return cls(
            status="error",
            command=command,
            exit_code=ec,
            error=error,
        )
