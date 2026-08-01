"""Typed records shared by RE-index import, query, and reporting services."""

from dataclasses import dataclass


@dataclass(frozen=True)
class MethodRecord:
    """A method from a normalized Cpp2IL method map."""

    id: int
    assembly: str
    type_name: str
    method_name: str
    signature: str
    rva: int
    pointer: int | None
    collision_key: str


@dataclass(frozen=True)
class ArtifactRecord:
    """A reproducible analysis artifact emitted during an indexed run."""

    logical_name: str
    path: str
    sha256: str
    producer: str
    run_id: str


@dataclass(frozen=True)
class TargetQuery:
    """A bounded method selector for index-only target discovery."""

    assembly: str | None = None
    namespace: str | None = None
    type_pattern: str | None = None
    method_pattern: str | None = None
    identity: str | None = None
    rva: int | None = None
    limit: int = 100

    def __post_init__(self) -> None:
        selectors = (
            self.assembly,
            self.namespace,
            self.type_pattern,
            self.method_pattern,
            self.identity,
            self.rva,
        )
        if not any(value is not None for value in selectors):
            raise ValueError("at least one selector is required")
        if not 1 <= self.limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
