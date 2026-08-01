"""Shared JSON Schema loading and validation for all canonical contracts."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas"


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate(instance: dict, schema_name: str) -> list[str]:
    """Return human-readable validation error messages; empty when valid."""
    validator = Draft202012Validator(load_schema(schema_name))
    messages = []
    for error in validator.iter_errors(instance):
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        messages.append(f"{path}: {error.message}")
    return messages
