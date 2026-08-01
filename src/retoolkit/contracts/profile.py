"""Portable profile loading with strict validation and runtime path resolution.

Committed profiles contain no absolute paths. Values either use ``${ENV_VAR}``
templates (resolved from the environment at runtime) or are relative paths
resolved against the profile's own directory (which must not escape it).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from retoolkit.contracts.result import ResultError
from retoolkit.contracts.schema import validate

ENV_TEMPLATE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

SCHEMA = "profile.schema.json"
SCHEMA_VERSION = "1.0.0"

_STAGE_NAMES = ("fixup", "cpp2il", "frida", "ghidra")


@dataclass
class ToolConfig:
    path: Path | None = None
    plugin_dir: Path | None = None
    timeout_seconds: int = 120


@dataclass
class Profile:
    name: str
    schema_version: str
    game_root: Path
    game_assembly: Path
    metadata: Path
    workspace: Path
    tools: dict[str, ToolConfig] = field(default_factory=dict)
    stages: dict[str, bool] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


def _substitute(value: str, env: dict[str, str], field_name: str) -> str:
    def repl(match: re.Match) -> str:
        var = match.group(1)
        if var not in env or not env[var]:
            raise ResultError.validation(
                f"profile.{field_name}: environment variable {var} is not set"
            )
        return env[var]

    return ENV_TEMPLATE.sub(repl, value)


def _resolve_path(
    value: str,
    base_dir: Path,
    env: dict[str, str],
    field_name: str,
    reject_absolute: bool,
) -> Path:
    had_template = bool(ENV_TEMPLATE.search(value))
    resolved_str = _substitute(value, env, field_name) if had_template else value
    candidate = Path(resolved_str)
    if candidate.is_absolute():
        # reject only committed literal absolutes; env-derived paths are runtime values
        if reject_absolute and not had_template:
            raise ResultError.validation(
                f"profile.{field_name}: absolute path '{resolved_str}' in a committed "
                "profile is not portable; use ${ENV_VAR} or a relative path"
            )
        return candidate
    resolved = (base_dir / candidate).resolve()
    if not resolved.is_relative_to(base_dir):
        raise ResultError.validation(
            f"profile.{field_name}: relative path '{value}' escapes the profile directory"
        )
    return resolved


def load_profile(
    path: str | Path,
    *,
    env: dict[str, str] | None = None,
    reject_absolute: bool = False,
) -> Profile:
    profile_path = Path(path)
    try:
        doc = __import__("json").loads(profile_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ResultError.validation(f"profile file not found: {profile_path}") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise ResultError.validation(
            f"profile file is not valid JSON: {profile_path}: {exc}"
        ) from None

    schema_errors = validate(doc, SCHEMA)
    if schema_errors:
        raise ResultError.validation(
            f"profile '{profile_path}' failed validation", details=schema_errors
        )

    base_dir = profile_path.resolve().parent
    env = dict(os.environ if env is None else env)
    errors: list[str] = []
    resolved: dict[str, Path] = {}

    for field_name in ("root", "game_assembly", "metadata"):
        try:
            resolved[field_name] = _resolve_path(
                doc["game"][field_name], base_dir, env, f"game.{field_name}", reject_absolute
            )
        except ResultError as exc:
            errors.append(exc.message)

    try:
        resolved["workspace"] = _resolve_path(
            doc["workspace"], base_dir, env, "workspace", reject_absolute
        )
    except ResultError as exc:
        errors.append(exc.message)

    tools: dict[str, ToolConfig] = {}
    for tool_name, tool_doc in doc.get("tools", {}).items():
        cfg = ToolConfig(timeout_seconds=int(tool_doc.get("timeout_seconds", 120)))
        for key in ("path", "plugin_dir"):
            if key in tool_doc:
                try:
                    setattr(cfg, key, _resolve_path(tool_doc[key], base_dir, env, f"tools.{tool_name}.{key}", reject_absolute))
                except ResultError as exc:
                    errors.append(exc.message)
        tools[tool_name] = cfg

    if errors:
        raise ResultError.validation(
            f"profile '{profile_path}' failed path resolution: {'; '.join(errors)}",
            details=errors,
        )

    stages = {name: bool(doc.get("stages", {}).get(name, False)) for name in _STAGE_NAMES}

    return Profile(
        name=doc["name"],
        schema_version=doc["schema_version"],
        game_root=resolved["root"],
        game_assembly=resolved["game_assembly"],
        metadata=resolved["metadata"],
        workspace=resolved["workspace"],
        tools=tools,
        stages=stages,
        raw=doc,
    )
