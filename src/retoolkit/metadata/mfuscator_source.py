"""Static evidence extraction from original and Mfuscator-modified libil2cpp source."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
import re
from typing import Iterable

from .mfuscator_contract import Evidence, ExportAlias, MfuscatorContract


_HEADER_RE = re.compile(
    r"typedef\s+struct\s+Il2CppGlobalMetadataHeader\s*\{(?P<body>.*?)\}"
    r"\s*Il2CppGlobalMetadataHeader\s*;",
    re.DOTALL,
)
_FIELD_RE = re.compile(r"\b(?:u?int32_t|int)\s+([A-Za-z_]\w*)\s*;")
_BIAS_RE = re.compile(
    r"s_GlobalMetadataHeader\s*->\s*[A-Za-z_]\w*\s*\+\s*(0x[0-9A-Fa-f]+|\d+)"
)
_API_RE = re.compile(
    r"DO_API(?:_NO_RETURN)?\s*\(\s*(?P<return>[^,]+?)\s*,\s*"
    r"(?P<name>[A-Za-z_]\w*)\s*,\s*\((?P<params>.*?)\)\s*\)\s*;",
    re.DOTALL,
)


def parse_randomized_header(source: str, canonical_names: Iterable[str]) -> dict[str, int]:
    """Return byte offsets for canonical fields embedded among randomized decoys."""
    match = _HEADER_RE.search(source)
    if match is None:
        raise ValueError("Il2CppGlobalMetadataHeader declaration was not found")
    canonical = set(canonical_names)
    result: dict[str, int] = {}
    for index, field_name in enumerate(_FIELD_RE.findall(match.group("body"))):
        if field_name not in canonical:
            continue
        if field_name in result:
            raise ValueError(f"duplicate canonical field: {field_name}")
        result[field_name] = index * 4
    return result


def infer_source_bias(source: str, *, minimum_support: int = 3) -> Evidence:
    """Infer the repeated constant added to metadata section offsets."""
    values = [int(raw, 0) for raw in _BIAS_RE.findall(source)]
    counts = Counter(values)
    if not counts:
        raise ValueError("no metadata source-bias expressions were found")
    ranked = counts.most_common()
    value, support = ranked[0]
    tied = len(ranked) > 1 and ranked[1][1] == support
    if support < minimum_support or tied:
        raise ValueError(f"no repeated source bias with support >= {minimum_support}")
    return Evidence(
        kind="source_bias",
        source="GlobalMetadata.cpp",
        value=value,
        support=support,
        confidence="confirmed" if support >= 3 else "inferred",
    )


def _normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _parse_api(source: str) -> list[tuple[str, str, str]]:
    return [
        (
            _normalize_space(match.group("return")),
            match.group("name"),
            _normalize_space(match.group("params")),
        )
        for match in _API_RE.finditer(source)
    ]


def infer_export_aliases(original_source: str, modified_source: str) -> tuple[ExportAlias, ...]:
    """Compare API declarations by ordinal and report signature-preserving renames."""
    original = _parse_api(original_source)
    modified = _parse_api(modified_source)
    if len(original) != len(modified):
        raise ValueError(
            f"API declaration count differs: original={len(original)}, modified={len(modified)}"
        )
    aliases: list[ExportAlias] = []
    for index, (before, after) in enumerate(zip(original, modified)):
        before_return, before_name, before_params = before
        after_return, after_name, after_params = after
        if (before_return, before_params) != (after_return, after_params):
            raise ValueError(f"API signature changed at declaration {index}")
        if before_name != after_name:
            aliases.append(
                ExportAlias(
                    canonical=before_name,
                    alias=after_name,
                    return_type=before_return,
                    parameters=before_params,
                )
            )
    return tuple(aliases)


def enrich_contract_from_sources(
    base: MfuscatorContract,
    modified_header_source: str,
    modified_runtime_source: str,
    original_api_source: str | None = None,
    modified_api_source: str | None = None,
    *,
    prefer_source_layout: bool = False,
) -> tuple[MfuscatorContract, dict[str, int]]:
    """Derive loader-layout evidence and merge it with a known contract."""
    canonical_names = {"sanity", "version"}
    for section in base.sections:
        canonical_names.add(f"{section.name}Offset")
        canonical_names.add(f"{section.name}Size")
    field_map = parse_randomized_header(modified_header_source, canonical_names)
    required_names = canonical_names - {"sanity", "version"}
    missing = sorted(required_names - field_map.keys())
    if missing:
        raise ValueError(f"randomized header is missing canonical field: {missing[0]}")

    bias = infer_source_bias(modified_runtime_source)
    source_sections = tuple(
        replace(
            section,
            custom_offset_field=field_map[f"{section.name}Offset"],
            custom_size_field=field_map[f"{section.name}Size"],
        )
        for section in base.sections
    )
    mismatch_count = sum(
        int(source.custom_offset_field != known.custom_offset_field)
        + int(source.custom_size_field != known.custom_size_field)
        for known, source in zip(base.sections, source_sections)
    )
    sections = source_sections if prefer_source_layout else base.sections
    aliases = base.export_aliases
    if (original_api_source is None) != (modified_api_source is None):
        raise ValueError("both original and modified API sources are required")
    if original_api_source is not None and modified_api_source is not None:
        aliases = infer_export_aliases(original_api_source, modified_api_source)
    layout_evidence = Evidence(
        kind="header_layout_mismatch" if mismatch_count else "header_layout_match",
        source="GlobalMetadataFileInternals.h",
        value=mismatch_count,
        support=len(base.sections) * 2,
        confidence="confirmed",
    )
    evidence = base.evidence + (
        bias,
        Evidence(
            kind="randomized_header_fields",
            source="GlobalMetadataFileInternals.h",
            value=len(field_map),
            support=len(field_map),
            confidence="confirmed",
        ),
        layout_evidence,
    )
    source_bias = int(bias.value) if prefer_source_layout or base.source_bias == 0 else base.source_bias
    return (
        replace(
            base,
            name=f"{base.name}-source-{'derived' if prefer_source_layout else 'evidenced'}",
            source_bias=source_bias,
            sections=sections,
            export_aliases=aliases,
            evidence=evidence,
        ),
        field_map,
    )
