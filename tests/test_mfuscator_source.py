from __future__ import annotations

import pytest

from retoolkit.metadata.mfuscator_source import (
    enrich_contract_from_sources,
    infer_export_aliases,
    infer_source_bias,
    parse_randomized_header,
)
from retoolkit.metadata.mfuscator_contract import MfuscatorContract, SectionContract


def test_parse_randomized_header_ignores_decoys_and_returns_byte_offsets() -> None:
    source = """
        typedef struct Il2CppGlobalMetadataHeader {
            int32_t fakeA;
            int32_t methodsOffset;
            int32_t fakeB;
            int32_t methodsSize;
            int32_t sanity;
            int32_t version;
        } Il2CppGlobalMetadataHeader;
    """

    result = parse_randomized_header(
        source, {"methodsOffset", "methodsSize", "sanity", "version"}
    )

    assert result == {
        "methodsOffset": 4,
        "methodsSize": 12,
        "sanity": 16,
        "version": 20,
    }


def test_parse_randomized_header_rejects_duplicate_canonical_field() -> None:
    source = """
        typedef struct Il2CppGlobalMetadataHeader {
            int32_t methodsOffset;
            int32_t methodsOffset;
        } Il2CppGlobalMetadataHeader;
    """

    with pytest.raises(ValueError, match="duplicate canonical field"):
        parse_randomized_header(source, {"methodsOffset"})


def test_infer_source_bias_requires_repeated_agreement() -> None:
    source = """
        s_GlobalMetadataHeader->methodsOffset + 484;
        s_GlobalMetadataHeader->typeDefinitionsOffset + 484;
        s_GlobalMetadataHeader->fieldsOffset + 12;
    """

    result = infer_source_bias(source, minimum_support=2)

    assert result.value == 484
    assert result.support == 2
    assert result.kind == "source_bias"


def test_infer_source_bias_rejects_tie() -> None:
    source = """
        s_GlobalMetadataHeader->methodsOffset + 484;
        s_GlobalMetadataHeader->fieldsOffset + 12;
    """

    with pytest.raises(ValueError, match="no repeated source bias"):
        infer_source_bias(source, minimum_support=2)


def test_infer_export_aliases_matches_same_api_slot_and_signature() -> None:
    original = """
        DO_API(int, il2cpp_init, (const char*));
        DO_API(const Il2CppAssembly**, il2cpp_domain_get_assemblies,
            (const Il2CppDomain*, size_t*));
    """
    modified = """
        DO_API(int, il2cpp_init, (const char*));
        DO_API(const Il2CppAssembly**, ab626d_wasting_your_life,
            (const Il2CppDomain*, size_t*));
    """

    aliases = infer_export_aliases(original, modified)

    assert len(aliases) == 1
    assert aliases[0].canonical == "il2cpp_domain_get_assemblies"
    assert aliases[0].alias == "ab626d_wasting_your_life"


def test_enrich_contract_replaces_section_fields_and_records_evidence() -> None:
    base = MfuscatorContract(
        name="base",
        metadata_magic=0xFAB11BAF,
        metadata_version=31,
        header_prefix=b"abcd",
        header_offset=4,
        header_length=24,
        payload_start=28,
        preserved_tail_start=16,
        source_bias=0,
        xxtea_key=b"0123456789abcdef",
        sections=(SectionContract("methods", 0, 4),),
    )
    header = """typedef struct Il2CppGlobalMetadataHeader {
        int32_t fake; int32_t methodsOffset; int32_t methodsSize;
        int32_t sanity; int32_t version;
    } Il2CppGlobalMetadataHeader;"""
    runtime = """
        s_GlobalMetadataHeader->methodsOffset + 484;
        s_GlobalMetadataHeader->methodsOffset + 484;
        s_GlobalMetadataHeader->methodsOffset + 484;
    """

    enriched, field_map = enrich_contract_from_sources(
        base, header, runtime, prefer_source_layout=True
    )

    assert field_map["methodsOffset"] == 4
    assert enriched.sections[0].custom_offset_field == 4
    assert enriched.sections[0].custom_size_field == 8
    assert enriched.source_bias == 484
    assert enriched.evidence[0].support == 3


def test_enrich_contract_preserves_known_layout_when_source_layout_conflicts() -> None:
    base = MfuscatorContract(
        name="known-build",
        metadata_magic=0xFAB11BAF,
        metadata_version=31,
        header_prefix=b"abcd",
        header_offset=4,
        header_length=24,
        payload_start=28,
        preserved_tail_start=16,
        source_bias=484,
        xxtea_key=b"0123456789abcdef",
        sections=(SectionContract("methods", 12, 16),),
    )
    conflicting_header = """typedef struct Il2CppGlobalMetadataHeader {
        int32_t methodsOffset; int32_t methodsSize;
        int32_t sanity; int32_t version;
    } Il2CppGlobalMetadataHeader;"""
    runtime = "\n".join(
        ["s_GlobalMetadataHeader->methodsOffset + 484;" for _ in range(3)]
    )

    enriched, _ = enrich_contract_from_sources(base, conflicting_header, runtime)

    assert enriched.sections[0].custom_offset_field == 12
    assert enriched.sections[0].custom_size_field == 16
    mismatch = [item for item in enriched.evidence if item.kind == "header_layout_mismatch"]
    assert mismatch[0].value == 2
