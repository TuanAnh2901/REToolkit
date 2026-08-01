from __future__ import annotations

from retoolkit.metadata.mfuscator_contract import (
    MfuscatorContract,
    PayloadTransformContract,
    SectionContract,
)


def test_contract_json_round_trip_preserves_field_offsets_and_bytes() -> None:
    contract = MfuscatorContract(
        name="fixture",
        metadata_magic=0xFAB11BAF,
        metadata_version=31,
        header_prefix=bytes.fromhex("e1b06cfe"),
        header_offset=4,
        header_length=676,
        payload_start=684,
        preserved_tail_start=256,
        source_bias=484,
        xxtea_key=b"fc48e86b730833ef",
        sections=(
            SectionContract(
                "methods",
                custom_offset_field=44,
                custom_size_field=144,
                record_size=32,
                payload_transform=PayloadTransformContract(initial=13, step=-1),
            ),
        ),
    )

    restored = MfuscatorContract.from_json(contract.to_json())

    assert restored == contract
    assert restored.header_prefix == bytes.fromhex("e1b06cfe")
    assert restored.xxtea_key == b"fc48e86b730833ef"


def test_contract_rejects_duplicate_section_names() -> None:
    section = SectionContract("methods", 4, 8)

    try:
        MfuscatorContract(
            name="duplicate",
            metadata_magic=0xFAB11BAF,
            metadata_version=31,
            header_prefix=b"abcd",
            header_offset=4,
            header_length=64,
            payload_start=68,
            preserved_tail_start=16,
            source_bias=0,
            xxtea_key=b"0123456789abcdef",
            sections=(section, section),
        )
    except ValueError as exc:
        assert "duplicate section name" in str(exc)
    else:
        raise AssertionError("duplicate section names were accepted")
