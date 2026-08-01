from __future__ import annotations

from retoolkit.metadata.mfuscator_contract import MfuscatorContract, SectionContract
from retoolkit.metadata.mfuscator_validate import validate_candidate


def _contract(*sections: SectionContract) -> MfuscatorContract:
    return MfuscatorContract(
        name="fixture",
        metadata_magic=0xFAB11BAF,
        metadata_version=31,
        header_prefix=b"abcd",
        header_offset=4,
        header_length=64,
        payload_start=68,
        preserved_tail_start=16,
        source_bias=0,
        xxtea_key=b"0123456789abcdef",
        sections=sections,
    )


def test_validator_rejects_out_of_bounds_and_record_remainder() -> None:
    contract = _contract(SectionContract("methods", 4, 8, record_size=8))

    report = validate_candidate(bytes(64), contract, ((60, 6),))

    assert report.accepted is False
    assert {finding.code for finding in report.findings} == {
        "section.bounds",
        "section.record_size",
    }


def test_validator_rejects_overlapping_nonempty_sections() -> None:
    contract = _contract(
        SectionContract("methods", 4, 8),
        SectionContract("types", 12, 16),
    )

    report = validate_candidate(bytes(256), contract, ((64, 64), (96, 64)))

    assert report.accepted is False
    assert any(finding.code == "section.overlap" for finding in report.findings)


def test_validator_accepts_aligned_nonoverlapping_sections() -> None:
    contract = _contract(
        SectionContract("methods", 4, 8, record_size=8),
        SectionContract("types", 12, 16, record_size=16),
    )

    report = validate_candidate(bytes(256), contract, ((64, 32), (96, 32)))

    assert report.accepted is True
    assert report.score > 0
    assert not [finding for finding in report.findings if finding.severity == "error"]
