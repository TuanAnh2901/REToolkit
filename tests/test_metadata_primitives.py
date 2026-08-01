"""Task 14: metadata primitive tests against captured fixtures."""

from pathlib import Path

import pytest

from retoolkit.metadata.scanner import MAGIC, MetadataHit, find_metadata_signatures, version_at
from retoolkit.metadata.xxtea import decrypt_header, derive_key_words

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "everlusting"
KEY = b"fc48e86b730833ef"


def test_decrypt_matches_captured_output_fixture() -> None:
    encrypted = (FIXTURES / "header-transform-input.dat").read_bytes()
    expected = (FIXTURES / "header-transform-output.dat").read_bytes()
    assert len(encrypted) == 676
    decoded = decrypt_header(encrypted, KEY)
    assert decoded == expected


def test_roundtrip_input_not_mutated() -> None:
    encrypted = (FIXTURES / "header-transform-input.dat").read_bytes()
    before = encrypted
    decrypt_header(encrypted, KEY)
    assert encrypted == before


def test_key_derivation_matches_reference() -> None:
    words = derive_key_words(KEY)
    # word0 = 'f'(0x66) | 'c'(0x63)<<8 | '4'(0x34)<<16 | '6'(0x36)<<24
    assert words[0] == 0x36346366
    assert len(words) == 4


def test_invalid_key_length_rejected() -> None:
    with pytest.raises(ValueError):
        derive_key_words(b"short")


def test_non_word_aligned_buffer_rejected() -> None:
    with pytest.raises(ValueError):
        decrypt_header(b"\x01\x02\x03", KEY)


def test_empty_buffer_rejected() -> None:
    with pytest.raises(ValueError):
        decrypt_header(b"", KEY)


def test_decrypt_trailer_zeroed() -> None:
    # any 8-byte block decrypts with a zeroed trailing word
    decoded = decrypt_header(b"\x00\x00\x00\x00\x00\x00\x00\x00", KEY)
    assert decoded[-4:] == b"\0\0\0\0"


def _header_bytes(version: int) -> bytes:
    import struct

    return MAGIC + struct.pack("<I", version)


def test_scanner_finds_valid_signatures() -> None:
    buffer = b"\x00" * 16 + _header_bytes(31) + b"\x00" * 32 + _header_bytes(27)
    hits = find_metadata_signatures(buffer)
    assert hits == [MetadataHit(offset=16, version=31), MetadataHit(offset=56, version=27)]


def test_scanner_rejects_implausible_version() -> None:
    import struct

    buffer = MAGIC + struct.pack("<I", 999) + MAGIC + struct.pack("<I", 31)
    hits = find_metadata_signatures(buffer)
    assert hits == [MetadataHit(offset=8, version=31)]


def test_scanner_rejects_truncated_tail() -> None:
    buffer = MAGIC + b"\x1f\x00"  # magic + 2 bytes only
    assert find_metadata_signatures(buffer) == []
    assert version_at(buffer, 0) is None


def test_scanner_empty_and_undersized() -> None:
    assert find_metadata_signatures(b"") == []
    assert find_metadata_signatures(b"\xAF\x1B") == []


def test_version_at_valid_and_invalid_offsets() -> None:
    import struct

    buffer = b"\x00" * 10 + _header_bytes(31)
    assert version_at(buffer, 10) == 31
    assert version_at(buffer, 9) is None
    assert version_at(buffer, 11) is None
    assert version_at(buffer, 1000) is None
