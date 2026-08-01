"""Task 15: config-driven Mfuscator fixup tests."""

import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from retoolkit.contracts.result import ResultError
from retoolkit.metadata.mfuscator import (
    FixupConfig,
    rebuild_file,
    rebuild_metadata,
    rebuild_with_report,
)
from retoolkit.metadata.xxtea import encrypt_header

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "everlusting"
CONFIG = json.loads((FIXTURES / "fixup-config.json").read_text(encoding="utf-8"))


def _config() -> FixupConfig:
    return FixupConfig.from_doc(CONFIG)


def _header_with_prefix() -> bytes:
    # the transform-input fixture is the encrypted header; the 4-byte custom
    # magic precedes it in the real file
    encrypted = (FIXTURES / "header-transform-input.dat").read_bytes()
    return bytes.fromhex(CONFIG["header_prefix"]) + encrypted


def test_config_loads_and_validates() -> None:
    config = _config()
    assert len(config.sections) == 31
    assert config.xxtea_key == b"fc48e86b730833ef"
    assert config.metadata_version == 31


def test_config_rejects_unknown_fields() -> None:
    bad = dict(CONFIG, mystery_field=1)
    with pytest.raises(ResultError) as exc:
        FixupConfig.from_doc(bad)
    assert exc.value.exit_code == 1
    assert "mystery_field" in str(exc.value.details)


def test_malformed_rules_fail_before_output(tmp_path) -> None:
    bad = json.loads(json.dumps(CONFIG))
    bad["sections"][0]["custom_offset_field"] = 10_000  # out of decrypted header bounds
    config = FixupConfig.from_doc(bad)
    data = _header_with_prefix() + b"\x00" * 4096
    with pytest.raises(ResultError) as exc:
        rebuild_metadata(data, config)
    assert "out of bounds" in exc.value.message


def test_wrong_key_fails_deterministically(tmp_path) -> None:
    config = _config()
    config.xxtea_key = b"wrong-key-00000000"
    data = _header_with_prefix() + b"\x00" * 4096
    with pytest.raises(ResultError) as exc:
        rebuild_metadata(data, config)
    # garbage header words produce out-of-bounds sections
    assert exc.value.exit_code == 1


def test_non_obfuscated_input_rejected() -> None:
    config = _config()
    with pytest.raises(ResultError) as exc:
        rebuild_metadata(b"\xAF\x1B\xB1\xFA" + b"\x00" * 100, config)
    assert "prefix" in exc.value.message


def test_rebuild_structure_on_synthetic_file(tmp_path) -> None:
    """Full pipeline on a synthetic file: standard header, preserved tail,
    XOR-transformed sections."""
    config = _config()
    plaintext = bytearray(676)
    # craft custom header words so sections point into a small payload
    struct.pack_into("<I", plaintext, config.sections[1].custom_offset_field, 0x100)
    struct.pack_into("<I", plaintext, config.sections[1].custom_size_field, 16)
    struct.pack_into("<I", plaintext, config.sections[2].custom_offset_field, 0x200)
    struct.pack_into("<I", plaintext, config.sections[2].custom_size_field, 16)
    encrypted = encrypt_header(bytes(plaintext), config.xxtea_key)
    # real layout: magic(4) + encrypted(676) + 4-byte gap + payload; the gap
    # makes the preserved region [256:684] span encrypted tail + gap
    gap = bytes((i * 7) & 0xFF for i in range(4))
    payload = bytearray(b"\xAA" * 4096)
    data = bytes.fromhex(CONFIG["header_prefix"]) + encrypted + gap + bytes(payload)
    rebuilt = rebuild_metadata(data, config)

    magic, version = struct.unpack_from("<II", rebuilt, 0)
    assert magic == config.metadata_magic
    assert version == 31
    expected_len = 8 + 31 * 8 + (config.payload_start - config.preserved_tail_start) + len(payload)
    assert len(rebuilt) == expected_len
    assert rebuilt[config.preserved_tail_start : config.payload_start] == data[
        config.preserved_tail_start : config.payload_start
    ]
    # XOR'd section 1 (file offset = 0x100 + bias) holds the 0xAA filler
    # encoded by the transform; decoding it must restore 0xAA
    section1_start = 0x100 + config.source_bias
    transform = config.sections[1].payload_transform
    encoded = bytes((0xAA ^ ((transform.initial + transform.step * i) & 0xFF)) for i in range(16))
    assert rebuilt[section1_start : section1_start + 16] == encoded
    assert data[config.header_offset : config.header_offset + 676] == encrypted


def test_existing_fixup_config_rebuild_uses_contract_validator() -> None:
    config = _config()
    plaintext = bytearray(config.header_length)
    struct.pack_into("<I", plaintext, config.sections[1].custom_offset_field, 0x100)
    struct.pack_into("<I", plaintext, config.sections[1].custom_size_field, 16)
    struct.pack_into("<I", plaintext, config.sections[2].custom_offset_field, 0x200)
    struct.pack_into("<I", plaintext, config.sections[2].custom_size_field, 16)
    encrypted = encrypt_header(bytes(plaintext), config.xxtea_key)
    data = config.header_prefix + encrypted + b"\x00" * 4 + b"\xAA" * 4096

    rebuilt, report = rebuild_with_report(data, config.to_contract())

    assert report.accepted
    assert rebuilt[:8] == struct.pack("<II", 0xFAB11BAF, 31)
    assert len(config.to_contract().sections) == 31


def test_known_good_hash_recorded_in_config() -> None:
    assert CONFIG["known_good_hash"]
    assert len(CONFIG["known_good_hash"]) == 64


def test_rebuild_file_reports_artifact(tmp_path) -> None:
    config = _config()
    plaintext = bytearray(676)
    struct.pack_into("<I", plaintext, config.sections[1].custom_offset_field, 0x100)
    struct.pack_into("<I", plaintext, config.sections[1].custom_size_field, 16)
    struct.pack_into("<I", plaintext, config.sections[2].custom_offset_field, 0x200)
    struct.pack_into("<I", plaintext, config.sections[2].custom_size_field, 16)
    encrypted = encrypt_header(bytes(plaintext), config.xxtea_key)
    data = bytes.fromhex(CONFIG["header_prefix"]) + encrypted + b"\x00" * 4 + b"\x00" * 4096
    source = tmp_path / "input.dat"
    source.write_bytes(data)
    output = tmp_path / "rebuilt.dat"
    report = rebuild_file(source, output, config)
    assert report["output_size"] == len(output.read_bytes())
    assert report["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.exists()


def test_live_reconstruction_matches_known_good(tmp_path) -> None:
    """When the real game metadata is reachable via RETOOLKIT_GAME_ROOT,
    rebuilding it must reproduce the known-good hash captured from a
    successful Cpp2IL load."""
    game_root = os.environ.get("RETOOLKIT_GAME_ROOT")
    metadata = Path(game_root) / "global-metadata.dat" if game_root else None
    if metadata is None or not metadata.is_file():
        pytest.skip("RETOOLKIT_GAME_ROOT with global-metadata.dat not available")
    rebuilt = rebuild_metadata(metadata.read_bytes(), _config())
    digest = hashlib.sha256(rebuilt).hexdigest()
    assert digest == CONFIG["known_good_hash"]
