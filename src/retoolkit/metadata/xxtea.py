"""Parameterized XXTEA decrypt for IL2CPP custom metadata headers.

Algorithm ported from the Everlusting Life Analysis workspace
(metadata_header_xxtea.py), which matches the C# CustomMetadataHeaderDecoder
byte-for-byte. The transform is generic; keys and section maps come from the
profile, never from this module.
"""

from __future__ import annotations

import struct

DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF


def _word(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def derive_key_words(key: bytes) -> list[int]:
    """Expand a 16-byte key into 4 XXTEA words. Matches the reference:
    word 0 is key[0..2] little-endian with key[6] in the top byte."""
    if len(key) != 16:
        raise ValueError(f"XXTEA key must be 16 bytes, got {len(key)}")
    return [
        key[0] | (key[1] << 8) | (key[2] << 16) | (key[6] << 24),
        _word(key, 4),
        _word(key, 8),
        _word(key, 12),
    ]


def _mix(sum_: int, y: int, z: int, key_index: int, key: list[int]) -> int:
    left = ((z >> 5) ^ ((y << 2) & MASK32)) + ((y >> 3) ^ ((z << 4) & MASK32))
    right = (sum_ ^ y) + (key[key_index] ^ z)
    return (left ^ right) & MASK32


def decrypt_header(encrypted: bytes, key: bytes) -> bytes:
    """XXTEA-decrypt a metadata header; zeroes the trailing 4 bytes exactly
    like the reference implementation."""
    if not encrypted:
        raise ValueError("empty encrypted buffer")
    if len(encrypted) % 4 != 0:
        raise ValueError(f"encrypted buffer length must be a multiple of 4, got {len(encrypted)}")
    words = list(struct.unpack(f"<{len(encrypted) // 4}I", encrypted))
    count = len(words)
    key_words = derive_key_words(key)
    sum_ = ((6 + 52 // count) * DELTA) & MASK32
    while sum_ != 0:
        y = words[0]
        for index in range(count - 1, 0, -1):
            z = words[index - 1]
            key_index = (index & 3) ^ ((sum_ >> 2) & 3)
            y = words[index] = (words[index] - _mix(sum_, y, z, key_index, key_words)) & MASK32
        z = words[-1]
        key_index = (0 & 3) ^ ((sum_ >> 2) & 3)
        words[0] = (words[0] - _mix(sum_, y, z, key_index, key_words)) & MASK32
        sum_ = (sum_ - DELTA) & MASK32
    decoded = bytearray(struct.pack(f"<{count}I", *words))
    decoded[-4:] = b"\0\0\0\0"
    return bytes(decoded)


def encrypt_header(plaintext: bytes, key: bytes) -> bytes:
    """XXTEA-encrypt a metadata header (inverse of decrypt_header); used to
    construct synthetic fixtures for round-trip tests."""
    if not plaintext or len(plaintext) % 4 != 0:
        raise ValueError("plaintext length must be a non-zero multiple of 4")
    words = list(struct.unpack(f"<{len(plaintext) // 4}I", plaintext))
    count = len(words)
    key_words = derive_key_words(key)
    rounds = 6 + 52 // count
    sum_ = 0
    for _ in range(rounds):
        sum_ = (sum_ + DELTA) & MASK32
        key_index_offset = (sum_ >> 2) & 3
        for index in range(count):
            y = words[(index + 1) % count]
            z = words[(index + count - 1) % count]
            key_index = (index & 3) ^ key_index_offset
            words[index] = (words[index] + _mix(sum_, y, z, key_index, key_words)) & MASK32
    return struct.pack(f"<{count}I", *words)
