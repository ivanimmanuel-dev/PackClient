"""Synthetic protocol fixture containing both directions in chronological order."""

from __future__ import annotations

import hashlib
import hmac
import struct

from tools.packclient_proto import TYPE_ENCRYPTED, TYPE_PLAINTEXT, frame_bytes, pla1_transcript


PSK = b"passive-synthetic-test-psk"
AES_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
ENVELOPE_HMAC_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PLAINTEXT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
NIST_CIPHERTEXT = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
ENCRYPTED_APPLICATION_PAYLOAD = b"test-vector"  # 11 bytes, followed by 0x01 padding
PLK1_PLAINTEXT = b"synthetic-verified-plk1-vector"


def _hello() -> bytes:
    return struct.pack("<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1, 0x0102030405060708, 4242, 0)


def _challenge() -> bytes:
    return struct.pack("<4sHH16s", b"PLC1", 1, 0xBEEF, bytes(range(16)))


def _authentication(hello: bytes, challenge: bytes) -> bytes:
    tag = hmac.new(PSK, pla1_transcript(hello, challenge), hashlib.sha256).digest()
    return struct.pack("<4sHH32s", b"PLA1", 1, 0, tag)


def _envelope() -> bytes:
    desired = struct.pack("<I", TYPE_PLAINTEXT) + ENCRYPTED_APPLICATION_PAYLOAD + b"\x01"
    iv = bytes(a ^ b ^ c for a, b, c in zip(NIST_PLAINTEXT, NIST_IV, desired))
    covered = b"\x01" + iv + struct.pack(">I", len(NIST_CIPHERTEXT)) + NIST_CIPHERTEXT
    return covered + hmac.new(ENVELOPE_HMAC_KEY, covered, hashlib.sha256).digest()


def _plk1_header() -> bytes:
    digest = hashlib.sha256(PLK1_PLAINTEXT).digest()
    return struct.pack(
        "<4sHBBQQ32s",
        b"PLK1",
        1,
        0,
        0,
        len(PLK1_PLAINTEXT),
        len(PLK1_PLAINTEXT),
        digest,
    )


def _chunk(sequence: int, data: bytes) -> bytes:
    return struct.pack("<II", sequence, len(data)) + data


def valid_stream() -> bytes:
    hello = _hello()
    challenge = _challenge()
    split = 9
    return b"".join(
        (
            frame_bytes(TYPE_PLAINTEXT, hello),
            frame_bytes(TYPE_PLAINTEXT, challenge),
            frame_bytes(TYPE_PLAINTEXT, _authentication(hello, challenge)),
            frame_bytes(TYPE_ENCRYPTED, _envelope()),
            frame_bytes(TYPE_PLAINTEXT, _plk1_header()),
            frame_bytes(TYPE_PLAINTEXT, _chunk(0, PLK1_PLAINTEXT[:split])),
            frame_bytes(TYPE_PLAINTEXT, _chunk(1, PLK1_PLAINTEXT[split:])),
        )
    )


def malformed_stream() -> bytes:
    stream = bytearray(valid_stream())
    stream[3] = 0
    return bytes(stream)
