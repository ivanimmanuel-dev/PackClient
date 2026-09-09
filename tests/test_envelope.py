"""Tests for PackClient envelope authentication and AES-256-CBC handling."""
import hashlib
import hmac
import struct
import unittest
from unittest.mock import patch

from tools.packclient_proto import (
    ProtocolError,
    _aes256_decrypt_block,
    aes256_cbc_decrypt_blocks,
    aes256_cbc_decrypt_padded,
    parse_envelope,
)


"""Adjust the CBC IV so the NIST ciphertext decrypts to *block*."""
AES_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
CIPHERTEXT = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
DESIRED_BLOCK = struct.pack("<I", 0x15) + b"hello-world" + b"\x01"
IV = bytes(a ^ b ^ c for a, b, c in zip(NIST_PLAIN, NIST_IV, DESIRED_BLOCK))
HMAC_KEY = bytes(range(32))

NIST_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST_CBC_CIPHERTEXT = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)
NIST_ECB_CIPHERTEXT = (
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
)


def envelope(iv: bytes = IV, ciphertext: bytes = CIPHERTEXT, declared: int | None = None) -> bytes:
    length = len(ciphertext) if declared is None else declared
    covered = b"\x01" + iv + struct.pack(">I", length) + ciphertext
    return covered + hmac.new(HMAC_KEY, covered, hashlib.sha256).digest()


def iv_for_plaintext_block(block: bytes) -> bytes:
    """Adjust CBC IV so the fixed published NIST ciphertext yields *block*."""
    if len(block) != 16:
        raise ValueError("test block must be 16 bytes")
    return bytes(a ^ b ^ c for a, b, c in zip(NIST_PLAIN, NIST_IV, block))


class EnvelopeTests(unittest.TestCase):
    def test_nist_fips_197_aes256_raw_block_decrypt(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(
            _aes256_decrypt_block(key, ciphertext),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )

    def test_nist_sp800_38a_aes256_ecb_decrypt_vectors(self):
        for index, ciphertext in enumerate(NIST_ECB_CIPHERTEXT):
            with self.subTest(block=index + 1):
                self.assertEqual(
                    _aes256_decrypt_block(AES_KEY, bytes.fromhex(ciphertext)),
                    NIST_PLAINTEXT[index * 16 : (index + 1) * 16],
                )

    def test_nist_sp800_38a_aes256_cbc_decrypt_vector(self):
        self.assertEqual(
            aes256_cbc_decrypt_blocks(AES_KEY, NIST_IV, NIST_CBC_CIPHERTEXT),
            NIST_PLAINTEXT,
        )

    def test_metadata_only_without_keys(self):
        result = parse_envelope(envelope())
        self.assertIsNone(result.plaintext_payload)
        self.assertIn("key absent", result.metadata["hmac_status"])
        self.assertEqual(result.metadata["ciphertext_length"], 16)

    def test_malformed_declared_length(self):
        with self.assertRaisesRegex(ProtocolError, "length mismatch"):
            parse_envelope(envelope(declared=32))

    def test_non_block_aligned_ciphertext(self):
        with self.assertRaisesRegex(ProtocolError, "block-aligned"):
            parse_envelope(envelope(ciphertext=CIPHERTEXT[:-1]))

    def test_correct_and_incorrect_hmac(self):
        result = parse_envelope(envelope(), hmac_key=HMAC_KEY)
        self.assertEqual(result.metadata["hmac_status"], "verified")
        bad = bytearray(envelope())
        bad[-1] ^= 1
        with self.assertRaisesRegex(ProtocolError, "HMAC-SHA-256"):
            parse_envelope(bytes(bad), hmac_key=HMAC_KEY)

    def test_hmac_failure_occurs_before_aes_decryption(self):
        bad = bytearray(envelope())
        bad[-1] ^= 1
        with patch(
            "tools.packclient_proto.aes256_cbc_decrypt_padded",
            side_effect=AssertionError("AES must not be reached"),
        ) as decrypt:
            with self.assertRaisesRegex(ProtocolError, "HMAC-SHA-256"):
                parse_envelope(bytes(bad), aes_key=AES_KEY, hmac_key=HMAC_KEY)
            decrypt.assert_not_called()

    def test_valid_aes256_cbc_decrypt(self):
        result = parse_envelope(envelope(), aes_key=AES_KEY, hmac_key=HMAC_KEY)
        self.assertEqual(result.plaintext_payload, b"hello-world")
        self.assertEqual(result.metadata["decryption_status"], "verified")

    def test_aes_key_alone_does_not_decrypt_unauthenticated_data(self):
        with patch(
            "tools.packclient_proto.aes256_cbc_decrypt_padded",
            side_effect=AssertionError("AES must not be reached"),
        ) as decrypt:
            result = parse_envelope(envelope(), aes_key=AES_KEY)
            decrypt.assert_not_called()
        self.assertIsNone(result.plaintext_payload)
        self.assertIn("HMAC not verified", result.metadata["decryption_status"])

    def test_pkcs7_rejects_zero_padding(self):
        bad_iv = iv_for_plaintext_block(b"A" * 15 + b"\x00")
        with self.assertRaisesRegex(ProtocolError, "invalid block padding"):
            aes256_cbc_decrypt_padded(AES_KEY, bad_iv, CIPHERTEXT)

    def test_pkcs7_rejects_padding_greater_than_block(self):
        bad_iv = iv_for_plaintext_block(b"A" * 15 + b"\x11")
        with self.assertRaisesRegex(ProtocolError, "invalid block padding"):
            aes256_cbc_decrypt_padded(AES_KEY, bad_iv, CIPHERTEXT)

    def test_pkcs7_rejects_inconsistent_trailing_bytes(self):
        bad_iv = iv_for_plaintext_block(b"A" * 14 + b"\x03\x02")
        with self.assertRaisesRegex(ProtocolError, "invalid block padding"):
            aes256_cbc_decrypt_padded(AES_KEY, bad_iv, CIPHERTEXT)

    def test_cbc_rejects_empty_and_non_aligned_ciphertext(self):
        for ciphertext in (b"", b"\x00" * 15, b"\x00" * 17):
            with self.subTest(length=len(ciphertext)):
                with self.assertRaisesRegex(ProtocolError, "nonempty and block-aligned"):
                    aes256_cbc_decrypt_padded(AES_KEY, NIST_IV, ciphertext)

    def test_decrypted_inner_type_must_be_plaintext(self):
        bad_iv = bytes([IV[0] ^ 1]) + IV[1:]
        with self.assertRaisesRegex(ProtocolError, "inner type"):
            parse_envelope(envelope(bad_iv), aes_key=AES_KEY, hmac_key=HMAC_KEY)


if __name__ == "__main__":
    unittest.main()
