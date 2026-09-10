"""Tests for the recovered Core key derivation and authenticated envelope."""

import hashlib
import hmac
import struct
import unittest

from tools.packclient_proto import (
    ProtocolError,
    derive_core_keys,
    parse_core_envelope,
)


CORE_PSK = b"core-test-psk"
CORE_ENVELOPE = bytes.fromhex(
    "01000102030405060708090a0b0c0d0e0f20000000"
    "edc6d1bf33207955c58cab5e93eceb4054d89a3e86aa7f06b82df8527d68b72c"
    "5c404a12b3c547a60a122fb83163cda7c997c209f5cb1fb083429a2e82c9bf22"
)


class CoreCryptoTests(unittest.TestCase):
    def test_domain_separated_sha256_kdf(self):
        aes_key, hmac_key = derive_core_keys(CORE_PSK)
        self.assertEqual(
            aes_key.hex(),
            "ad14793405a0260777aec4c0e86a3338ae9341ead1fb9aa4a3622a4a26fff056",
        )
        self.assertEqual(
            hmac_key.hex(),
            "3eaa25b2d9e51e885c6e0519eada42474ea565aa6e8bebf93dd1b206cac1a316",
        )
        self.assertNotEqual(aes_key, hmac_key)

    def test_valid_core_envelope_authenticates_before_decrypting(self):
        result = parse_core_envelope(CORE_ENVELOPE, auth_psk=CORE_PSK)
        self.assertEqual(result.metadata["hmac_status"], "verified")
        self.assertEqual(result.metadata["decryption_status"], "verified")
        self.assertEqual(result.metadata["inner_type"], "0x00000003")
        self.assertEqual(result.inner_message_type, 3)
        self.assertEqual(result.inner_payload, b"SYS|Q|EXT|STARTUP|PROBE|")

    def test_metadata_only_without_psk(self):
        result = parse_core_envelope(CORE_ENVELOPE)
        self.assertEqual(result.metadata["ciphertext_length"], 32)
        self.assertIsNone(result.inner_message_type)
        self.assertIsNone(result.inner_payload)

    def test_tampered_hmac_and_wrong_psk_are_rejected(self):
        tampered = bytearray(CORE_ENVELOPE)
        tampered[-1] ^= 1
        for envelope, psk in ((bytes(tampered), CORE_PSK), (CORE_ENVELOPE, b"wrong")):
            with self.subTest(psk=psk):
                with self.assertRaisesRegex(ProtocolError, "HMAC"):
                    parse_core_envelope(envelope, auth_psk=psk)

    def test_invalid_length_and_padding_fail_closed(self):
        length = bytearray(CORE_ENVELOPE)
        struct.pack_into("<I", length, 17, 16)
        with self.assertRaisesRegex(ProtocolError, "length mismatch"):
            parse_core_envelope(bytes(length), auth_psk=CORE_PSK)

        padding = bytearray(CORE_ENVELOPE)
        padding[0x15 + 15] ^= 2
        _, hmac_key = derive_core_keys(CORE_PSK)
        padding[-32:] = hmac.new(hmac_key, padding[:-32], hashlib.sha256).digest()
        with self.assertRaisesRegex(ProtocolError, "padding"):
            parse_core_envelope(bytes(padding), auth_psk=CORE_PSK)

    def test_launcher_big_endian_length_is_not_accepted_as_core(self):
        ciphertext = bytes(16)
        launcher = b"\x01" + bytes(16) + struct.pack(">I", 16) + ciphertext + bytes(32)
        with self.assertRaisesRegex(ProtocolError, "length mismatch"):
            parse_core_envelope(launcher)


if __name__ == "__main__":
    unittest.main()
