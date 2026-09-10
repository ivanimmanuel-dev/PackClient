"""Tests for Core messages, phase selection, and PV10 parsing."""

import hashlib
import struct
import unittest

from test_core_crypto import CORE_ENVELOPE, CORE_PSK
from tools.packclient_proto import (
    PHASE_AUTO,
    PHASE_CORE,
    PHASE_LAUNCHER,
    ProtocolError,
    StreamDecoder,
    TYPE_ENCRYPTED,
    classify_core_payload,
    frame_bytes,
    parse_pv10,
)


JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(16) + b"\xff\xd9"
PV10 = b"PV10" + struct.pack("<I", len(JPEG)) + JPEG


class CoreProtocolTests(unittest.TestCase):
    def test_observed_plaintext_command_is_classified_without_values(self):
        payload = b"INP|HELLO|uuid=private-device-value|S1|iid="
        report = StreamDecoder(phase=PHASE_CORE).decode(frame_bytes(3, payload))
        self.assertEqual(report["status"], "parsed")
        frame = report["frames"][0]
        self.assertEqual(frame["phase"], PHASE_CORE)
        self.assertEqual(frame["core"]["kind"], "core-structured-message")
        self.assertEqual(frame["core"]["command"], "client-hello")
        self.assertNotIn("private-device-value", repr(report))

    def test_observed_message_types_are_recognized(self):
        expected = {
            1: "core-type-1",
            2: "core-type-2",
            3: "core-structured-message",
            10: "core-information-request",
            11: "core-host-inventory",
            17: "core-type-17",
        }
        for message_type, kind in expected.items():
            with self.subTest(message_type=message_type):
                report = StreamDecoder(phase=PHASE_CORE).decode(
                    frame_bytes(message_type, b"synthetic")
                )
                self.assertEqual(report["frames"][0]["core"]["kind"], kind)

    def test_valid_pv10_is_verified_and_retained_for_explicit_export(self):
        decoder = StreamDecoder(phase=PHASE_CORE)
        report = decoder.decode(frame_bytes(18, PV10))
        metadata = report["frames"][0]["pv10"]
        self.assertEqual(metadata["status"], "verified")
        self.assertEqual(metadata["jpeg_length"], len(JPEG))
        self.assertEqual(metadata["jpeg_sha256"], hashlib.sha256(JPEG).hexdigest())
        artifacts = decoder.pop_completed_pv10()
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].jpeg, JPEG)
        self.assertNotIn(JPEG.hex(), repr(report))

    def test_malformed_pv10_is_rejected(self):
        cases = (
            b"PV10",
            b"NOPE" + struct.pack("<I", len(JPEG)) + JPEG,
            b"PV10" + struct.pack("<I", len(JPEG) + 1) + JPEG,
            b"PV10" + struct.pack("<I", 4) + b"nope",
            b"PV10" + struct.pack("<I", len(JPEG)) + JPEG[:-2] + b"xx",
        )
        for payload in cases:
            with self.subTest(payload=payload[:8]):
                report = StreamDecoder(phase=PHASE_CORE).decode(frame_bytes(18, payload))
                self.assertEqual(report["status"], "rejected/malformed")

    def test_core_envelope_uses_recovered_kdf(self):
        report = StreamDecoder(phase=PHASE_CORE, core_psk=CORE_PSK).decode(
            frame_bytes(TYPE_ENCRYPTED, CORE_ENVELOPE)
        )
        frame = report["frames"][0]
        self.assertEqual(frame["envelope"]["decryption_status"], "verified")
        self.assertEqual(frame["core"]["command"], "startup-probe")

    def test_auto_phase_distinguishes_launcher_and_core_envelopes(self):
        ciphertext = bytes(16)
        launcher = b"\x01" + bytes(16) + struct.pack(">I", 16) + ciphertext + bytes(32)
        launcher_report = StreamDecoder(phase=PHASE_AUTO).decode(
            frame_bytes(TYPE_ENCRYPTED, launcher)
        )
        self.assertEqual(launcher_report["frames"][0]["phase"], PHASE_LAUNCHER)

        core_report = StreamDecoder(phase=PHASE_AUTO).decode(
            frame_bytes(TYPE_ENCRYPTED, CORE_ENVELOPE)
        )
        self.assertEqual(core_report["frames"][0]["phase"], PHASE_CORE)
        self.assertEqual(
            core_report["frames"][0]["envelope"]["format"],
            "Core (little-endian length)",
        )

    def test_auto_phase_rejects_ambiguous_envelope_length(self):
        ambiguous = b"\x01" + bytes(16) + bytes(4) + bytes(32)
        report = StreamDecoder(phase=PHASE_AUTO).decode(
            frame_bytes(TYPE_ENCRYPTED, ambiguous)
        )
        self.assertEqual(report["status"], "rejected/malformed")
        self.assertIn("phase is ambiguous", report["error"])

    def test_truncated_core_frame_and_invalid_type_fail_closed(self):
        truncated = frame_bytes(3, b"abc")[:-1]
        report = StreamDecoder(phase=PHASE_CORE).decode(truncated)
        self.assertEqual(report["status"], "rejected/malformed")
        with self.assertRaisesRegex(ProtocolError, "unsupported Core"):
            classify_core_payload(9, b"")


if __name__ == "__main__":
    unittest.main()
