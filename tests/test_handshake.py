import hashlib
import hmac
import struct
import unittest

from tools.packclient_proto import (
    DEFAULT_LAUNCHER_PSK,
    DIRECTION_CLIENT_TO_SERVER,
    DIRECTION_SERVER_TO_CLIENT,
    HandshakeContext,
    ProtocolError,
    StreamDecoder,
    TYPE_PLAINTEXT,
    frame_bytes,
    pla1_transcript,
    parse_pla1,
    parse_plc1,
    parse_plh1,
    verify_pla1,
)


def hello() -> bytes:
    return struct.pack("<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1, 0x0102030405060708, 4242, 0)


def challenge() -> bytes:
    return struct.pack("<4sHH16s", b"PLC1", 1, 0xBEEF, bytes(range(16)))


def auth(psk: bytes) -> bytes:
    tag = hmac.new(psk, pla1_transcript(hello(), challenge()), hashlib.sha256).digest()
    return struct.pack("<4sHH32s", b"PLA1", 1, 0, tag)


class HandshakeTests(unittest.TestCase):
    def test_exact_layouts_and_transcript(self):
        self.assertEqual(parse_plh1(hello())["process_id"], 4242)
        self.assertEqual(parse_plc1(challenge())["field_06"], 0xBEEF)
        self.assertEqual(parse_pla1(auth(b"test-psk"))["version"], 1)
        transcript = pla1_transcript(hello(), challenge())
        self.assertEqual(len(transcript), 42)
        self.assertEqual(
            transcript,
            hello()[0x10:0x20]
            + challenge()[0x08:0x18]
            + hello()[0x0C:0x10]
            + hello()[0x06:0x08]
            + b"PLK1",
        )

    def test_malformed_handshake_objects(self):
        with self.assertRaises(ProtocolError):
            parse_plh1(hello()[:-1])
        malformed_plc = bytearray(challenge())
        malformed_plc[4:6] = b"\x02\x00"
        with self.assertRaisesRegex(ProtocolError, "version"):
            parse_plc1(bytes(malformed_plc))
        malformed_pla = bytearray(auth(b"test-psk"))
        malformed_pla[6] = 1
        with self.assertRaisesRegex(ProtocolError, "fixed field"):
            parse_pla1(bytes(malformed_pla))

    def test_correct_and_incorrect_pla1_hmac(self):
        psk = b"test-psk"
        self.assertEqual(verify_pla1(hello(), challenge(), auth(psk), psk=psk), "verified")
        bad = bytearray(auth(psk))
        bad[-1] ^= 1
        with self.assertRaisesRegex(ProtocolError, "verification failed"):
            verify_pla1(hello(), challenge(), bytes(bad), psk=psk)

    def test_default_psk_requires_explicit_request(self):
        pla = auth(DEFAULT_LAUNCHER_PSK)
        self.assertIn("PSK absent", verify_pla1(hello(), challenge(), pla))
        self.assertEqual(
            verify_pla1(hello(), challenge(), pla, use_default_psk=True),
            "verified",
        )

    def test_client_stream_alone_cannot_verify_without_plc1(self):
        psk = b"test-psk"
        context = HandshakeContext()
        stream = frame_bytes(TYPE_PLAINTEXT, hello()) + frame_bytes(
            TYPE_PLAINTEXT, auth(psk)
        )
        report = StreamDecoder(
            direction=DIRECTION_CLIENT_TO_SERVER,
            handshake_context=context,
            psk=psk,
        ).decode(stream)
        self.assertEqual(report["status"], "parsed")
        self.assertEqual(report["handshake_context"]["PLH1"], "available")
        self.assertEqual(report["handshake_context"]["PLC1"], "absent")
        self.assertEqual(
            report["frames"][1]["handshake"]["verification_status"],
            "unverifiable: PLC1 context absent",
        )

    def test_server_stream_supplies_plc1_context(self):
        context = HandshakeContext()
        report = StreamDecoder(
            direction=DIRECTION_SERVER_TO_CLIENT,
            handshake_context=context,
        ).decode(frame_bytes(TYPE_PLAINTEXT, challenge()))
        self.assertEqual(report["status"], "parsed")
        self.assertEqual(report["handshake_context"]["PLC1"], "available")

    def test_shared_directional_context_verifies_pla1(self):
        psk = b"test-psk"
        context = HandshakeContext()
        client = StreamDecoder(
            direction=DIRECTION_CLIENT_TO_SERVER,
            handshake_context=context,
            psk=psk,
        )
        server = StreamDecoder(
            direction=DIRECTION_SERVER_TO_CLIENT,
            handshake_context=context,
        )
        self.assertEqual(
            client.decode(frame_bytes(TYPE_PLAINTEXT, hello()))["status"], "parsed"
        )
        self.assertEqual(
            server.decode(frame_bytes(TYPE_PLAINTEXT, challenge()))["status"], "parsed"
        )
        report = client.decode(frame_bytes(TYPE_PLAINTEXT, auth(psk)))
        self.assertEqual(
            report["frames"][0]["handshake"]["verification_status"], "verified"
        )

    def test_wrong_shared_plc1_context_fails_verification(self):
        psk = b"test-psk"
        context = HandshakeContext()
        client = StreamDecoder(
            direction=DIRECTION_CLIENT_TO_SERVER,
            handshake_context=context,
            psk=psk,
        )
        server = StreamDecoder(
            direction=DIRECTION_SERVER_TO_CLIENT,
            handshake_context=context,
        )
        client.decode(frame_bytes(TYPE_PLAINTEXT, hello()))
        wrong = bytearray(challenge())
        wrong[-1] ^= 1
        server.decode(frame_bytes(TYPE_PLAINTEXT, bytes(wrong)))
        report = client.decode(frame_bytes(TYPE_PLAINTEXT, auth(psk)))
        self.assertEqual(report["status"], "rejected/malformed")
        self.assertIn("PLA1 HMAC-SHA-256 verification failed", report["error"])

    def test_shared_context_requires_explicit_direction(self):
        with self.assertRaisesRegex(ProtocolError, "requires explicit direction"):
            StreamDecoder(handshake_context=HandshakeContext())


if __name__ == "__main__":
    unittest.main()
