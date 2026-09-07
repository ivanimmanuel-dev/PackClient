import struct
import unittest

from tools.packclient_proto import (
    FRAME_PREFIX,
    MAX_BODY_LENGTH,
    ProtocolError,
    StreamDecoder,
    TYPE_PLAINTEXT,
    frame_bytes,
    parse_outer_frame,
    validate_body_length,
)


class TransportTests(unittest.TestCase):
    def test_valid_plaintext_frame(self):
        raw = frame_bytes(TYPE_PLAINTEXT, b"abc")
        frame, next_offset = parse_outer_frame(raw)
        self.assertEqual(frame.message_type, TYPE_PLAINTEXT)
        self.assertEqual(frame.payload, b"abc")
        self.assertEqual(next_offset, len(raw))

    def test_truncated_outer_frame_word(self):
        with self.assertRaisesRegex(ProtocolError, "truncated outer frame word"):
            parse_outer_frame(b"\x07\x00\x40")

    def test_wrong_frame_prefix(self):
        raw = struct.pack("<II", 0x5A000004, TYPE_PLAINTEXT)
        with self.assertRaisesRegex(ProtocolError, "wrong outer frame prefix"):
            parse_outer_frame(raw)

    def test_zero_and_oversized_lengths(self):
        with self.assertRaisesRegex(ProtocolError, "zero"):
            parse_outer_frame(struct.pack("<I", FRAME_PREFIX))
        with self.assertRaisesRegex(ProtocolError, "22-bit maximum"):
            validate_body_length(MAX_BODY_LENGTH + 1)

    def test_body_too_short_for_type(self):
        with self.assertRaisesRegex(ProtocolError, "too short"):
            parse_outer_frame(struct.pack("<I", FRAME_PREFIX | 1) + b"x")

    def test_truncated_body(self):
        raw = struct.pack("<I", FRAME_PREFIX | 8) + struct.pack("<I", TYPE_PLAINTEXT)
        with self.assertRaisesRegex(ProtocolError, "truncated outer body"):
            parse_outer_frame(raw)

    def test_stream_report_rejects_trailing_partial_frame(self):
        raw = frame_bytes(TYPE_PLAINTEXT, b"data") + b"\x01\x02"
        report = StreamDecoder().decode(raw)
        self.assertEqual(report["status"], "rejected/malformed")
        self.assertEqual(len(report["frames"]), 1)


if __name__ == "__main__":
    unittest.main()
