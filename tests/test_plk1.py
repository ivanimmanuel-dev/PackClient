"""Tests for PLK1 header validation, transfer reassembly, and LZ4 decoding."""
import hashlib
import importlib.util
import struct
import unittest

from tools.packclient_proto import (
    DIRECTION_SERVER_TO_CLIENT,
    HandshakeContext,
    PLK1Reassembler,
    ProtocolError,
    StreamDecoder,
    TYPE_PLAINTEXT,
    frame_bytes,
    parse_plk1_header,
)


def header(
    wire: bytes,
    plaintext: bytes,
    *,
    version: int = 1,
    lz4_flag: int = 0,
    digest: bytes | None = None,
    orig_size: int | None = None,
) -> bytes:
    return struct.pack(
        "<4sHBBQQ32s",
        b"PLK1",
        version,
        lz4_flag,
        0,
        len(wire),
        len(plaintext) if orig_size is None else orig_size,
        hashlib.sha256(plaintext).digest() if digest is None else digest,
    )


def raw_header(*, version: int = 1, total_size: int = 1, orig_size: int = 1) -> bytes:
    return struct.pack(
        "<4sHBBQQ32s", b"PLK1", version, 0, 0, total_size, orig_size, bytes(32)
    )


def chunk(sequence: int, data: bytes) -> bytes:
    return struct.pack("<II", sequence, len(data)) + data


class PLK1Tests(unittest.TestCase):
    def test_valid_reassembly_and_hash(self):
        plaintext = b"deterministic-core-vector"
        reassembler = PLK1Reassembler(header(plaintext, plaintext))
        first = reassembler.add_chunk(chunk(0, plaintext[:8]))
        self.assertEqual(first["state"], "incomplete")
        final = reassembler.add_chunk(chunk(1, plaintext[8:]))
        self.assertEqual(final["state"], "complete")
        self.assertEqual(final["final"]["sha256_status"], "verified")
        self.assertEqual(reassembler.plaintext, plaintext)

    def test_stream_decoder_integrates_header_and_chunks(self):
        plaintext = b"stream-level-vector"
        raw = (
            frame_bytes(TYPE_PLAINTEXT, header(plaintext, plaintext))
            + frame_bytes(TYPE_PLAINTEXT, chunk(0, plaintext[:6]))
            + frame_bytes(TYPE_PLAINTEXT, chunk(1, plaintext[6:]))
        )
        report = StreamDecoder(
            direction=DIRECTION_SERVER_TO_CLIENT,
            handshake_context=HandshakeContext(),
        ).decode(raw)
        self.assertEqual(report["status"], "parsed")
        self.assertEqual(report["frame_count"], 3)
        self.assertEqual(report["reassemblies"][0]["final"]["status"], "verified")
        self.assertEqual(report["frames"][0]["direction"], "server-to-client")

    def test_header_rejects_unsupported_version(self):
        with self.assertRaisesRegex(ProtocolError, "wire version"):
            parse_plk1_header(raw_header(version=3))

    def test_header_rejects_zero_and_oversized_total_size(self):
        for total_size in (0, 0x08000001):
            with self.subTest(total_size=total_size):
                with self.assertRaisesRegex(ProtocolError, "total_size"):
                    parse_plk1_header(raw_header(total_size=total_size))

    def test_v2_header_rejects_zero_and_oversized_orig_size(self):
        for orig_size in (0, 0x08000001):
            with self.subTest(orig_size=orig_size):
                with self.assertRaisesRegex(ProtocolError, "orig_size"):
                    parse_plk1_header(raw_header(version=2, orig_size=orig_size))

    def test_bad_sequence(self):
        data = b"abc"
        reassembler = PLK1Reassembler(header(data, data))
        with self.assertRaisesRegex(ProtocolError, "sequence mismatch"):
            reassembler.add_chunk(chunk(1, data))

    def test_plaintext_size_mismatch(self):
        data = b"abcde"
        reassembler = PLK1Reassembler(
            header(data, data, version=2, orig_size=len(data) + 1)
        )
        with self.assertRaisesRegex(ProtocolError, "plaintext size mismatch"):
            reassembler.add_chunk(chunk(0, data))

    def test_sha256_mismatch(self):
        data = b"abcde"
        reassembler = PLK1Reassembler(header(data, data, digest=b"\x00" * 32))
        with self.assertRaisesRegex(ProtocolError, "SHA-256 mismatch"):
            reassembler.add_chunk(chunk(0, data))

    def test_malformed_chunk_length(self):
        data = b"abcde"
        reassembler = PLK1Reassembler(header(data, data))
        with self.assertRaisesRegex(ProtocolError, "length mismatch"):
            reassembler.add_chunk(struct.pack("<II", 0, 6) + data)

    @unittest.skipUnless(importlib.util.find_spec("lz4"), "optional lz4 dependency absent")
    def test_optional_raw_block_lz4_reconstruction(self):
        import lz4.block

        plaintext = b"ABCD" * 1024
        wire = lz4.block.compress(plaintext, store_size=False)
        reassembler = PLK1Reassembler(
            header(wire, plaintext, version=2, lz4_flag=1)
        )
        final = reassembler.add_chunk(chunk(0, wire))
        self.assertEqual(final["final"]["status"], "verified")


if __name__ == "__main__":
    unittest.main()
