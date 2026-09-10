"""Tests for verified PLK1 extraction and provenance manifests."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from test_pcap_tooling import ethernet_ipv4_tcp, pcap
from tools.packclient_artifacts import export_capture_artifacts, inspect_pe
from tools.packclient_pcap import PLK1Artifact, analyze_capture
from tools.packclient_proto import ProtocolError, TYPE_PLAINTEXT, frame_bytes


def synthetic_pe() -> bytes:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x210E)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<I", data, 0x98 + 56, 0x2000)
    return bytes(data)


def plk1_stream(data: bytes, *, digest: bytes | None = None) -> bytes:
    header = struct.pack(
        "<4sHBBQQ32s",
        b"PLK1",
        1,
        0,
        0,
        len(data),
        len(data),
        hashlib.sha256(data).digest() if digest is None else digest,
    )
    split = len(data) // 2
    chunks = (
        struct.pack("<II", 0, split) + data[:split],
        struct.pack("<II", 1, len(data) - split) + data[split:],
    )
    return b"".join(
        (frame_bytes(TYPE_PLAINTEXT, header),)
        + tuple(frame_bytes(TYPE_PLAINTEXT, chunk) for chunk in chunks)
    )


def capture_for_stream(stream: bytes) -> bytes:
    packet = ethernet_ipv4_tcp(stream, 5000, client_to_server=False)
    return pcap([(1_700_000_000, 100, packet)])


class PLK1ExtractionTests(unittest.TestCase):
    def test_capture_recovers_exact_verified_bytes_with_frame_provenance(self):
        plaintext = synthetic_pe()
        capture = capture_for_stream(plk1_stream(plaintext))
        artifacts: list[PLK1Artifact] = []
        report = analyze_capture(capture, plk1_artifacts=artifacts)
        self.assertEqual(report["flows"][0]["status"], "parsed")
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        self.assertEqual(artifact.plaintext, plaintext)
        self.assertEqual(artifact.chunk_count, 2)
        self.assertEqual(len(artifact.frames), 3)
        self.assertEqual(artifact.frames[0]["packet_indexes"], [0])

    def test_duplicate_transfers_write_one_file_with_two_observations(self):
        plaintext = synthetic_pe()
        capture = capture_for_stream(plk1_stream(plaintext))
        artifacts: list[PLK1Artifact] = []
        analyze_capture(capture, plk1_artifacts=artifacts)
        with tempfile.TemporaryDirectory(prefix="packclient-extract-") as temporary:
            output = Path(temporary)
            manifest = export_capture_artifacts(
                capture=capture,
                capture_format="pcap",
                output_dir=output,
                plk1_artifacts=[artifacts[0], artifacts[0]],
                export_plk1=True,
            )
            self.assertEqual(len(manifest["plk1"]), 1)
            self.assertEqual(len(manifest["plk1"][0]["observations"]), 2)
            relative = manifest["plk1"][0]["output_file"]
            self.assertEqual((output / relative).read_bytes(), plaintext)
            disk_manifest = json.loads((output / "manifest.json").read_text("utf-8"))
            self.assertEqual(disk_manifest["capture"]["sha256"], hashlib.sha256(capture).hexdigest())
            self.assertNotIn(str(output), (output / "manifest.json").read_text("utf-8"))

    def test_pe_metadata_is_bounded_and_identifies_pe32_dll(self):
        metadata = inspect_pe(synthetic_pe())
        self.assertTrue(metadata["is_pe"])
        self.assertEqual(metadata["format"], "PE32")
        self.assertEqual(metadata["machine"], "0x014c")
        self.assertTrue(metadata["dll"])
        self.assertFalse(inspect_pe(b"MZ" + bytes(20))["is_pe"])

    def test_bad_hash_produces_no_artifact(self):
        plaintext = synthetic_pe()
        capture = capture_for_stream(plk1_stream(plaintext, digest=bytes(32)))
        artifacts: list[PLK1Artifact] = []
        report = analyze_capture(capture, plk1_artifacts=artifacts)
        self.assertEqual(report["flows"][0]["status"], "rejected/malformed")
        self.assertEqual(artifacts, [])

    def test_existing_different_payload_is_not_overwritten(self):
        plaintext = synthetic_pe()
        capture = capture_for_stream(plk1_stream(plaintext))
        artifacts: list[PLK1Artifact] = []
        analyze_capture(capture, plk1_artifacts=artifacts)
        digest = hashlib.sha256(plaintext).hexdigest()
        with tempfile.TemporaryDirectory(prefix="packclient-extract-") as temporary:
            output = Path(temporary)
            target = output / "plk1" / f"plk1-{digest[:12]}.bin"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"different")
            with self.assertRaisesRegex(ProtocolError, "refusing to overwrite"):
                export_capture_artifacts(
                    capture=capture,
                    capture_format="pcap",
                    output_dir=output,
                    plk1_artifacts=artifacts,
                    export_plk1=True,
                )
            self.assertEqual(target.read_bytes(), b"different")
            self.assertFalse(any(target.parent.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
