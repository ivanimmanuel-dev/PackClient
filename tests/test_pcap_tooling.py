"""Tests for PackClient capture parsing and TCP stream reconstruction."""
import hashlib
import hmac
import ipaddress
from fractions import Fraction
from pathlib import Path
import subprocess
import struct
import sys
import tracemalloc
import unittest

from tools.packclient_pcap import (
    DLT_LOOP,
    DLT_NULL,
    Endpoint,
    TCPSegment,
    analyze_capture,
    format_timeline,
    parse_capture,
    reassemble_tcp_direction,
)
from tools.packclient_proto import (
    TYPE_ENCRYPTED,
    TYPE_PLAINTEXT,
    ProtocolError,
    frame_bytes,
    pla1_transcript,
)


CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_PORT = 49152
SERVER_PORT = 8443
CLIENT = Endpoint(CLIENT_IP, CLIENT_PORT)
PSK = b"capture-synthetic-psk"


def hello() -> bytes:
    return struct.pack(
        "<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1, 0x0102030405060708, 4242, 0
    )


def challenge() -> bytes:
    return struct.pack("<4sHH16s", b"PLC1", 1, 0xBEEF, bytes(range(16)))


def authentication() -> bytes:
    tag = hmac.new(PSK, pla1_transcript(hello(), challenge()), hashlib.sha256).digest()
    return struct.pack("<4sHH32s", b"PLA1", 1, 0, tag)


def ethernet_ipv4_tcp(
    payload: bytes,
    sequence: int,
    *,
    client_to_server: bool = True,
) -> bytes:
    if client_to_server:
        source_ip, destination_ip = CLIENT_IP, SERVER_IP
        source_port, destination_port = CLIENT_PORT, SERVER_PORT
    else:
        source_ip, destination_ip = SERVER_IP, CLIENT_IP
        source_port, destination_port = SERVER_PORT, CLIENT_PORT
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0x4000,
        64,
        6,
        0,
        ipaddress.ip_address(source_ip).packed,
        ipaddress.ip_address(destination_ip).packed,
    )
    tcp = struct.pack(
        ">HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        0x18,
        8192,
        0,
        0,
    )
    return ethernet + ipv4 + tcp + payload


def pcap(
    packets: list[tuple[int, int, bytes]],
    *,
    endian: str = "<",
    linktype: int = 1,
) -> bytes:
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    output = bytearray(
        magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, linktype)
    )
    for seconds, micros, packet in packets:
        output.extend(
            struct.pack(endian + "IIII", seconds, micros, len(packet), len(packet))
        )
        output.extend(packet)
    return bytes(output)


def block(block_type: int, body: bytes, *, endian: str = "<") -> bytes:
    total = 12 + len(body)
    assert total % 4 == 0
    return (
        struct.pack(endian + "II", block_type, total)
        + body
        + struct.pack(endian + "I", total)
    )


def pcapng(
    packets: list[tuple[int, bytes]],
    *,
    endian: str = "<",
    linktype: int = 1,
) -> bytes:
    section = block(
        0x0A0D0D0A,
        struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1),
        endian=endian,
    )
    interface = block(
        1, struct.pack(endian + "HHI", linktype, 0, 65535), endian=endian
    )
    enhanced = []
    for timestamp_micros, packet in packets:
        padding = b"\x00" * ((-len(packet)) % 4)
        body = struct.pack(
            endian + "IIIII",
            0,
            timestamp_micros >> 32,
            timestamp_micros & 0xFFFFFFFF,
            len(packet), len(packet),
        ) + packet + padding
        enhanced.append(block(6, body, endian=endian))
    return section + interface + b"".join(enhanced)


def loopback_ipv4_tcp(
    payload: bytes,
    sequence: int,
    *,
    address_family_endian: str,
) -> bytes:
    ipv4_tcp = ethernet_ipv4_tcp(payload, sequence)[14:]
    return struct.pack(address_family_endian + "I", 2) + ipv4_tcp


def analyze_segments(
    segments: list[tuple[int, int, bytes, bool]],
    *,
    psk: bytes | None = None,
) -> dict:
    packets = [
        (1_700_000_000, timestamp, ethernet_ipv4_tcp(payload, sequence, client_to_server=c2s))
        for timestamp, sequence, payload, c2s in segments
    ]
    return analyze_capture(pcap(packets), psk=psk)


class PcapToolingTests(unittest.TestCase):
    def test_frame_split_after_outer_header_is_reassembled(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        report = analyze_segments(
            [(100, 1000, frame[:4], True), (200, 1004, frame[4:], True)]
        )
        flow = report["flows"][0]
        self.assertEqual(flow["status"], "parsed")
        self.assertEqual(flow["timeline"][0]["classification"], "PLH1")
        self.assertEqual(flow["timeline"][0]["frame_length"], len(frame))

    def test_header_split_itself_is_reassembled(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        report = analyze_segments(
            [(100, 1000, frame[:2], True), (200, 1002, frame[2:], True)]
        )
        self.assertEqual(report["flows"][0]["timeline"][0]["classification"], "PLH1")

    def test_multiple_frames_in_one_tcp_segment(self):
        raw = frame_bytes(TYPE_PLAINTEXT, hello()) + frame_bytes(
            TYPE_PLAINTEXT, authentication()
        )
        report = analyze_segments([(100, 1000, raw, True)], psk=PSK)
        timeline = report["flows"][0]["timeline"]
        self.assertEqual([row["classification"] for row in timeline], ["PLH1", "PLA1"])
        self.assertEqual(
            timeline[1]["decoder"]["handshake"]["verification_status"],
            "unverifiable: PLC1 context absent",
        )

    def test_retransmission_and_duplicate_packet_are_tolerated(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        report = analyze_segments(
            [
                (100, 1000, frame[:20], True),
                (150, 1010, frame[10:30], True),
                (160, 1010, frame[10:30], True),
                (200, 1030, frame[30:], True),
            ]
        )
        tcp = report["flows"][0]["tcp"][str(CLIENT)]
        self.assertEqual(report["flows"][0]["status"], "parsed")
        self.assertEqual(tcp["duplicate_segments"], 1)
        self.assertGreaterEqual(tcp["retransmitted_bytes"], 20)

    def test_out_of_order_delivery_is_reassembled(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        report = analyze_segments(
            [(100, 1020, frame[20:], True), (200, 1000, frame[:20], True)]
        )
        self.assertEqual(report["flows"][0]["status"], "parsed")
        self.assertEqual(report["flows"][0]["timeline"][0]["classification"], "PLH1")

    def test_out_of_order_frames_preserve_plk1_state_and_digest(self):
        vector = b"inert out-of-order transfer"
        header = frame_bytes(TYPE_PLAINTEXT, struct.pack(
            "<4sHBBQQ32s", b"PLK1", 1, 0, 0, len(vector), len(vector),
            hashlib.sha256(vector).digest(),
        ))
        chunk = frame_bytes(TYPE_PLAINTEXT, struct.pack("<II", 0, len(vector)) + vector)
        report = analyze_segments([
            (100, 5000 + len(header), chunk, False),
            (200, 5000, header, False),
        ])
        flow = report["flows"][0]
        self.assertEqual(flow["status"], "parsed")
        self.assertEqual([r["stream_offset"] for r in flow["timeline"]], [0, len(header)])
        final = flow["timeline"][1]["decoder"]["plk1_chunk"]["final"]
        self.assertEqual(final["status"], "verified")
        self.assertEqual(final["sha256"], hashlib.sha256(vector).hexdigest())

    def test_reassembly_provenance_has_bounded_memory_overhead(self):
        segment = TCPSegment(0, Fraction(1), CLIENT, Endpoint(SERVER_IP, SERVER_PORT),
                             1000, bytes(128 * 1024), False)
        tracemalloc.start()
        try:
            result = reassemble_tcp_direction([segment])
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result.data, segment.payload)
        self.assertLess(peak, 2 * 1024 * 1024)

    def test_simple_packet_respects_snaplen_and_excludes_padding(self):
        section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        for snaplen, original, expected in [(5, 9, b"abcde"), (0, 5, b"abcde"), (99, 5, b"abcde")]:
            with self.subTest(snaplen=snaplen):
                interface = block(1, struct.pack("<HHI", 1, 0, snaplen))
                simple = block(3, struct.pack("<I", original) + b"abcde" + bytes(3))
                parsed = parse_capture(section + interface + simple)[1][0]
                self.assertEqual(parsed.data, expected)
                self.assertEqual(parsed.captured_length, 5)
                self.assertEqual(parsed.original_length, original)

    def test_simple_packet_rejects_truncated_body(self):
        section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        interface = block(1, struct.pack("<HHI", 1, 0, 20))
        simple = block(3, struct.pack("<I", 20) + bytes(4))
        with self.assertRaisesRegex(ProtocolError, "simple packet length"):
            parse_capture(section + interface + simple)

    def test_short_section_header_is_rejected(self):
        malformed = struct.pack("<IIII", 0x0A0D0D0A, 16, 0x1A2B3C4D, 16) + bytes(12)
        with self.assertRaisesRegex(ProtocolError, "section header is too short"):
            parse_capture(malformed)

    def test_packet_lengths_respect_original_and_interface(self):
        frame = ethernet_ipv4_tcp(frame_bytes(TYPE_PLAINTEXT, hello()), 1000)
        classic = bytearray(pcap([(1, 0, frame)]))
        struct.pack_into("<I", classic, 36, len(frame) - 1)
        with self.assertRaisesRegex(ProtocolError, "original length"):
            parse_capture(bytes(classic))
        enhanced = bytearray(pcapng([(1, frame)]))
        struct.pack_into("<I", enhanced, 40, len(frame) - 1)
        with self.assertRaisesRegex(ProtocolError, "original/snaplen"):
            parse_capture(bytes(enhanced))

    def test_extreme_pcapng_timestamp_does_not_crash_renderer(self):
        frame = ethernet_ipv4_tcp(frame_bytes(TYPE_PLAINTEXT, hello()), 1000)
        capture = pcapng([(2**64 - 1, frame)])
        # PCAPNG if_tsresol=0 makes each timestamp tick one second, pushing this value beyond datetime's range.
        interface = block(1, struct.pack("<HHIHH", 1, 0, 65535, 9, 1) + bytes(4))
        capture = capture[:28] + interface + capture[48:]
        text = format_timeline(analyze_capture(capture))
        self.assertIn("outside calendar range", text)
        self.assertIn("class=PLH1", text)

    def test_contradictory_overlap_fails_closed(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        changed = bytearray(frame[10:25])
        changed[3] ^= 1
        report = analyze_segments(
            [(100, 1000, frame[:20], True), (200, 1010, bytes(changed), True)]
        )
        flow = report["flows"][0]
        self.assertEqual(flow["status"], "rejected/malformed")
        self.assertIn("contradictory TCP overlap", flow["error"])

    def test_directional_handshake_across_different_boundaries(self):
        plh = frame_bytes(TYPE_PLAINTEXT, hello())
        plc = frame_bytes(TYPE_PLAINTEXT, challenge())
        pla = frame_bytes(TYPE_PLAINTEXT, authentication())
        report = analyze_segments(
            [
                (100, 1000, plh[:3], True),
                (110, 1003, plh[3:17], True),
                (120, 1017, plh[17:], True),
                (200, 5000, plc[:4], False),
                (210, 5004, plc[4:], False),
                (300, 1000 + len(plh), pla[:9], True),
                (310, 1000 + len(plh) + 9, pla[9:], True),
            ],
            psk=PSK,
        )
        flow = report["flows"][0]
        self.assertEqual(flow["client_endpoint"], str(CLIENT))
        self.assertEqual(flow["direction_basis"], "protocol evidence")
        self.assertEqual(
            [row["classification"] for row in flow["timeline"]],
            ["PLH1", "PLC1", "PLA1"],
        )
        self.assertEqual(
            flow["timeline"][2]["decoder"]["handshake"]["verification_status"],
            "verified",
        )

    def test_explicit_direction_override_without_handshake(self):
        payload = frame_bytes(TYPE_PLAINTEXT, b"ordinary-application-object")
        capture = pcap(
            [(1_700_000_000, 100, ethernet_ipv4_tcp(payload, 1000, client_to_server=True))]
        )
        report = analyze_capture(capture, client_endpoints=[CLIENT])
        flow = report["flows"][0]
        self.assertEqual(flow["direction_basis"], "analyst override")
        self.assertEqual(flow["timeline"][0]["direction"], "client-to-server")

    def test_plk1_progress_and_envelope_metadata_are_rendered(self):
        vector = b"synthetic-capture-vector"
        header = struct.pack(
            "<4sHBBQQ32s",
            b"PLK1", 1, 0, 0, len(vector), len(vector), hashlib.sha256(vector).digest(),
        )
        split = 7
        chunk0 = struct.pack("<II", 0, split) + vector[:split]
        chunk1 = struct.pack("<II", 1, len(vector) - split) + vector[split:]
        covered = b"\x01" + bytes(16) + struct.pack(">I", 16) + bytes(16)
        envelope = covered + bytes(32)
        raw = b"".join(
            (
                frame_bytes(TYPE_ENCRYPTED, envelope),
                frame_bytes(TYPE_PLAINTEXT, header),
                frame_bytes(TYPE_PLAINTEXT, chunk0),
                frame_bytes(TYPE_PLAINTEXT, chunk1),
            )
        )
        report = analyze_segments([(100, 5000, raw, False)])
        text = format_timeline(report)
        self.assertIn("plk1_version=1", text)
        self.assertIn(f"progress={len(vector)}/{len(vector)} state=complete", text)
        self.assertIn("final=verified", text)
        self.assertIn("envelope_version=1 ciphertext=16", text)
        self.assertNotIn(vector.decode(), text)

    def test_final_plk1_ack_stays_in_launcher_phase_before_core_traffic(self):
        vector = b"synthetic-phase-boundary-vector"
        plh = frame_bytes(TYPE_PLAINTEXT, hello())
        header = frame_bytes(
            TYPE_PLAINTEXT,
            struct.pack(
                "<4sHBBQQ32s",
                b"PLK1",
                1,
                0,
                0,
                len(vector),
                len(vector),
                hashlib.sha256(vector).digest(),
            ),
        )
        final_chunk = frame_bytes(
            TYPE_PLAINTEXT, struct.pack("<II", 0, len(vector)) + vector
        )
        final_ack = frame_bytes(TYPE_PLAINTEXT, struct.pack("<I", 0))
        core_message = frame_bytes(3, b"SYS|R|EXT|STARTUP|OK|tags=")
        report = analyze_segments(
            [
                (100, 1000, plh, True),
                (200, 5000, header, False),
                (300, 5000 + len(header), final_chunk, False),
                (400, 1000 + len(plh), final_ack, True),
                (500, 5000 + len(header) + len(final_chunk), core_message, False),
            ]
        )
        timeline = report["flows"][0]["timeline"]
        acknowledgement = timeline[3]
        self.assertEqual(acknowledgement["classification"], "PLK1-ACK")
        self.assertEqual(acknowledgement["decoder"]["phase"], "launcher")
        self.assertEqual(
            acknowledgement["decoder"]["plk1_acknowledgement"]["sequence"], 0
        )
        self.assertEqual(timeline[4]["decoder"]["phase"], "core")
        self.assertEqual(timeline[4]["classification"], "core-structured-message")
        self.assertIn("plk1_ack=0", format_timeline(report))

    def test_four_byte_frame_word_is_incomplete_body_not_message(self):
        only_header = bytes.fromhex("2400405a")
        report = analyze_segments([(100, 1000, only_header, True)])
        event = report["flows"][0]["timeline"][0]
        self.assertEqual(report["flows"][0]["status"], "partial")
        self.assertEqual(event["status"], "incomplete")
        self.assertEqual(event["declared_body_length"], 0x24)
        self.assertEqual(event["declared_frame_length"], 0x28)

    def test_pcapng_ingestion_and_timestamp(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = ethernet_ipv4_tcp(frame, 1000)
        capture = pcapng([(1_700_000_000_123_456, packet)])
        capture_format, parsed = parse_capture(capture)
        self.assertEqual(capture_format, "pcapng")
        self.assertEqual(len(parsed), 1)
        report = analyze_capture(capture)
        text = format_timeline(report)
        self.assertIn("2023-11-14T22:13:20.123456000Z", text)
        self.assertIn("class=PLH1", text)

    def test_little_endian_classic_pcap_dlt_null(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = loopback_ipv4_tcp(frame, 1000, address_family_endian="<")
        capture = pcap(
            [(1_700_000_000, 123, packet)], endian="<", linktype=DLT_NULL
        )
        _, parsed = parse_capture(capture)
        self.assertEqual(parsed[0].byte_order, "<")
        self.assertEqual(analyze_capture(capture)["flows"][0]["status"], "parsed")

    def test_big_endian_classic_pcap_dlt_null(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = loopback_ipv4_tcp(frame, 1000, address_family_endian=">")
        capture = pcap(
            [(1_700_000_000, 123, packet)], endian=">", linktype=DLT_NULL
        )
        _, parsed = parse_capture(capture)
        self.assertEqual(parsed[0].byte_order, ">")
        self.assertEqual(analyze_capture(capture)["flows"][0]["status"], "parsed")

    def test_little_endian_pcapng_linktype_null(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = loopback_ipv4_tcp(frame, 1000, address_family_endian="<")
        capture = pcapng([(123, packet)], endian="<", linktype=DLT_NULL)
        _, parsed = parse_capture(capture)
        self.assertEqual(parsed[0].byte_order, "<")
        self.assertEqual(analyze_capture(capture)["flows"][0]["status"], "parsed")

    def test_big_endian_pcapng_linktype_null(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = loopback_ipv4_tcp(frame, 1000, address_family_endian=">")
        capture = pcapng([(123, packet)], endian=">", linktype=DLT_NULL)
        _, parsed = parse_capture(capture)
        self.assertEqual(parsed[0].byte_order, ">")
        self.assertEqual(analyze_capture(capture)["flows"][0]["status"], "parsed")

    def test_dlt_loop_remains_big_endian(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        packet = loopback_ipv4_tcp(frame, 1000, address_family_endian=">")
        capture = pcap(
            [(1_700_000_000, 123, packet)], endian="<", linktype=DLT_LOOP
        )
        self.assertEqual(analyze_capture(capture)["flows"][0]["status"], "parsed")

    def test_analyst_override_conflicting_with_protocol_fails(self):
        frame = frame_bytes(TYPE_PLAINTEXT, hello())
        capture = pcap(
            [(1_700_000_000, 100, ethernet_ipv4_tcp(frame, 1000, client_to_server=True))]
        )
        wrong = Endpoint(SERVER_IP, SERVER_PORT)
        flow = analyze_capture(capture, client_endpoints=[wrong])["flows"][0]
        self.assertEqual(flow["status"], "rejected/malformed")
        self.assertIn("conflicts", flow["error"])

    def test_capture_cli_verifies_pla1_without_printing_psk(self):
        plh = frame_bytes(TYPE_PLAINTEXT, hello())
        plc = frame_bytes(TYPE_PLAINTEXT, challenge())
        pla = frame_bytes(TYPE_PLAINTEXT, authentication())
        capture = pcap(
            [
                (1_700_000_000, 100, ethernet_ipv4_tcp(plh, 1000, client_to_server=True)),
                (1_700_000_000, 200, ethernet_ipv4_tcp(plc, 5000, client_to_server=False)),
                (
                    1_700_000_000,
                    300,
                    ethernet_ipv4_tcp(pla, 1000 + len(plh), client_to_server=True),
                ),
            ]
        )
        root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(root / "tools" / "packclient_pcap_decode.py"),
                "-",
                "--psk-hex",
                PSK.hex(),
            ],
            cwd=root,
            input=capture,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        self.assertIn(b"class=PLA1 verification=verified", result.stdout)
        self.assertNotIn(PSK, result.stdout)
        self.assertNotIn(PSK.hex().encode(), result.stdout)


if __name__ == "__main__":
    unittest.main()
