"""TShark integration tests for the PackClient Lua dissector."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from tools.packclient_proto import (
    FRAME_PREFIX,
    TYPE_ENCRYPTED,
    TYPE_PLAINTEXT,
    frame_bytes,
)


ROOT = Path(__file__).resolve().parent.parent
LUA_DISSECTOR = ROOT / "tools" / "wireshark" / "packclient.lua"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_PORT = 49152
SERVER_PORT = 8443


def _find_tshark() -> str | None:
    configured = os.environ.get("TSHARK")
    candidates = (
        configured,
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    return None


def _hello() -> bytes:
    return struct.pack(
        "<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1, 0x0102030405060708, 4242, 0
    )


def _challenge() -> bytes:
    return struct.pack("<4sHH16s", b"PLC1", 1, 0xBEEF, bytes(range(16)))


def _authentication() -> bytes:
    return struct.pack("<4sHH32s", b"PLA1", 1, 0, bytes(range(32)))


def _plk1_header() -> bytes:
    vector = b"passive-synthetic-vector"
    return struct.pack(
        "<4sHBBQQ32s",
        b"PLK1",
        1,
        0,
        0,
        len(vector),
        len(vector),
        hashlib.sha256(vector).digest(),
    )


def _envelope() -> bytes:
    ciphertext = bytes.fromhex("00112233445566778899aabbccddeeff")
    return b"\x01" + bytes(range(16)) + struct.pack(">I", len(ciphertext)) + ciphertext + bytes(32)


def _ethernet_ipv4_tcp(payload: bytes, sequence: int) -> bytes:
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
        ipaddress.ip_address(CLIENT_IP).packed,
        ipaddress.ip_address(SERVER_IP).packed,
    )
    tcp = struct.pack(
        ">HHIIBBHHH",
        CLIENT_PORT,
        SERVER_PORT,
        sequence,
        0,
        5 << 4,
        0x18,
        8192,
        0,
        0,
    )
    return ethernet + ipv4 + tcp + payload


def _pcap(payloads: list[tuple[int, bytes]]) -> bytes:
    output = bytearray(
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    for index, (_, packet) in enumerate(payloads):
        output.extend(struct.pack("<IIII", 1_700_000_000, 100 + index, len(packet), len(packet)))
        output.extend(packet)
    return bytes(output)


def _pcapng(payloads: list[tuple[int, bytes]]) -> bytes:
    def block(block_type: int, body: bytes) -> bytes:
        total_length = 12 + len(body)
        return (
            struct.pack("<II", block_type, total_length)
            + body
            + struct.pack("<I", total_length)
        )

    output = bytearray()
    output.extend(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    output.extend(block(1, struct.pack("<HHI", 1, 0, 65535)))
    for index, (_, packet) in enumerate(payloads):
        padding = bytes((-len(packet)) % 4)
        timestamp = 1_700_000_000_000_000 + index
        body = (
            struct.pack(
                "<IIIII",
                0,
                timestamp >> 32,
                timestamp & 0xFFFFFFFF,
                len(packet),
                len(packet),
            )
            + packet
            + padding
        )
        output.extend(block(6, body))
    return bytes(output)


@unittest.skipUnless(_find_tshark(), "tshark is not installed")
class WiresharkRuntimeTests(unittest.TestCase):
    tshark = _find_tshark()

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="packclient-dissector-")
        cls.capture_dir = Path(cls.temporary.name)

        plh1 = frame_bytes(TYPE_PLAINTEXT, _hello())
        plc1 = frame_bytes(TYPE_PLAINTEXT, _challenge())
        pla1 = frame_bytes(TYPE_PLAINTEXT, _authentication())
        plk1 = frame_bytes(TYPE_PLAINTEXT, _plk1_header())
        envelope = frame_bytes(TYPE_ENCRYPTED, _envelope())
        combined = plh1 + plc1 + pla1 + plk1 + envelope
        malformed = struct.pack("<I", FRAME_PREFIX | 3) + b"\x00\x00\x00"
        prefix_collision = (
            struct.pack("<II4s", FRAME_PREFIX | 36, TYPE_PLAINTEXT, b"NOPE")
            + bytes(28)
        )
        invalid_plh1_payload = bytearray(_hello())
        struct.pack_into("<H", invalid_plh1_payload, 4, 2)
        invalid_plh1 = frame_bytes(TYPE_PLAINTEXT, bytes(invalid_plh1_payload))
        invalid_envelope_payload = bytearray(_envelope())
        invalid_envelope_payload[0] = 2
        invalid_envelope = frame_bytes(TYPE_ENCRYPTED, bytes(invalid_envelope_payload))

        captures = {
            "heuristic": [(1000, plh1)],
            "heuristic_false_positive": [(1500, prefix_collision)],
            "combined": [(2000, combined)],
            "envelope": [(2500, envelope)],
            "split_after_header": [(3000, plh1[:4]), (3004, plh1[4:])],
            "split_header": [(4000, plh1[:2]), (4002, plh1[2:])],
            "malformed": [(5000, malformed)],
            "invalid_plh1": [(6000, invalid_plh1)],
            "invalid_envelope": [(7000, invalid_envelope)],
        }
        cls.paths: dict[str, Path] = {}
        for name, segments in captures.items():
            path = cls.capture_dir / f"{name}.pcap"
            packets = [
                (sequence, _ethernet_ipv4_tcp(payload, sequence))
                for sequence, payload in segments
            ]
            path.write_bytes(_pcap(packets))
            cls.paths[name] = path
        pcapng_path = cls.capture_dir / "heuristic.pcapng"
        pcapng_packet = _ethernet_ipv4_tcp(plh1, 8000)
        pcapng_path.write_bytes(_pcapng([(8000, pcapng_packet)]))
        cls.paths["pcapng"] = pcapng_path

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def _run(
        self, *arguments: str, invalid_field: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        assert self.tshark is not None
        # Supported TShark versions require -G to be the first argument.
        # Load the Lua dissector for both glossary and packet checks.
        result = subprocess.run(
            [self.tshark, *arguments, "-n", "-X", f"lua_script:{LUA_DISSECTOR}"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if invalid_field is None:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "Unregistered field must be rejected")
            self.assertIn("Some fields aren't valid", result.stderr)
            self.assertIn(invalid_field, result.stderr)
        self.assertNotIn("Lua Error", result.stderr)
        return result

    def _fields(
        self,
        capture: str,
        fields: tuple[str, ...],
        *,
        decode_as: bool = True,
        display_filter: str | None = None,
        heuristic_first: bool = False,
    ) -> list[list[str]]:
        arguments = [
            "-2",
            "-r",
            str(self.paths[capture]),
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
        ]
        if heuristic_first:
            arguments.extend(("-o", "tcp.try_heuristic_first:TRUE"))
        if decode_as:
            arguments.extend(("-d", f"tcp.port=={SERVER_PORT},packclient"))
        if display_filter:
            arguments.extend(("-Y", display_filter))
        arguments.extend(("-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"))
        for field in fields:
            arguments.extend(("-e", field))
        output = self._run(*arguments).stdout
        return [line.split("\t") for line in output.splitlines()]

    def test_plugin_loads_and_protocol_registers(self):
        protocols = self._run("-G", "protocols").stdout
        rows = [line.split("\t") for line in protocols.splitlines()]
        self.assertTrue(any(len(row) >= 3 and row[0] == "PackClient Launcher Transport"
                            and row[2] == "packclient" for row in rows),
                        "PackClient must register its long name and filter abbreviation")

    def test_framing_and_handshake_labels(self):
        rows = self._fields(
            "combined",
            ("packclient.frame_word", "packclient.body_length", "packclient.object.magic"),
            display_filter="packclient",
        )
        joined = "\n".join("\t".join(row) for row in rows)
        self.assertIn("0x5a400024", joined)
        self.assertIn("36", joined)
        for magic in ("PLH1", "PLC1", "PLA1"):
            self.assertIn(magic, joined)

    def test_plk1_header_fields_decode(self):
        rows = self._fields(
            "combined",
            (
                "packclient.plk1.wire_version",
                "packclient.plk1.lz4_flag",
                "packclient.plk1.total_size",
                "packclient.plk1.original_size",
                "packclient.plk1.expected_sha256",
            ),
            display_filter="packclient.object.magic == \"PLK1\"",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0:4], ["1", "0x00", "24", "24"])
        self.assertEqual(rows[0][4], hashlib.sha256(b"passive-synthetic-vector").hexdigest())

    def test_type_0x16_is_metadata_only(self):
        rows = self._fields(
            "envelope",
            (
                "packclient.message_type",
                "packclient.envelope.version",
                "packclient.envelope.ciphertext_length",
                "packclient.object.magic",
            ),
            display_filter="packclient.message_type == 0x16",
        )
        self.assertEqual(rows, [["0x00000016", "1", "16", ""]])
        ## Query absent fields directly because older TShark interprets additional
        # `-G fields` arguments as a prefix, conflicting with the Lua-loader flags.
        for name in ("packclient.envelope.plaintext", "packclient.envelope.decrypted"):
            self._run("-r", str(self.paths["envelope"]), "-T", "fields", "-e", name,
                      invalid_field=name)

    def test_split_after_outer_header_desegments(self):
        rows = self._fields(
            "split_after_header",
            ("frame.number", "packclient.object.magic"),
            display_filter="packclient.object.magic == \"PLH1\"",
        )
        self.assertEqual(rows, [["2", "PLH1"]])

        heuristic_rows = self._fields(
            "split_after_header",
            ("frame.number", "packclient.object.magic"),
            decode_as=False,
            heuristic_first=True,
            display_filter="packclient.object.magic == \"PLH1\"",
        )
        self.assertEqual(heuristic_rows, [["2", "PLH1"]])

    def test_header_split_desegments_with_decode_as(self):
        rows = self._fields(
            "split_header",
            ("frame.number", "packclient.object.magic"),
            display_filter="packclient.object.magic == \"PLH1\"",
        )
        self.assertEqual(rows, [["2", "PLH1"]])

    def test_multiple_pdus_in_one_segment_decode_independently(self):
        rows = self._fields(
            "combined",
            ("packclient.object.magic", "packclient.message_type"),
            display_filter="packclient",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0].split(","), ["PLH1", "PLC1", "PLA1", "PLK1"])
        self.assertEqual(len(rows[0][1].split(",")), 5)

    def test_impossible_framing_fails_safely(self):
        rows = self._fields(
            "malformed",
            ("packclient.frame_word", "packclient.message_type", "_ws.expert.message"),
            display_filter="packclient",
        )
        self.assertEqual(
            rows,
            [["0x5a400003", "", "Malformed PackClient framing"]],
        )

        heuristic_rows = self._fields(
            "malformed",
            ("packclient.frame_word",),
            decode_as=False,
            heuristic_first=True,
            display_filter="packclient",
        )
        self.assertEqual(heuristic_rows, [])

    def test_invalid_structures_are_not_given_verified_labels(self):
        handshake_rows = self._fields(
            "invalid_plh1",
            ("packclient.object.magic", "_ws.expert.message"),
            display_filter="packclient",
        )
        self.assertEqual(
            handshake_rows,
            [["", "PLH1 fixed field validation failed"]],
        )

        envelope_rows = self._fields(
            "invalid_envelope",
            ("_ws.col.Info",),
            display_filter="packclient.envelope.version == 2",
        )
        self.assertEqual(len(envelope_rows), 1)
        self.assertNotIn("type 0x16 metadata", envelope_rows[0][0])

    def test_heuristic_recognition(self):
        rows = self._fields(
            "heuristic",
            ("_ws.col.Protocol", "packclient.object.magic"),
            decode_as=False,
            heuristic_first=True,
            display_filter="packclient",
        )
        self.assertEqual(rows, [["PackClient", "PLH1"]])

    def test_heuristic_rejects_frame_prefix_collision(self):
        rows = self._fields(
            "heuristic_false_positive",
            ("_ws.col.Protocol", "packclient.frame_word"),
            decode_as=False,
            heuristic_first=True,
            display_filter="packclient",
        )
        self.assertEqual(rows, [])

    def test_synthetic_pcapng_is_dissected(self):
        rows = self._fields(
            "pcapng",
            ("_ws.col.Protocol", "packclient.object.magic"),
            decode_as=False,
            heuristic_first=True,
            display_filter="packclient",
        )
        self.assertEqual(rows, [["PackClient", "PLH1"]])

    def test_decode_as_and_useful_display_filters(self):
        filters = {
            "packclient": "PLH1",
            "packclient.message_type == 0x15": "PLH1",
            "packclient.object.magic == \"PLC1\"": "PLC1",
            "packclient.plk1.total_size == 24": "PLK1",
            "packclient.envelope.ciphertext_length == 16": "0x00000016",
        }
        for display_filter, expected in filters.items():
            with self.subTest(display_filter=display_filter):
                rows = self._fields(
                    "combined",
                    ("packclient.object.magic", "packclient.message_type"),
                    display_filter=display_filter,
                )
                self.assertEqual(len(rows), 1)
                self.assertIn(expected, "\t".join(rows[0]))


if __name__ == "__main__":
    unittest.main()
