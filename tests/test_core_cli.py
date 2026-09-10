"""End-to-end tests for capture recovery and Core timeline output."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_core_crypto import CORE_ENVELOPE, CORE_PSK
from test_core_protocol import JPEG, PV10
from test_pcap_tooling import ethernet_ipv4_tcp, pcap
from test_plk1_extraction import plk1_stream, synthetic_pe
from tools.packclient_proto import TYPE_ENCRYPTED, frame_bytes


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "tools" / "packclient_pcap_decode.py"


def run_cli(capture: bytes, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-B", str(CLI), "-", *arguments],
        cwd=ROOT,
        input=capture,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CoreCLITests(unittest.TestCase):
    def test_capture_to_plk1_and_pv10_artifacts(self):
        plaintext = synthetic_pe()
        server_stream = plk1_stream(plaintext) + frame_bytes(
            3, b"SYS|Q|EXT|STARTUP|PROBE|"
        )
        client_stream = frame_bytes(18, PV10)
        capture = pcap(
            [
                (1_700_000_000, 100, ethernet_ipv4_tcp(server_stream, 5000, client_to_server=False)),
                (1_700_000_000, 200, ethernet_ipv4_tcp(client_stream, 1000, client_to_server=True)),
            ]
        )
        with tempfile.TemporaryDirectory(prefix="packclient-cli-") as temporary:
            output = Path(temporary) / "artifacts"
            result = run_cli(
                capture,
                "--output-dir",
                str(output),
                "--extract-plk1",
                "--extract-pv10",
            )
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
            self.assertEqual(result.stderr, b"")
            manifest = json.loads((output / "manifest.json").read_text("utf-8"))
            self.assertEqual(len(manifest["plk1"]), 1)
            self.assertEqual(len(manifest["pv10"]), 1)
            self.assertEqual((output / manifest["plk1"][0]["output_file"]).read_bytes(), plaintext)
            self.assertEqual((output / manifest["pv10"][0]["output_file"]).read_bytes(), JPEG)
            self.assertIn(b"command=startup-probe", result.stdout)
            self.assertIn(b"class=PV10", result.stdout)
            self.assertNotIn(plaintext, result.stdout)
            self.assertNotIn(JPEG, result.stdout)

    def test_core_envelope_timeline_does_not_print_psk_or_plaintext(self):
        frame = frame_bytes(TYPE_ENCRYPTED, CORE_ENVELOPE)
        capture = pcap(
            [(1_700_000_000, 100, ethernet_ipv4_tcp(frame, 1000, client_to_server=True))]
        )
        result = run_cli(
            capture,
            "--phase",
            "core",
            "--core-psk-text",
            CORE_PSK.decode(),
        )
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        self.assertIn(b"decrypt=verified", result.stdout)
        self.assertIn(b"command=startup-probe", result.stdout)
        self.assertNotIn(CORE_PSK, result.stdout)
        self.assertNotIn(b"SYS|Q|EXT|STARTUP|PROBE|", result.stdout)

    def test_failed_verification_leaves_no_output_directory(self):
        plaintext = synthetic_pe()
        stream = plk1_stream(plaintext, digest=bytes(32))
        capture = pcap(
            [(1_700_000_000, 100, ethernet_ipv4_tcp(stream, 5000, client_to_server=False))]
        )
        with tempfile.TemporaryDirectory(prefix="packclient-cli-") as temporary:
            output = Path(temporary) / "must-not-exist"
            result = run_cli(capture, "--output-dir", str(output), "--extract-plk1")
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            self.assertNotIn(b"Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
