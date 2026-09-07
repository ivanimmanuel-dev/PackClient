import json
from pathlib import Path
import subprocess
import sys
import unittest

from synthetic_stream import (
    AES_KEY,
    ENCRYPTED_APPLICATION_PAYLOAD,
    ENVELOPE_HMAC_KEY,
    PLK1_PLAINTEXT,
    PSK,
    malformed_stream,
    valid_stream,
)


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "tools" / "packclient_decode.py"


def run_cli(stream: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-B",
            str(CLI),
            "-",
            "--direction",
            "protocol-logic-fixture",
            "--psk-hex",
            PSK.hex(),
            "--aes-key-hex",
            AES_KEY.hex(),
            "--envelope-hmac-key-hex",
            ENVELOPE_HMAC_KEY.hex(),
        ],
        cwd=ROOT,
        input=stream,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class RawCLITests(unittest.TestCase):
    def assert_secrets_absent(self, result: subprocess.CompletedProcess[bytes]) -> None:
        combined = result.stdout + result.stderr
        for secret in (PSK, PSK.hex().encode(), AES_KEY.hex().encode(), ENVELOPE_HMAC_KEY.hex().encode()):
            self.assertNotIn(secret, combined)

    def test_full_synthetic_stream(self):
        result = run_cli(valid_stream())
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        self.assert_secrets_absent(result)
        self.assertNotIn(ENCRYPTED_APPLICATION_PAYLOAD, result.stdout)
        self.assertNotIn(PLK1_PLAINTEXT, result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "parsed")
        self.assertEqual(report["frame_count"], 7)
        self.assertEqual(report["frames"][2]["handshake"]["verification_status"], "verified")
        self.assertEqual(report["frames"][3]["envelope"]["hmac_status"], "verified")
        self.assertEqual(report["frames"][3]["envelope"]["decryption_status"], "verified")
        self.assertEqual(report["reassemblies"][0]["final"]["status"], "verified")

    def test_malformed_stream_fails_closed_without_secret_leak(self):
        result = run_cli(malformed_stream())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")
        self.assert_secrets_absent(result)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "rejected/malformed")
        self.assertIn("wrong outer frame prefix", report["error"])

    def test_invalid_secret_argument_is_redacted_without_traceback(self):
        secret_argument = "synthetic-invalid-secret-value"
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(CLI),
                "-",
                "--aes-key-hex",
                secret_argument,
            ],
            cwd=ROOT,
            input=valid_stream(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(secret_argument.encode(), result.stdout)
        self.assertNotIn(b"Traceback", result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "rejected/malformed")
        self.assertEqual(report["error"], "AES key must be hexadecimal")


if __name__ == "__main__":
    unittest.main()
