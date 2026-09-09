#!/usr/bin/env python3
"""Passively decode a raw PackClient Launcher byte stream."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.packclient_proto import ProtocolError, StreamDecoder  # noqa: E402


def _hex_key(value: str, label: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ProtocolError(f"{label} must be hexadecimal") from exc
    if len(decoded) != 32:
        raise ProtocolError(f"{label} must decode to exactly 32 bytes")
    return decoded


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="raw stream file, or - for standard input")
    parser.add_argument(
        "--direction",
        help=(
            "analyst-supplied label; use client-to-server or server-to-client "
            "for directional handshake validation"
        ),
    )
    psk_group = parser.add_mutually_exclusive_group()
    psk_group.add_argument("--psk-text", help="literal UTF-8 handshake PSK")
    psk_group.add_argument("--psk-hex", help="hex-encoded handshake PSK")
    psk_group.add_argument(
        "--use-default-psk",
        action="store_true",
        help="explicitly use recovered Launcher fallback pack-launch-dev-psk",
    )
    parser.add_argument("--aes-key-hex", help="independent 32-byte AES key as hex")
    parser.add_argument(
        "--envelope-hmac-key-hex",
        help="independent 32-byte envelope HMAC key as hex",
    )
    parser.add_argument(
        "--no-lz4",
        action="store_true",
        help="do not attempt optional raw-block LZ4 decoding",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.input == "-":
            data = sys.stdin.buffer.read()
        else:
            data = Path(args.input).read_bytes()
        if args.psk_text is not None:
            psk = args.psk_text.encode("utf-8")
        elif args.psk_hex is not None:
            psk = bytes.fromhex(args.psk_hex)
            if not psk:
                raise ProtocolError("--psk-hex must decode to a nonempty value")
        else:
            psk = None
        aes_key = _hex_key(args.aes_key_hex, "AES key") if args.aes_key_hex else None
        hmac_key = (
            _hex_key(args.envelope_hmac_key_hex, "envelope HMAC key")
            if args.envelope_hmac_key_hex
            else None
        )
        report = StreamDecoder(
            direction=args.direction,
            psk=psk,
            use_default_psk=args.use_default_psk,
            aes_key=aes_key,
            envelope_hmac_key=hmac_key,
            decode_lz4=not args.no_lz4,
        ).decode(data)
    except (OSError, ValueError, ProtocolError) as exc:
        report = {"status": "rejected/malformed", "error": str(exc)}
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if report["status"] == "parsed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
