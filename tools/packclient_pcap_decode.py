#!/usr/bin/env python3
"""Print a PackClient timeline from a PCAP or PCAPNG file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.packclient_pcap import (  # noqa: E402
    analyze_capture,
    format_timeline,
    parse_endpoint,
)
from tools.packclient_proto import ProtocolError  # noqa: E402


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
    parser.add_argument("input", help="PCAP/PCAPNG file, or - for standard input")
    parser.add_argument(
        "--client-endpoint",
        action="append",
        default=[],
        metavar="IP:PORT",
        help=(
            "explicit client-side endpoint override; repeat as needed; IPv6 uses "
            "[address]:port; numeric addresses only"
        ),
    )
    psk_group = parser.add_mutually_exclusive_group()
    psk_group.add_argument("--psk-text", help="literal UTF-8 handshake PSK")
    psk_group.add_argument("--psk-hex", help="hex-encoded handshake PSK")
    psk_group.add_argument(
        "--use-default-psk",
        action="store_true",
        help="explicitly opt in to the recovered Launcher fallback PSK",
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
    parser.add_argument(
        "--all-tcp",
        action="store_true",
        help="include other TCP payload flows for capture troubleshooting",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        data = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
        endpoints = [parse_endpoint(value) for value in args.client_endpoint]
        if args.psk_text is not None:
            psk = args.psk_text.encode("utf-8")
            if not psk:
                raise ProtocolError("--psk-text must be nonempty")
        elif args.psk_hex is not None:
            try:
                psk = bytes.fromhex(args.psk_hex)
            except ValueError as exc:
                raise ProtocolError("handshake PSK must be hexadecimal") from exc
            if not psk:
                raise ProtocolError("--psk-hex must decode to a nonempty value")
        else:
            psk = None
        aes_key = _hex_key(args.aes_key_hex, "AES key") if args.aes_key_hex else None
        hmac_key = (
            _hex_key(args.envelope_hmac_key_hex, "envelope HMAC key")
            if args.envelope_hmac_key_hex else None
        )
        report = analyze_capture(
            data,
            client_endpoints=endpoints,
            psk=psk,
            use_default_psk=args.use_default_psk,
            aes_key=aes_key,
            envelope_hmac_key=hmac_key,
            decode_lz4=not args.no_lz4,
            include_all_tcp=args.all_tcp,
        )
        print(format_timeline(report))
        return 0 if all(flow["status"] in ("parsed", "partial") for flow in report["flows"]) else 2
    except (OSError, ValueError, ProtocolError) as exc:
        print(f"rejected/malformed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
