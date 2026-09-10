#!/usr/bin/env python3
"""Print a passive PackClient timeline from PCAP or PCAPNG input."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.packclient_pcap import (  # noqa: E402
    PLK1Artifact,
    PV10Artifact,
    analyze_capture,
    format_timeline,
    parse_endpoint,
)
from tools.packclient_artifacts import export_capture_artifacts  # noqa: E402
from tools.packclient_proto import (  # noqa: E402
    PHASE_AUTO,
    PHASE_CORE,
    PHASE_LAUNCHER,
    ProtocolError,
)


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
    parser.add_argument(
        "--phase",
        choices=(PHASE_AUTO, PHASE_LAUNCHER, PHASE_CORE),
        default=PHASE_AUTO,
        help="protocol phase; auto switches to Core after a complete PLK1 transfer",
    )
    core_psk_group = parser.add_mutually_exclusive_group()
    core_psk_group.add_argument("--core-psk-text", help="literal UTF-8 Core auth_psk")
    core_psk_group.add_argument("--core-psk-hex", help="hex-encoded Core auth_psk")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for verified artifacts and manifest.json",
    )
    parser.add_argument(
        "--extract-plk1",
        action="store_true",
        help="write each unique verified PLK1 plaintext",
    )
    parser.add_argument(
        "--extract-pv10",
        action="store_true",
        help="write each unique validated PV10 JPEG",
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
        if args.core_psk_text is not None:
            core_psk = args.core_psk_text.encode("utf-8")
            if not core_psk:
                raise ProtocolError("--core-psk-text must be nonempty")
        elif args.core_psk_hex is not None:
            try:
                core_psk = bytes.fromhex(args.core_psk_hex)
            except ValueError as exc:
                raise ProtocolError("Core auth_psk must be hexadecimal") from exc
            if not core_psk:
                raise ProtocolError("--core-psk-hex must decode to a nonempty value")
        else:
            core_psk = None
        if (args.extract_plk1 or args.extract_pv10) and args.output_dir is None:
            raise ProtocolError("--output-dir is required when extracting artifacts")
        if args.output_dir is not None and not (args.extract_plk1 or args.extract_pv10):
            raise ProtocolError("--output-dir requires --extract-plk1 or --extract-pv10")
        aes_key = _hex_key(args.aes_key_hex, "AES key") if args.aes_key_hex else None
        hmac_key = (
            _hex_key(args.envelope_hmac_key_hex, "envelope HMAC key")
            if args.envelope_hmac_key_hex else None
        )
        plk1_artifacts: list[PLK1Artifact] = []
        pv10_artifacts: list[PV10Artifact] = []
        report = analyze_capture(
            data,
            client_endpoints=endpoints,
            psk=psk,
            use_default_psk=args.use_default_psk,
            aes_key=aes_key,
            envelope_hmac_key=hmac_key,
            core_psk=core_psk,
            decode_lz4=not args.no_lz4,
            include_all_tcp=args.all_tcp,
            phase=args.phase,
            plk1_artifacts=plk1_artifacts,
            pv10_artifacts=pv10_artifacts,
        )
        if args.output_dir is not None:
            if any(flow["status"] == "rejected/malformed" for flow in report["flows"]):
                raise ProtocolError("capture contains a rejected PackClient flow; nothing was written")
            if args.extract_plk1 and not plk1_artifacts:
                raise ProtocolError("capture contains no verified PLK1 plaintext; nothing was written")
            if args.extract_pv10 and not pv10_artifacts:
                raise ProtocolError("capture contains no validated PV10 JPEG; nothing was written")
            manifest = export_capture_artifacts(
                capture=data,
                capture_format=report["capture_format"],
                output_dir=args.output_dir,
                plk1_artifacts=plk1_artifacts,
                pv10_artifacts=pv10_artifacts,
                export_plk1=args.extract_plk1,
                export_pv10=args.extract_pv10,
            )
            print(
                f"artifacts={args.output_dir / 'manifest.json'} "
                f"plk1={len(manifest['plk1'])} pv10={len(manifest['pv10'])}"
            )
        print(format_timeline(report))
        return 0 if all(flow["status"] in ("parsed", "partial") for flow in report["flows"]) else 2
    except (OSError, ValueError, ProtocolError) as exc:
        print(f"rejected/malformed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
