#!/usr/bin/env python3
"""PCAP/PCAPNG parser and TCP reassembler for the recovered PackClient protocol."""

from __future__ import annotations

import ipaddress
import struct
from bisect import bisect_right
from dataclasses import dataclass
from datetime import UTC, datetime
from fractions import Fraction
from typing import Any, Iterable

from tools.packclient_proto import (
    DIRECTION_CLIENT_TO_SERVER,
    DIRECTION_SERVER_TO_CLIENT,
    FRAME_PREFIX,
    FRAME_PREFIX_MASK,
    BODY_LENGTH_MASK,
    HandshakeContext,
    ProtocolError,
    StreamDecoder,
    TYPE_ENCRYPTED,
    TYPE_PLAINTEXT,
    parse_pla1,
    parse_plc1,
    parse_plh1,
    validate_body_length,
)


DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276
MAX_CAPTURE_PACKET = 64 * 1024 * 1024
MAX_REASSEMBLED_DIRECTION = 256 * 1024 * 1024


@dataclass(frozen=True)
class CapturePacket:
    index: int
    timestamp: Fraction | None
    linktype: int
    byte_order: str
    captured_length: int
    original_length: int
    data: bytes


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    def __str__(self) -> str:
        if ":" in self.address:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class TCPSegment:
    packet_index: int
    timestamp: Fraction | None
    source: Endpoint
    destination: Endpoint
    sequence: int
    payload: bytes
    syn: bool


@dataclass(frozen=True)
class ByteOrigin:
    timestamp: Fraction | None
    packet_index: int


@dataclass(frozen=True)
class OriginSpan:
    start: int
    end: int
    origin: ByteOrigin


@dataclass(frozen=True)
class ReassembledDirection:
    data: bytes
    origins: tuple[OriginSpan, ...]
    segment_count: int
    duplicate_segments: int
    retransmitted_bytes: int
    error: str | None


@dataclass(frozen=True)
class _PcapngInterface:
    linktype: int
    snaplen: int
    timestamp_units: Fraction
    timestamp_offset: int


def _need(data: bytes, offset: int, length: int, what: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ProtocolError(f"truncated {what}", offset=offset)


def parse_capture(data: bytes) -> tuple[str, list[CapturePacket]]:
    """Parse classic PCAP or PCAPNG bytes without invoking external tooling."""
    if len(data) < 4:
        raise ProtocolError("capture is shorter than a file signature", offset=0)
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng", _parse_pcapng(data)
    magic = data[:4]
    variants = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in variants:
        raise ProtocolError("unsupported capture signature (expected PCAP or PCAPNG)")
    endian, resolution = variants[magic]
    return "pcap", _parse_pcap(data, endian, resolution)


def _parse_pcap(data: bytes, endian: str, resolution: int) -> list[CapturePacket]:
    _need(data, 0, 24, "PCAP global header")
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    if (major, minor) != (2, 4):
        raise ProtocolError(f"unsupported PCAP version {major}.{minor}")
    snaplen, linktype = struct.unpack_from(endian + "II", data, 16)
    if snaplen == 0:
        raise ProtocolError("PCAP snaplen is zero")
    linktype &= 0xFFFF
    packets: list[CapturePacket] = []
    offset = 24
    while offset < len(data):
        _need(data, offset, 16, "PCAP packet header")
        seconds, fraction, captured, original = struct.unpack_from(
            endian + "IIII", data, offset
        )
        if fraction >= resolution:
            raise ProtocolError("PCAP packet timestamp fraction is out of range", offset=offset)
        if captured > MAX_CAPTURE_PACKET or captured > snaplen:
            raise ProtocolError("PCAP captured length exceeds the safe/snaplen bound", offset=offset)
        if captured > original:
            raise ProtocolError("PCAP captured length exceeds original length", offset=offset)
        _need(data, offset + 16, captured, "PCAP packet data")
        packet_data = data[offset + 16 : offset + 16 + captured]
        packets.append(
            CapturePacket(
                len(packets),
                Fraction(seconds * resolution + fraction, resolution),
                linktype,
                endian,
                captured,
                original,
                packet_data,
            )
        )
        offset += 16 + captured
    return packets


def _parse_pcapng_options(
    block: bytes, start: int, end: int, endian: str
) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    offset = start
    while offset < end:
        _need(block, offset, 4, "PCAPNG option header")
        code, length = struct.unpack_from(endian + "HH", block, offset)
        offset += 4
        if code == 0:
            if length != 0:
                raise ProtocolError("PCAPNG end-of-options length is nonzero")
            return options
        padded = (length + 3) & ~3
        if offset + padded > end:
            raise ProtocolError("truncated PCAPNG option value")
        options.setdefault(code, []).append(block[offset : offset + length])
        offset += padded
    return options


def _parse_pcapng(data: bytes) -> list[CapturePacket]:
    packets: list[CapturePacket] = []
    interfaces: list[_PcapngInterface] = []
    endian: str | None = None
    offset = 0
    while offset < len(data):
        _need(data, offset, 12, "PCAPNG block")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            _need(data, offset, 28, "PCAPNG section header")
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ProtocolError("invalid PCAPNG byte-order magic", offset=offset)
            total = struct.unpack_from(endian + "I", data, offset + 4)[0]
            if total < 28:
                raise ProtocolError("PCAPNG section header is too short", offset=offset)
            interfaces = []
        else:
            if endian is None:
                raise ProtocolError("PCAPNG data appears before a section header", offset=offset)
            total = struct.unpack_from(endian + "I", data, offset + 4)[0]
        if total < 12 or total % 4 != 0:
            raise ProtocolError("invalid PCAPNG block length", offset=offset)
        _need(data, offset, total, "PCAPNG block")
        block = data[offset : offset + total]
        if struct.unpack_from(endian + "I", block, total - 4)[0] != total:
            raise ProtocolError("PCAPNG leading/trailing block lengths disagree", offset=offset)
        block_type = struct.unpack_from(endian + "I", block, 0)[0]
        if block_type == 0x0A0D0D0A:
            major, minor = struct.unpack_from(endian + "HH", block, 12)
            if (major, minor) != (1, 0):
                raise ProtocolError(f"unsupported PCAPNG version {major}.{minor}")
        elif block_type == 1:
            if total < 20:
                raise ProtocolError("PCAPNG interface block is too short", offset=offset)
            linktype = struct.unpack_from(endian + "H", block, 8)[0]
            snaplen = struct.unpack_from(endian + "I", block, 12)[0]
            options = _parse_pcapng_options(block, 16, total - 4, endian)
            units = Fraction(1, 1_000_000)
            if 9 in options:
                value = options[9][-1]
                if len(value) != 1:
                    raise ProtocolError("PCAPNG if_tsresol must be one byte")
                exponent = value[0] & 0x7F
                units = Fraction(1, (2 if value[0] & 0x80 else 10) ** exponent)
            timestamp_offset = 0
            if 14 in options:
                value = options[14][-1]
                if len(value) != 8:
                    raise ProtocolError("PCAPNG if_tsoffset must be eight bytes")
                timestamp_offset = struct.unpack(endian + "q", value)[0]
            interfaces.append(_PcapngInterface(linktype, snaplen, units, timestamp_offset))
        elif block_type == 6:
            if total < 32:
                raise ProtocolError("PCAPNG enhanced packet block is too short", offset=offset)
            interface_id, ts_high, ts_low, captured, original = struct.unpack_from(
                endian + "IIIII", block, 8
            )
            if interface_id >= len(interfaces):
                raise ProtocolError("PCAPNG packet references an unknown interface", offset=offset)
            if captured > MAX_CAPTURE_PACKET:
                raise ProtocolError("PCAPNG captured length exceeds the safe bound", offset=offset)
            interface = interfaces[interface_id]
            if captured > original or (interface.snaplen and captured > interface.snaplen):
                raise ProtocolError("PCAPNG captured length exceeds original/snaplen bound", offset=offset)
            padded = (captured + 3) & ~3
            if 28 + padded > total - 4:
                raise ProtocolError("truncated PCAPNG enhanced packet data", offset=offset)
            ticks = (ts_high << 32) | ts_low
            timestamp = interface.timestamp_offset + ticks * interface.timestamp_units
            packet_data = block[28 : 28 + captured]
            packets.append(
                CapturePacket(
                    len(packets), timestamp, interface.linktype, endian,
                    captured, original, packet_data
                )
            )
        elif block_type == 3:
            if not interfaces:
                raise ProtocolError("PCAPNG simple packet has no interface", offset=offset)
            if total < 16:
                raise ProtocolError("PCAPNG simple packet block is too short", offset=offset)
            original = struct.unpack_from(endian + "I", block, 8)[0]
            snaplen = interfaces[0].snaplen
            captured = min(original, snaplen) if snaplen else original
            if captured > MAX_CAPTURE_PACKET:
                raise ProtocolError("PCAPNG captured length exceeds the safe bound", offset=offset)
            if total - 16 != ((captured + 3) & ~3):
                raise ProtocolError("PCAPNG simple packet length disagrees with original/snaplen", offset=offset)
            packets.append(
                CapturePacket(
                    len(packets), None, interfaces[0].linktype, endian,
                    captured, original,
                    block[12 : 12 + captured],
                )
            )
        offset += total
    return packets


def _network_payload(packet: CapturePacket) -> tuple[int, bytes] | None:
    data = packet.data
    linktype = packet.linktype
    if linktype == DLT_EN10MB:
        if len(data) < 14:
            return None
        ethertype = struct.unpack_from(">H", data, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack_from(">H", data, offset + 2)[0]
            offset += 4
        return ethertype, data[offset:]
    if linktype in (DLT_RAW, DLT_IPV4, DLT_IPV6):
        if not data:
            return None
        version = data[0] >> 4
        if linktype == DLT_IPV4 or version == 4:
            return 0x0800, data
        if linktype == DLT_IPV6 or version == 6:
            return 0x86DD, data
        return None
    if linktype == DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        return struct.unpack_from(">H", data, 14)[0], data[16:]
    if linktype == DLT_LINUX_SLL2:
        if len(data) < 20:
            return None
        return struct.unpack_from(">H", data, 0)[0], data[20:]
    if linktype in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            return None
        raw = data[:4]
        families = {
            2: 0x0800,
            10: 0x86DD,
            23: 0x86DD,
            24: 0x86DD,
            28: 0x86DD,
            30: 0x86DD,
        }
        address_family_order = ">" if linktype == DLT_LOOP else packet.byte_order
        first = struct.unpack(address_family_order + "I", raw)[0]
        ethertype = families.get(first)
        return (ethertype, data[4:]) if ethertype is not None else None
    return None


def _tcp_from_packet(packet: CapturePacket) -> TCPSegment | None:
    network = _network_payload(packet)
    if network is None:
        return None
    ethertype, data = network
    if ethertype == 0x0800:
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack_from(">H", data, 2)[0]
        if ihl < 20 or total < ihl or total > len(data):
            return None
        fragment = struct.unpack_from(">H", data, 6)[0]
        if fragment & 0x3FFF or data[9] != 6:
            return None
        source_address = str(ipaddress.ip_address(data[12:16]))
        destination_address = str(ipaddress.ip_address(data[16:20]))
        tcp = data[ihl:total]
    elif ethertype == 0x86DD:
        if len(data) < 40 or data[0] >> 4 != 6:
            return None
        payload_length = struct.unpack_from(">H", data, 4)[0]
        end = 40 + payload_length
        if end > len(data):
            return None
        next_header = data[6]
        cursor = 40
        while next_header in (0, 43, 44, 51, 60):
            if next_header == 44:
                return None  # IPv6 fragmentation requires a separate reassembler.
            if cursor + 2 > end:
                return None
            current = next_header
            next_header = data[cursor]
            if current == 51:
                extension_length = (data[cursor + 1] + 2) * 4
            else:
                extension_length = (data[cursor + 1] + 1) * 8
            if extension_length < 8 or cursor + extension_length > end:
                return None
            cursor += extension_length
        if next_header != 6:
            return None
        source_address = str(ipaddress.ip_address(data[8:24]))
        destination_address = str(ipaddress.ip_address(data[24:40]))
        tcp = data[cursor:end]
    else:
        return None
    if len(tcp) < 20:
        return None
    source_port, destination_port, sequence = struct.unpack_from(">HHI", tcp, 0)
    header_length = (tcp[12] >> 4) * 4
    if header_length < 20 or header_length > len(tcp):
        return None
    flags = tcp[13]
    return TCPSegment(
        packet.index,
        packet.timestamp,
        Endpoint(source_address, source_port),
        Endpoint(destination_address, destination_port),
        sequence,
        tcp[header_length:],
        bool(flags & 0x02),
    )


def _endpoint_key(endpoint: Endpoint) -> tuple[int, bytes, int]:
    address = ipaddress.ip_address(endpoint.address)
    return address.version, address.packed, endpoint.port


def _flow_key(source: Endpoint, destination: Endpoint) -> tuple[Endpoint, Endpoint]:
    if _endpoint_key(source) <= _endpoint_key(destination):
        return source, destination
    return destination, source


def _sequence_delta(sequence: int, anchor: int) -> int:
    return ((sequence - anchor + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def reassemble_tcp_direction(segments: Iterable[TCPSegment]) -> ReassembledDirection:
    """Conservatively merge one TCP direction, rejecting gaps/conflicting overlap."""
    rows = [segment for segment in segments if segment.payload]
    if not rows:
        return ReassembledDirection(b"", (), 0, 0, 0, None)
    anchor = (rows[0].sequence + (1 if rows[0].syn else 0)) & 0xFFFFFFFF
    positioned = []
    for segment in rows:
        start_sequence = (segment.sequence + (1 if segment.syn else 0)) & 0xFFFFFFFF
        positioned.append((_sequence_delta(start_sequence, anchor), segment))
    positioned.sort(key=lambda item: (item[0], item[1].packet_index))
    base = positioned[0][0]
    highest_end = max(start - base + len(segment.payload) for start, segment in positioned)
    if highest_end > MAX_REASSEMBLED_DIRECTION:
        return ReassembledDirection(
            b"", (), len(rows), 0, 0,
            "TCP sequence span exceeds the 256 MiB passive reassembly bound",
        )
    stream = bytearray()
    origins: list[OriginSpan] = []
    duplicate_segments = 0
    retransmitted_bytes = 0
    signatures: set[tuple[int, bytes]] = set()
    for start, segment in positioned:
        relative = start - base
        signature = (relative, segment.payload)
        if signature in signatures:
            duplicate_segments += 1
        signatures.add(signature)
        if relative > len(stream):
            return ReassembledDirection(
                bytes(stream), tuple(origins), len(rows), duplicate_segments,
                retransmitted_bytes,
                f"TCP sequence gap of {relative - len(stream)} bytes at stream offset {len(stream)}",
            )
        overlap = min(len(segment.payload), len(stream) - relative)
        if overlap:
            retransmitted_bytes += overlap
            existing = bytes(stream[relative : relative + overlap])
            supplied = segment.payload[:overlap]
            if existing != supplied:
                mismatch = next(
                    index for index, pair in enumerate(zip(existing, supplied))
                    if pair[0] != pair[1]
                )
                return ReassembledDirection(
                    bytes(stream), tuple(origins), len(rows), duplicate_segments,
                    retransmitted_bytes,
                    "contradictory TCP overlap at stream offset "
                    f"{relative + mismatch}; reassembly rejected",
                )
        tail = segment.payload[overlap:]
        if tail:
            tail_start = len(stream)
            stream.extend(tail)
            origins.append(OriginSpan(
                tail_start, len(stream), ByteOrigin(segment.timestamp, segment.packet_index)
            ))
    return ReassembledDirection(
        bytes(stream), tuple(origins), len(rows), duplicate_segments,
        retransmitted_bytes, None,
    )


def _event_origin(origins: tuple[OriginSpan, ...], start: int, end: int) -> ByteOrigin:
    # One span per contributing segment, not one Python object per payload byte.
    index = max(0, bisect_right(origins, start, key=lambda span: span.start) - 1)
    selected = []
    while index < len(origins) and origins[index].start < end:
        span = origins[index]
        if span.end > start:
            selected.append(span.origin)
        index += 1
    known = [origin for origin in selected if origin.timestamp is not None]
    if known:
        return min(known, key=lambda item: (item.timestamp, item.packet_index))
    if selected:
        return min(selected, key=lambda item: item.packet_index)
    return ByteOrigin(None, -1)


def _extract_frames(reassembled: ReassembledDirection) -> list[dict[str, Any]]:
    data = reassembled.data
    events: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data):
        available = len(data) - offset
        if available < 4:
            origin = _event_origin(reassembled.origins, offset, len(data))
            events.append({
                "status": "incomplete",
                "reason": "incomplete PackClient outer header",
                "stream_offset": offset,
                "available_bytes": available,
                "timestamp": origin.timestamp,
                "packet_index": origin.packet_index,
            })
            break
        frame_word = struct.unpack_from("<I", data, offset)[0]
        if frame_word & FRAME_PREFIX_MASK != FRAME_PREFIX:
            origin = _event_origin(reassembled.origins, offset, offset + 4)
            events.append({
                "status": "rejected/malformed",
                "reason": f"wrong outer frame prefix in 0x{frame_word:08X}",
                "stream_offset": offset,
                "timestamp": origin.timestamp,
                "packet_index": origin.packet_index,
            })
            break
        body_length = frame_word & BODY_LENGTH_MASK
        try:
            validate_body_length(body_length)
        except ProtocolError as exc:
            origin = _event_origin(reassembled.origins, offset, offset + 4)
            events.append({
                "status": "rejected/malformed",
                "reason": str(exc),
                "stream_offset": offset,
                "timestamp": origin.timestamp,
                "packet_index": origin.packet_index,
            })
            break
        total = 4 + body_length
        origin = _event_origin(reassembled.origins, offset, min(len(data), offset + total))
        if available < total:
            events.append({
                "status": "incomplete",
                "reason": "incomplete PackClient frame body",
                "stream_offset": offset,
                "frame_word": f"0x{frame_word:08X}",
                "declared_body_length": body_length,
                "declared_frame_length": total,
                "available_bytes": available,
                "timestamp": origin.timestamp,
                "packet_index": origin.packet_index,
            })
            break
        frame = data[offset : offset + total]
        message_type = struct.unpack_from("<I", frame, 4)[0]
        payload = frame[8:]
        classification = None
        if message_type == TYPE_PLAINTEXT and payload[:4] in (
            b"PLH1", b"PLC1", b"PLA1", b"PLK1"
        ):
            classification = payload[:4].decode("ascii")
        events.append({
            "status": "complete",
            "stream_offset": offset,
            "frame_length": total,
            "body_length": body_length,
            "message_type": message_type,
            "classification_hint": classification,
            "timestamp": origin.timestamp,
            "packet_index": origin.packet_index,
            "frame": frame,
        })
        offset += total
    return events


def parse_endpoint(value: str) -> Endpoint:
    """Parse a numeric IP:port override without resolving hostnames."""
    try:
        if value.startswith("["):
            close = value.index("]")
            address_text = value[1:close]
            if value[close + 1 : close + 2] != ":":
                raise ValueError
            port_text = value[close + 2 :]
        else:
            address_text, port_text = value.rsplit(":", 1)
        address = str(ipaddress.ip_address(address_text))
        port = int(port_text, 10)
        if port < 0 or port > 65535:
            raise ValueError
    except (ValueError, IndexError) as exc:
        raise ProtocolError(
            "client endpoint must be numeric IP:port (IPv6 uses [address]:port)"
        ) from exc
    return Endpoint(address, port)


def _validated_direction_evidence(event: dict[str, Any]) -> str | None:
    if event.get("status") != "complete" or event.get("message_type") != TYPE_PLAINTEXT:
        return None
    frame = event["frame"]
    payload = frame[8:]
    magic = payload[:4]
    try:
        if magic == b"PLH1":
            parse_plh1(payload)
            return "client"
        if magic == b"PLC1":
            parse_plc1(payload)
            return "server"
        if magic == b"PLA1":
            parse_pla1(payload)
            return "client"
    except ProtocolError:
        return None
    return None


def analyze_capture(
    data: bytes,
    *,
    client_endpoints: Iterable[Endpoint] = (),
    psk: bytes | None = None,
    use_default_psk: bool = False,
    aes_key: bytes | None = None,
    envelope_hmac_key: bytes | None = None,
    decode_lz4: bool = True,
    include_all_tcp: bool = False,
) -> dict[str, Any]:
    """Ingest a capture and return per-flow protocol metadata."""
    capture_format, packets = parse_capture(data)
    flow_segments: dict[tuple[Endpoint, Endpoint], dict[Endpoint, list[TCPSegment]]] = {}
    tcp_packet_count = 0
    for packet in packets:
        segment = _tcp_from_packet(packet)
        if segment is None:
            continue
        tcp_packet_count += 1
        key = _flow_key(segment.source, segment.destination)
        directions = flow_segments.setdefault(key, {key[0]: [], key[1]: []})
        if segment.payload:
            directions[segment.source].append(segment)

    overrides = set(client_endpoints)
    flows: list[dict[str, Any]] = []
    for key in sorted(flow_segments, key=lambda pair: (_endpoint_key(pair[0]), _endpoint_key(pair[1]))):
        directions = flow_segments[key]
        assembled = {
            endpoint: reassemble_tcp_direction(directions[endpoint]) for endpoint in key
        }
        extracted = {
            endpoint: _extract_frames(assembled[endpoint]) for endpoint in key
        }
        candidate = any(
            value.data[:4] and len(value.data) >= 4
            and struct.unpack_from("<I", value.data, 0)[0] & FRAME_PREFIX_MASK == FRAME_PREFIX
            for value in assembled.values()
        )
        matching_overrides = [endpoint for endpoint in key if endpoint in overrides]
        if not (candidate or include_all_tcp or matching_overrides):
            continue
        flow_id = f"flow-{len(flows) + 1}"
        flow: dict[str, Any] = {
            "id": flow_id,
            "endpoint_a": str(key[0]),
            "endpoint_b": str(key[1]),
            "four_tuple": {
                "a_address": key[0].address,
                "a_port": key[0].port,
                "b_address": key[1].address,
                "b_port": key[1].port,
            },
            "status": "parsed",
            "direction_basis": "unknown",
            "client_endpoint": None,
            "server_endpoint": None,
            "tcp": {
                str(endpoint): {
                    "segment_count": assembled[endpoint].segment_count,
                    "stream_length": len(assembled[endpoint].data),
                    "duplicate_segments": assembled[endpoint].duplicate_segments,
                    "retransmitted_bytes": assembled[endpoint].retransmitted_bytes,
                    "error": assembled[endpoint].error,
                }
                for endpoint in key
            },
            "timeline": [],
        }
        reassembly_errors = [value.error for value in assembled.values() if value.error]
        if reassembly_errors:
            flow["status"] = "rejected/malformed"
            flow["error"] = "; ".join(reassembly_errors)
            flows.append(flow)
            continue

        inferred: set[Endpoint] = set()
        for source in key:
            destination = key[1] if source == key[0] else key[0]
            for event in extracted[source]:
                role = _validated_direction_evidence(event)
                if role == "client":
                    inferred.add(source)
                elif role == "server":
                    inferred.add(destination)
        if len(matching_overrides) > 1:
            flow["status"] = "rejected/malformed"
            flow["error"] = "both flow endpoints were supplied as client overrides"
            flows.append(flow)
            continue
        override = matching_overrides[0] if matching_overrides else None
        if len(inferred) > 1:
            flow["status"] = "rejected/malformed"
            flow["error"] = "contradictory PLH1/PLC1/PLA1 direction evidence"
            flows.append(flow)
            continue
        inferred_client = next(iter(inferred)) if inferred else None
        if override is not None and inferred_client is not None and override != inferred_client:
            flow["status"] = "rejected/malformed"
            flow["error"] = "analyst direction override conflicts with validated protocol evidence"
            flows.append(flow)
            continue
        client = override or inferred_client
        if client is not None:
            server = key[1] if client == key[0] else key[0]
            flow["client_endpoint"] = str(client)
            flow["server_endpoint"] = str(server)
            flow["direction_basis"] = "analyst override" if override else "protocol evidence"
            context = HandshakeContext()
            decoders = {
                client: StreamDecoder(
                    direction=DIRECTION_CLIENT_TO_SERVER,
                    handshake_context=context,
                    psk=psk,
                    use_default_psk=use_default_psk,
                    aes_key=aes_key,
                    envelope_hmac_key=envelope_hmac_key,
                    decode_lz4=decode_lz4,
                ),
                server: StreamDecoder(
                    direction=DIRECTION_SERVER_TO_CLIENT,
                    handshake_context=context,
                    psk=psk,
                    use_default_psk=use_default_psk,
                    aes_key=aes_key,
                    envelope_hmac_key=envelope_hmac_key,
                    decode_lz4=decode_lz4,
                ),
            }
        else:
            decoders = {
                endpoint: StreamDecoder(
                    psk=psk,
                    use_default_psk=use_default_psk,
                    aes_key=aes_key,
                    envelope_hmac_key=envelope_hmac_key,
                    decode_lz4=decode_lz4,
                )
                for endpoint in key
            }

        # TCP order is authoritative within each direction. A global timestamp
        # sort can feed a chunk to the decoder before its PLK1 header when a
        # later-sequence segment was captured first. Only compare current heads.
        ordered: list[tuple[Endpoint, dict[str, Any]]] = []
        positions = {source: 0 for source in key}
        while True:
            heads = [
                (source, extracted[source][positions[source]])
                for source in key if positions[source] < len(extracted[source])
            ]
            if not heads:
                break
            source, event = min(heads, key=lambda pair: (
                pair[1]["timestamp"] is None,
                pair[1]["timestamp"] or Fraction(0),
                pair[1]["packet_index"],
            ))
            ordered.append((source, event))
            positions[source] += 1
        for source, event in ordered:
            destination = key[1] if source == key[0] else key[0]
            if client is None:
                direction = f"{source} -> {destination} (role unknown)"
            else:
                direction = (
                    DIRECTION_CLIENT_TO_SERVER
                    if source == client else DIRECTION_SERVER_TO_CLIENT
                )
            row = {item: value for item, value in event.items() if item != "frame"}
            row["source"] = str(source)
            row["destination"] = str(destination)
            row["direction"] = direction
            if event["status"] == "complete":
                decoded = decoders[source].decode(event["frame"])
                if decoded["status"] != "parsed":
                    row["status"] = "rejected/malformed"
                    row["error"] = decoded["error"]
                    flow["status"] = "rejected/malformed"
                    flow["error"] = decoded["error"]
                    flow["timeline"].append(row)
                    break
                metadata = decoded["frames"][0]
                row["decoder"] = metadata
                row["classification"] = (
                    metadata.get("handshake", {}).get("kind")
                    or metadata.get("plk1_header", {}).get("kind")
                    or ("type-0x16-envelope" if "envelope" in metadata else "unclassified")
                )
            elif event["status"] == "incomplete":
                flow["status"] = "partial"
            else:
                flow["status"] = "rejected/malformed"
                flow["error"] = event["reason"]
                flow["timeline"].append(row)
                break
            flow["timeline"].append(row)
        flows.append(flow)

    return {
        "status": "parsed",
        "capture_format": capture_format,
        "packet_count": len(packets),
        "tcp_packet_count": tcp_packet_count,
        "tcp_flow_count": len(flow_segments),
        "included_flow_count": len(flows),
        "flows": flows,
    }


def _format_timestamp(value: Fraction | None) -> str:
    if value is None:
        return "timestamp-unknown"
    seconds = value.numerator // value.denominator
    fraction = value - seconds
    nanoseconds = (fraction.numerator * 1_000_000_000) // fraction.denominator
    try:
        stamp = datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"unix-seconds={value.numerator}/{value.denominator} (outside calendar range)"
    return f"{stamp}.{nanoseconds:09d}Z"


def format_timeline(report: dict[str, Any]) -> str:
    """Render concise text without payload bodies, authentication tags, or keys."""
    lines = [
        f"capture={report['capture_format']} packets={report['packet_count']} "
        f"tcp_packets={report['tcp_packet_count']} tcp_flows={report['tcp_flow_count']} "
        f"included_flows={report['included_flow_count']}"
    ]
    for flow in report["flows"]:
        role = (
            f"client={flow['client_endpoint']} server={flow['server_endpoint']}"
            if flow["client_endpoint"] else "roles=unknown"
        )
        tcp_rows = list(flow["tcp"].values())
        tcp_summary = (
            f"segments={sum(row['segment_count'] for row in tcp_rows)} "
            f"duplicates={sum(row['duplicate_segments'] for row in tcp_rows)} "
            f"retransmitted_bytes={sum(row['retransmitted_bytes'] for row in tcp_rows)}"
        )
        lines.append(
            f"{flow['id']} {flow['endpoint_a']} <-> {flow['endpoint_b']} "
            f"status={flow['status']} {role} basis={flow['direction_basis']} {tcp_summary}"
        )
        for row in flow["timeline"]:
            stamp = _format_timestamp(row["timestamp"])
            if row["status"] == "incomplete":
                declared = (
                    f" declared_body={row['declared_body_length']} "
                    f"declared_frame={row['declared_frame_length']}"
                    if "declared_body_length" in row else ""
                )
                lines.append(
                    f"  {stamp} {row['direction']} incomplete offset={row['stream_offset']}"
                    f" available={row['available_bytes']}{declared} reason={row['reason']}"
                )
                continue
            if row["status"] != "complete":
                lines.append(
                    f"  {stamp} {row['direction']} rejected offset={row['stream_offset']} "
                    f"reason={row.get('error', row.get('reason'))}"
                )
                continue
            decoded = row["decoder"]
            summary = (
                f"len={row['frame_length']} body={row['body_length']} "
                f"type=0x{row['message_type']:08X} class={row['classification']}"
            )
            handshake = decoded.get("handshake")
            if handshake and handshake["kind"] == "PLA1":
                summary += f" verification={handshake['verification_status']}"
            header = decoded.get("plk1_header")
            if header:
                summary += (
                    f" plk1_version={header['wire_version']} total={header['total_size']} "
                    f"original={header['orig_size']} lz4={str(header['lz4_enabled']).lower()}"
                )
            chunk = decoded.get("plk1_chunk")
            if chunk:
                summary += (
                    f" plk1_chunk={chunk['sequence']} chunk_len={chunk['chunk_length']} "
                    f"progress={chunk['assembled_wire_size']}/{chunk['expected_wire_size']} "
                    f"state={chunk['state']}"
                )
                if "final" in chunk:
                    summary += f" final={chunk['final']['status']}"
            envelope = decoded.get("envelope")
            if envelope:
                summary += (
                    f" envelope_version={envelope['version']} "
                    f"ciphertext={envelope['ciphertext_length']} "
                    f"hmac={envelope['hmac_status']} decrypt={envelope['decryption_status']}"
                )
                if "inner_type" in envelope:
                    summary += f" inner_type={envelope['inner_type']}"
            lines.append(f"  {stamp} {row['direction']} {summary}")
        if flow.get("error") and not flow["timeline"]:
            lines.append(f"  rejected: {flow['error']}")
    return "\n".join(lines)
