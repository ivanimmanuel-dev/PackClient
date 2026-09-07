#!/usr/bin/env python3
"""PackClientLauncher transport, authentication, envelope, and PLK1 decoder."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import struct
from dataclasses import dataclass
from typing import Any


FRAME_PREFIX = 0x5A400000
FRAME_PREFIX_MASK = 0xFFC00000
BODY_LENGTH_MASK = 0x003FFFFF
MAX_BODY_LENGTH = BODY_LENGTH_MASK
TYPE_PLAINTEXT = 0x15
TYPE_ENCRYPTED = 0x16
DIRECTION_CLIENT_TO_SERVER = "client-to-server"
DIRECTION_SERVER_TO_CLIENT = "server-to-client"
TRANSPORT_DIRECTIONS = frozenset(
    (DIRECTION_CLIENT_TO_SERVER, DIRECTION_SERVER_TO_CLIENT)
)
DEFAULT_LAUNCHER_PSK = b"pack-launch-dev-psk"
PLK1_HEADER_SIZE = 0x38
MAX_PLK1_SIZE = 0x08000000


class ProtocolError(ValueError):
    """A supplied stream violates the reconstructed protocol contract."""

    def __init__(self, message: str, *, offset: int | None = None):
        super().__init__(message)
        self.offset = offset


def _hex_u32(value: int) -> str:
    return f"0x{value:08X}"


def _require_length(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise ProtocolError(f"{name} must be exactly {expected} bytes (got {len(value)})")


def _validate_32_byte_key(name: str, key: bytes | None) -> None:
    if key is not None and len(key) != 32:
        raise ProtocolError(f"{name} must be exactly 32 bytes")


def validate_body_length(body_length: int) -> None:
    if body_length == 0:
        raise ProtocolError("outer body length is zero")
    if body_length > MAX_BODY_LENGTH:
        raise ProtocolError(
            f"outer body length exceeds 22-bit maximum 0x{MAX_BODY_LENGTH:X}"
        )
    if body_length < 4:
        raise ProtocolError("outer body is too short for its LE32 message type")


@dataclass(frozen=True)
class OuterFrame:
    offset: int
    frame_word: int
    body_length: int
    message_type: int
    payload: bytes

    @property
    def end_offset(self) -> int:
        return self.offset + 4 + self.body_length


def parse_outer_frame(data: bytes, offset: int = 0) -> tuple[OuterFrame, int]:
    """Parse one complete outer frame at *offset* and return it plus next offset."""
    if offset < 0 or offset > len(data):
        raise ProtocolError("outer frame offset is outside the stream", offset=offset)
    if len(data) - offset < 4:
        raise ProtocolError("truncated outer frame word", offset=offset)
    frame_word = struct.unpack_from("<I", data, offset)[0]
    if frame_word & FRAME_PREFIX_MASK != FRAME_PREFIX:
        raise ProtocolError(
            f"wrong outer frame prefix in {_hex_u32(frame_word)}", offset=offset
        )
    body_length = frame_word & BODY_LENGTH_MASK
    try:
        validate_body_length(body_length)
    except ProtocolError as exc:
        exc.offset = offset
        raise
    body_offset = offset + 4
    available = len(data) - body_offset
    if available < body_length:
        raise ProtocolError(
            f"truncated outer body: need {body_length} bytes, have {available}",
            offset=offset,
        )
    message_type = struct.unpack_from("<I", data, body_offset)[0]
    payload = data[body_offset + 4 : body_offset + body_length]
    frame = OuterFrame(offset, frame_word, body_length, message_type, payload)
    return frame, frame.end_offset


def frame_bytes(message_type: int, payload: bytes) -> bytes:
    """Build deterministic synthetic framing for tests."""
    body_length = 4 + len(payload)
    validate_body_length(body_length)
    return struct.pack("<II", FRAME_PREFIX | body_length, message_type) + payload


def parse_plh1(payload: bytes) -> dict[str, Any]:
    _require_length("PLH1", payload, 32)
    magic, version, field_06, field_08, field_0c, tick, pid, reserved = struct.unpack(
        "<4sHHIIQII", payload
    )
    if magic != b"PLH1":
        raise ProtocolError("PLH1 magic mismatch")
    if version != 1 or field_06 != 0x20 or field_08 != 0 or field_0c != 1 or reserved != 0:
        raise ProtocolError("PLH1 fixed field validation failed")
    return {
        "kind": "PLH1",
        "status": "parsed",
        "version": version,
        "field_06": field_06,
        "field_08": field_08,
        "field_0c": field_0c,
        "tick_count_64": tick,
        "process_id": pid,
        "reserved": reserved,
    }


def parse_plc1(payload: bytes) -> dict[str, Any]:
    _require_length("PLC1", payload, 24)
    magic, version, field_06, challenge = struct.unpack("<4sHH16s", payload)
    if magic != b"PLC1":
        raise ProtocolError("PLC1 magic mismatch")
    if version != 1:
        raise ProtocolError("PLC1 version must be 1")
    return {
        "kind": "PLC1",
        "status": "parsed",
        "version": version,
        "field_06": field_06,
        "challenge_hex": challenge.hex(),
    }


def parse_pla1(payload: bytes) -> dict[str, Any]:
    _require_length("PLA1", payload, 40)
    magic, version, reserved, authenticator = struct.unpack("<4sHH32s", payload)
    if magic != b"PLA1":
        raise ProtocolError("PLA1 magic mismatch")
    if version != 1 or reserved != 0:
        raise ProtocolError("PLA1 fixed field validation failed")
    return {
        "kind": "PLA1",
        "status": "parsed",
        "version": version,
        "reserved": reserved,
        "authenticator_hex": authenticator.hex(),
    }


def pla1_transcript(plh1: bytes, plc1: bytes) -> bytes:
    """Reconstruct the exact 42-byte PLA1 HMAC transcript."""
    parse_plh1(plh1)
    parse_plc1(plc1)
    transcript = (
        plh1[0x10:0x20]
        + plc1[0x08:0x18]
        + plh1[0x0C:0x10]
        + plh1[0x06:0x08]
        + b"PLK1"
    )
    if len(transcript) != 42:
        raise AssertionError("internal PLA1 transcript size error")
    return transcript


def select_psk(psk: bytes | None, *, use_default_psk: bool = False) -> bytes | None:
    """Return a supplied PSK, or the Launcher fallback only when requested."""
    if psk is not None:
        if len(psk) == 0:
            raise ProtocolError("an explicitly supplied PSK must be nonempty")
        return psk
    return DEFAULT_LAUNCHER_PSK if use_default_psk else None


def verify_pla1(
    plh1: bytes,
    plc1: bytes,
    pla1: bytes,
    *,
    psk: bytes | None = None,
    use_default_psk: bool = False,
) -> str:
    parsed = parse_pla1(pla1)
    selected = select_psk(psk, use_default_psk=use_default_psk)
    if selected is None:
        return "unverifiable: PSK absent"
    expected = hmac.new(selected, pla1_transcript(plh1, plc1), hashlib.sha256).digest()
    supplied = bytes.fromhex(parsed["authenticator_hex"])
    if not hmac.compare_digest(expected, supplied):
        raise ProtocolError("PLA1 HMAC-SHA-256 verification failed")
    return "verified"


@dataclass
class HandshakeContext:
    """Handshake state shared by separately parsed directional streams."""

    plh1: bytes | None = None
    plc1: bytes | None = None

    def record_plh1(self, payload: bytes) -> None:
        parse_plh1(payload)
        self.plh1 = payload

    def record_plc1(self, payload: bytes) -> None:
        parse_plc1(payload)
        self.plc1 = payload

    def verify_pla1(self, payload: bytes, *, psk: bytes | None) -> str:
        parse_pla1(payload)
        missing = []
        if self.plh1 is None:
            missing.append("PLH1")
        if self.plc1 is None:
            missing.append("PLC1")
        if missing:
            return f"unverifiable: {'/'.join(missing)} context absent"
        if psk is None:
            return "unverifiable: PSK absent"
        return verify_pla1(self.plh1, self.plc1, payload, psk=psk)

    def snapshot(self) -> dict[str, str]:
        return {
            "PLH1": "available" if self.plh1 is not None else "absent",
            "PLC1": "available" if self.plc1 is not None else "absent",
        }


@dataclass(frozen=True)
class EnvelopeResult:
    metadata: dict[str, Any]
    plaintext_payload: bytes | None


def parse_envelope(
    envelope: bytes,
    *,
    aes_key: bytes | None = None,
    hmac_key: bytes | None = None,
) -> EnvelopeResult:
    """Parse, optionally authenticate, and optionally decrypt a type-0x16 envelope."""
    _validate_32_byte_key("AES-256 key", aes_key)
    _validate_32_byte_key("envelope HMAC key", hmac_key)
    if len(envelope) < 0x35:
        raise ProtocolError("type 0x16 envelope is shorter than 0x35 bytes")
    version = envelope[0]
    if version != 1:
        raise ProtocolError("type 0x16 envelope version must be 1")
    iv = envelope[1:17]
    ciphertext_length = struct.unpack_from(">I", envelope, 17)[0]
    expected_length = ciphertext_length + 0x35
    if len(envelope) != expected_length:
        raise ProtocolError(
            f"type 0x16 envelope length mismatch: declared {ciphertext_length}, "
            f"total must be {expected_length}, got {len(envelope)}"
        )
    if ciphertext_length == 0:
        raise ProtocolError("type 0x16 ciphertext is empty")
    if ciphertext_length % 16 != 0:
        raise ProtocolError("type 0x16 ciphertext length is not AES block-aligned")
    ciphertext_end = 0x15 + ciphertext_length
    ciphertext = envelope[0x15:ciphertext_end]
    supplied_tag = envelope[ciphertext_end:]
    metadata: dict[str, Any] = {
        "status": "parsed",
        "version": version,
        "iv_hex": iv.hex(),
        "ciphertext_length": ciphertext_length,
        "tag_hex": supplied_tag.hex(),
        "hmac_status": "unverifiable: envelope HMAC key absent",
        "decryption_status": "unavailable: AES key absent",
    }
    authenticated = False
    if hmac_key is not None:
        expected_tag = hmac.new(hmac_key, envelope[:ciphertext_end], hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, supplied_tag):
            raise ProtocolError("type 0x16 envelope HMAC-SHA-256 verification failed")
        metadata["hmac_status"] = "verified"
        authenticated = True
    if aes_key is None:
        return EnvelopeResult(metadata, None)
    if not authenticated:
        metadata["decryption_status"] = "unavailable: envelope HMAC not verified"
        return EnvelopeResult(metadata, None)
    plaintext = aes256_cbc_decrypt_padded(aes_key, iv, ciphertext)
    if len(plaintext) < 4:
        raise ProtocolError("decrypted type 0x16 plaintext is shorter than an inner type")
    inner_type = struct.unpack_from("<I", plaintext, 0)[0]
    if inner_type != TYPE_PLAINTEXT:
        raise ProtocolError(
            f"decrypted type 0x16 inner type is {_hex_u32(inner_type)}, not 0x00000015"
        )
    metadata["decryption_status"] = "verified"
    metadata["inner_type"] = _hex_u32(inner_type)
    metadata["plaintext_payload_length"] = len(plaintext) - 4
    return EnvelopeResult(metadata, plaintext[4:])


def parse_plk1_header(payload: bytes) -> dict[str, Any]:
    _require_length("PLK1 header", payload, PLK1_HEADER_SIZE)
    magic, wire_version, lz4_flag, reserved, total_size, orig_size, digest = struct.unpack(
        "<4sHBBQQ32s", payload
    )
    if magic != b"PLK1":
        raise ProtocolError("PLK1 magic mismatch")
    if wire_version not in (1, 2):
        raise ProtocolError("PLK1 wire version must be 1 or 2")
    if total_size == 0 or total_size > MAX_PLK1_SIZE or total_size > 0xFFFFFFFF:
        raise ProtocolError("PLK1 total_size is outside 1..0x08000000")
    lz4_enabled = wire_version == 2 and lz4_flag != 0
    if wire_version == 1:
        plaintext_size = total_size
    else:
        if orig_size == 0 or orig_size > MAX_PLK1_SIZE or orig_size > 0xFFFFFFFF:
            raise ProtocolError("PLK1 orig_size is outside 1..0x08000000")
        plaintext_size = orig_size
    return {
        "kind": "PLK1",
        "status": "parsed",
        "wire_version": wire_version,
        "lz4_flag": lz4_flag,
        "lz4_enabled": lz4_enabled,
        "reserved": reserved,
        "total_size": total_size,
        "orig_size": orig_size,
        "expected_plaintext_size": plaintext_size,
        "expected_sha256": digest.hex(),
    }


def parse_plk1_chunk(payload: bytes) -> tuple[int, bytes]:
    if len(payload) < 8:
        raise ProtocolError("PLK1 chunk is shorter than 8 bytes")
    sequence, chunk_length = struct.unpack_from("<II", payload)
    if chunk_length == 0:
        raise ProtocolError("PLK1 chunk length is zero")
    if len(payload) != 8 + chunk_length:
        raise ProtocolError(
            f"PLK1 chunk length mismatch: declared {chunk_length}, got {len(payload) - 8}"
        )
    return sequence, payload[8:]


def _lz4_block_decode(data: bytes, expected_size: int) -> bytes:
    try:
        block = importlib.import_module("lz4.block")
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "optional raw-block LZ4 decoding requires the 'lz4' package"
        ) from exc
    try:
        decoded = block.decompress(data, uncompressed_size=expected_size)
    except Exception as exc:  # dependency-specific decode exception types vary
        raise ProtocolError(f"PLK1 raw-block LZ4 decode failed: {exc}") from exc
    if len(decoded) != expected_size:
        raise ProtocolError(
            f"PLK1 LZ4 output size mismatch: expected {expected_size}, got {len(decoded)}"
        )
    return decoded


class PLK1Reassembler:
    """Strict, single-transfer PLK1 chunk reassembler."""

    def __init__(self, header_payload: bytes, *, decode_lz4: bool = True):
        self.header = parse_plk1_header(header_payload)
        self.decode_lz4 = decode_lz4
        self.expected_sequence = 0
        self._wire = bytearray()
        self.complete = False
        self.plaintext: bytes | None = None
        self.result: dict[str, Any] | None = None

    def add_chunk(self, payload: bytes) -> dict[str, Any]:
        if self.complete:
            raise ProtocolError("PLK1 chunk supplied after reassembly completed")
        sequence, chunk = parse_plk1_chunk(payload)
        if sequence != self.expected_sequence:
            raise ProtocolError(
                f"PLK1 sequence mismatch: expected {self.expected_sequence}, got {sequence}"
            )
        new_size = len(self._wire) + len(chunk)
        if new_size > self.header["total_size"]:
            raise ProtocolError("PLK1 chunks exceed declared total_size")
        self._wire.extend(chunk)
        self.expected_sequence += 1
        state: dict[str, Any] = {
            "sequence": sequence,
            "chunk_length": len(chunk),
            "assembled_wire_size": len(self._wire),
            "expected_wire_size": self.header["total_size"],
            "state": "incomplete",
        }
        if len(self._wire) == self.header["total_size"]:
            self.result = self._finish()
            self.complete = True
            state["state"] = "complete"
            state["final"] = self.result
        return state

    def snapshot(self) -> dict[str, Any]:
        return {
            "header": self.header,
            "expected_sequence": self.expected_sequence,
            "assembled_wire_size": len(self._wire),
            "state": "complete" if self.complete else "incomplete",
            "final": self.result,
        }

    def _finish(self) -> dict[str, Any]:
        wire = bytes(self._wire)
        expected_size = self.header["expected_plaintext_size"]
        if self.header["lz4_enabled"]:
            if not self.decode_lz4:
                return {
                    "status": "unverifiable: LZ4 decoding disabled",
                    "plaintext_size_status": "unverifiable",
                    "sha256_status": "unverifiable",
                }
            try:
                plaintext = _lz4_block_decode(wire, expected_size)
            except ModuleNotFoundError:
                return {
                    "status": "unverifiable: optional LZ4 dependency absent",
                    "plaintext_size_status": "unverifiable",
                    "sha256_status": "unverifiable",
                }
        else:
            plaintext = wire
        if len(plaintext) != expected_size:
            raise ProtocolError(
                f"PLK1 plaintext size mismatch: expected {expected_size}, got {len(plaintext)}"
            )
        digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(digest, self.header["expected_sha256"]):
            raise ProtocolError("PLK1 final SHA-256 mismatch")
        self.plaintext = plaintext
        return {
            "status": "verified",
            "plaintext_size": len(plaintext),
            "plaintext_size_status": "verified",
            "sha256": digest,
            "sha256_status": "verified",
        }


class StreamDecoder:
    """Stateful decoder for one ordered transport byte stream."""

    def __init__(
        self,
        *,
        direction: str | None = None,
        handshake_context: HandshakeContext | None = None,
        psk: bytes | None = None,
        use_default_psk: bool = False,
        aes_key: bytes | None = None,
        envelope_hmac_key: bytes | None = None,
        decode_lz4: bool = True,
    ):
        if handshake_context is not None and direction not in TRANSPORT_DIRECTIONS:
            raise ProtocolError(
                "a shared handshake context requires explicit direction "
                "'client-to-server' or 'server-to-client'"
            )
        self.direction = direction
        self.handshake_context = handshake_context or HandshakeContext()
        self.psk = select_psk(psk, use_default_psk=use_default_psk)
        _validate_32_byte_key("AES-256 key", aes_key)
        _validate_32_byte_key("envelope HMAC key", envelope_hmac_key)
        self.aes_key = aes_key
        self.envelope_hmac_key = envelope_hmac_key
        self.decode_lz4 = decode_lz4
        self._reassembler: PLK1Reassembler | None = None
        self._reassemblies: list[dict[str, Any]] = []

    def decode(self, data: bytes) -> dict[str, Any]:
        frames: list[dict[str, Any]] = []
        offset = 0
        try:
            while offset < len(data):
                frame, next_offset = parse_outer_frame(data, offset)
                frames.append(self._decode_frame(frame))
                offset = next_offset
        except ProtocolError as exc:
            return {
                "status": "rejected/malformed",
                "error": str(exc),
                "error_offset": exc.offset if exc.offset is not None else offset,
                "stream_length": len(data),
                "frames": frames,
                "handshake_context": self.handshake_context.snapshot(),
                "reassemblies": self._current_reassemblies(),
            }
        return {
            "status": "parsed",
            "stream_length": len(data),
            "frame_count": len(frames),
            "frames": frames,
            "handshake_context": self.handshake_context.snapshot(),
            "reassemblies": self._current_reassemblies(),
        }

    def _current_reassemblies(self) -> list[dict[str, Any]]:
        rows = list(self._reassemblies)
        if self._reassembler is not None:
            rows.append(self._reassembler.snapshot())
        return rows

    def _decode_frame(self, frame: OuterFrame) -> dict[str, Any]:
        row: dict[str, Any] = {
            "offset": frame.offset,
            "end_offset": frame.end_offset,
            "direction": self.direction,
            "frame_word": _hex_u32(frame.frame_word),
            "body_length": frame.body_length,
            "message_type": _hex_u32(frame.message_type),
            "status": "parsed",
        }
        if frame.message_type == TYPE_PLAINTEXT:
            payload = frame.payload
            row["payload_status"] = "available: plaintext type 0x15"
        elif frame.message_type == TYPE_ENCRYPTED:
            result = parse_envelope(
                frame.payload,
                aes_key=self.aes_key,
                hmac_key=self.envelope_hmac_key,
            )
            row["envelope"] = result.metadata
            payload = result.plaintext_payload
            row["payload_status"] = (
                "available: authenticated/decrypted inner type 0x15"
                if payload is not None
                else "unverifiable/unavailable: envelope keys absent or incomplete"
            )
        else:
            raise ProtocolError(
                f"unsupported outer message type {_hex_u32(frame.message_type)}",
                offset=frame.offset,
            )
        if payload is not None:
            row["plaintext_payload_length"] = len(payload)
            self._decode_payload(payload, row)
        return row

    def _decode_payload(self, payload: bytes, row: dict[str, Any]) -> None:
        if self._reassembler is not None:
            chunk_state = self._reassembler.add_chunk(payload)
            row["plk1_chunk"] = chunk_state
            if self._reassembler.complete:
                self._reassemblies.append(self._reassembler.snapshot())
                self._reassembler = None
            return
        magic = payload[:4]
        if magic == b"PLH1":
            self._require_handshake_direction(DIRECTION_CLIENT_TO_SERVER, "PLH1")
            row["handshake"] = parse_plh1(payload)
            self.handshake_context.record_plh1(payload)
        elif magic == b"PLC1":
            self._require_handshake_direction(DIRECTION_SERVER_TO_CLIENT, "PLC1")
            row["handshake"] = parse_plc1(payload)
            self.handshake_context.record_plc1(payload)
        elif magic == b"PLA1":
            self._require_handshake_direction(DIRECTION_CLIENT_TO_SERVER, "PLA1")
            handshake = parse_pla1(payload)
            handshake["verification_status"] = self.handshake_context.verify_pla1(
                payload, psk=self.psk
            )
            row["handshake"] = handshake
        elif magic == b"PLK1":
            self._reassembler = PLK1Reassembler(payload, decode_lz4=self.decode_lz4)
            row["plk1_header"] = self._reassembler.header

    def _require_handshake_direction(self, expected: str, kind: str) -> None:
        if self.direction in TRANSPORT_DIRECTIONS and self.direction != expected:
            raise ProtocolError(f"{kind} is not valid in direction {self.direction}")


# Dependency-free AES-256 decryption used by the envelope decoder.
_SBOX = (
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
)
_INV_SBOX = tuple(_SBOX.index(value) for value in range(256))
_RCON = (0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36)


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _aes256_round_keys(key: bytes) -> list[bytes]:
    _validate_32_byte_key("AES-256 key", key)
    words = [list(key[index:index + 4]) for index in range(0, 32, 4)]
    for index in range(8, 60):
        temp = list(words[index - 1])
        if index % 8 == 0:
            temp = [_SBOX[value] for value in _rot_word(temp)]
            temp[0] ^= _RCON[index // 8]
        elif index % 8 == 4:
            temp = [_SBOX[value] for value in temp]
        words.append([a ^ b for a, b in zip(words[index - 8], temp)])
    return [bytes(sum(words[index:index + 4], [])) for index in range(0, 60, 4)]


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def _inv_shift_rows(state: list[int]) -> None:
    for row in range(1, 4):
        values = [state[row + 4 * column] for column in range(4)]
        values = values[-row:] + values[:-row]
        for column, value in enumerate(values):
            state[row + 4 * column] = value


def _inv_mix_columns(state: list[int]) -> None:
    for column in range(4):
        index = 4 * column
        a, b, c, d = state[index:index + 4]
        state[index:index + 4] = [
            _gf_mul(a, 14) ^ _gf_mul(b, 11) ^ _gf_mul(c, 13) ^ _gf_mul(d, 9),
            _gf_mul(a, 9) ^ _gf_mul(b, 14) ^ _gf_mul(c, 11) ^ _gf_mul(d, 13),
            _gf_mul(a, 13) ^ _gf_mul(b, 9) ^ _gf_mul(c, 14) ^ _gf_mul(d, 11),
            _gf_mul(a, 11) ^ _gf_mul(b, 13) ^ _gf_mul(c, 9) ^ _gf_mul(d, 14),
        ]


def _aes256_decrypt_block(key: bytes, block: bytes) -> bytes:
    _require_length("AES block", block, 16)
    round_keys = _aes256_round_keys(key)
    state = [value ^ round_keys[14][index] for index, value in enumerate(block)]
    for round_number in range(13, 0, -1):
        _inv_shift_rows(state)
        state[:] = [_INV_SBOX[value] for value in state]
        state[:] = [value ^ round_keys[round_number][index] for index, value in enumerate(state)]
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    state[:] = [_INV_SBOX[value] for value in state]
    return bytes(value ^ round_keys[0][index] for index, value in enumerate(state))


def aes256_cbc_decrypt_blocks(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt nonempty block-aligned AES-256-CBC data without unpadding."""
    _validate_32_byte_key("AES-256 key", key)
    _require_length("AES-CBC IV", iv, 16)
    if not ciphertext or len(ciphertext) % 16:
        raise ProtocolError("AES-CBC ciphertext must be nonempty and block-aligned")
    plaintext = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        decoded = _aes256_decrypt_block(key, block)
        plaintext.extend(a ^ b for a, b in zip(decoded, previous))
        previous = block
    return bytes(plaintext)


def aes256_cbc_decrypt_padded(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC decrypt followed by strict BCrypt-compatible PKCS#7 removal."""
    plaintext = aes256_cbc_decrypt_blocks(key, iv, ciphertext)
    padding_length = plaintext[-1]
    if padding_length < 1 or padding_length > 16:
        raise ProtocolError("AES-CBC plaintext has invalid block padding")
    if plaintext[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ProtocolError("AES-CBC plaintext has invalid block padding")
    return plaintext[:-padding_length]
