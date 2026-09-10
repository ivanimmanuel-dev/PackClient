#!/usr/bin/env python3
"""Verified, atomic export of PackClient payloads recovered from captures."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Iterable

from tools.packclient_pcap import PLK1Artifact, PV10Artifact
from tools.packclient_proto import ProtocolError


KNOWN_CORE_SHA256 = "4de6ef8647fb4b599966a233740cb0514d1e71b8019a1a1792ed7e1e514edf1c"


def inspect_pe(data: bytes) -> dict[str, Any]:
    """Return bounded PE metadata without loading or executing the image."""
    result: dict[str, Any] = {"is_pe": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return result
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > len(data) - 24:
        return result
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return result
    machine, sections = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe_offset + 20)
    optional_offset = pe_offset + 24
    if optional_size < 2 or optional_offset + optional_size > len(data):
        return result
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    result.update(
        {
            "is_pe": True,
            "format": {0x10B: "PE32", 0x20B: "PE32+"}.get(
                optional_magic, f"unknown-0x{optional_magic:04x}"
            ),
            "machine": f"0x{machine:04x}",
            "sections": sections,
            "dll": bool(characteristics & 0x2000),
        }
    )
    if optional_size >= 60:
        result["entry_point_rva"] = struct.unpack_from("<I", data, optional_offset + 16)[0]
        result["image_size"] = struct.unpack_from("<I", data, optional_offset + 56)[0]
    return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes, *, replace: bool = False) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not replace:
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise ProtocolError(f"cannot verify existing output {path.name}: {exc}") from exc
        if hmac.compare_digest(_sha256(existing), _sha256(data)):
            return "existing-verified"
        raise ProtocolError(f"refusing to overwrite different existing file {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return "written"


def _plk1_observation(artifact: PLK1Artifact) -> dict[str, Any]:
    return {
        "flow": artifact.flow_id,
        "source": artifact.source,
        "destination": artifact.destination,
        "direction": artifact.direction,
        "chunk_count": artifact.chunk_count,
        "frames": list(artifact.frames),
    }


def _pv10_observation(artifact: PV10Artifact) -> dict[str, Any]:
    return {
        "flow": artifact.flow_id,
        "source": artifact.source,
        "destination": artifact.destination,
        "direction": artifact.direction,
        "frame": artifact.frame,
    }


def export_capture_artifacts(
    *,
    capture: bytes,
    capture_format: str,
    output_dir: Path,
    plk1_artifacts: Iterable[PLK1Artifact] = (),
    pv10_artifacts: Iterable[PV10Artifact] = (),
    export_plk1: bool = False,
    export_pv10: bool = False,
) -> dict[str, Any]:
    """Export verified artifacts and an atomic, path-independent manifest."""
    manifest: dict[str, Any] = {
        "schema": "packclient-capture-artifacts-v1",
        "capture": {
            "format": capture_format,
            "size": len(capture),
            "sha256": _sha256(capture),
        },
        "plk1": [],
        "pv10": [],
    }
    plk1_groups: dict[str, list[PLK1Artifact]] = {}
    for artifact in plk1_artifacts:
        digest = _sha256(artifact.plaintext)
        if digest != artifact.final.get("sha256"):
            raise ProtocolError("PLK1 artifact changed after verification")
        if len(artifact.plaintext) != artifact.final.get("plaintext_size"):
            raise ProtocolError("PLK1 artifact size changed after verification")
        plk1_groups.setdefault(digest, []).append(artifact)

    for digest, artifacts in sorted(plk1_groups.items()):
        first = artifacts[0]
        pe = inspect_pe(first.plaintext)
        known_core = digest == KNOWN_CORE_SHA256 and pe.get("is_pe") is True
        filename = (
            f"PackClientCore-{digest[:12]}.dll"
            if known_core
            else f"plk1-{digest[:12]}.bin"
        )
        relative = Path("plk1") / filename
        status = "not-requested"
        if export_plk1:
            status = _atomic_write(output_dir / relative, first.plaintext)
        manifest["plk1"].append(
            {
                "output_file": relative.as_posix() if export_plk1 else None,
                "write_status": status,
                "identity": "PackClientCore.dll" if known_core else "unclassified",
                "size": len(first.plaintext),
                "sha256": digest,
                "wire_size": first.final["wire_size"],
                "wire_sha256": first.final["wire_sha256"],
                "header": first.header,
                "pe": pe,
                "observations": [_plk1_observation(item) for item in artifacts],
            }
        )

    pv10_groups: dict[str, list[PV10Artifact]] = {}
    for artifact in pv10_artifacts:
        digest = _sha256(artifact.jpeg)
        if digest != artifact.metadata.get("jpeg_sha256"):
            raise ProtocolError("PV10 artifact changed after verification")
        pv10_groups.setdefault(digest, []).append(artifact)

    for digest, artifacts in sorted(pv10_groups.items()):
        first = artifacts[0]
        relative = Path("pv10") / f"pv10-{digest[:12]}.jpg"
        status = "not-requested"
        if export_pv10:
            status = _atomic_write(output_dir / relative, first.jpeg)
        manifest["pv10"].append(
            {
                "output_file": relative.as_posix() if export_pv10 else None,
                "write_status": status,
                "size": len(first.jpeg),
                "sha256": digest,
                "jfif": first.metadata["jfif"],
                "observations": [_pv10_observation(item) for item in artifacts],
            }
        )

    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=False).encode("utf-8") + b"\n"
    )
    _atomic_write(output_dir / "manifest.json", manifest_bytes, replace=True)
    return manifest
