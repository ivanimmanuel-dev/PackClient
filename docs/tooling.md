# Passive analysis tools

The repository includes two offline Python command-line tools and a Wireshark Lua dissector for PackClient Launcher and Core traffic. They parse raw streams or captures without executing samples, opening sockets, resolving domains, or replaying traffic. The capture tool can also export verified PLK1 plaintext and validated `PV10` JPEGs with a provenance manifest.

Launcher wire details are documented in [Launcher protocol](launcher-protocol.md), Core messages and encryption in [Core analysis](core-analysis.md), and remaining boundaries in [Scope and limitations](limitations.md).

## Interfaces and requirements

| Interface | Input | Output | Requirements |
|---|---|---|---|
| [`packclient_decode.py`](../tools/packclient_decode.py) | Ordered raw byte stream from a file or standard input | JSON for Launcher/Core framing, handshake, envelopes, commands, PLK1 and `PV10` | Python 3.11–3.13; standard library |
| [`packclient_pcap_decode.py`](../tools/packclient_pcap_decode.py) | PCAP or PCAPNG from a file or standard input | Reassembled per-flow timeline; optional verified PLK1/`PV10` files and `manifest.json` | Python 3.11–3.13; standard library |
| [`packclient.lua`](../tools/wireshark/packclient.lua) | TCP data in a capture opened by Wireshark/TShark | Launcher/Core phase, handshake and PLK1 fields, type-`0x16` format, Core commands, `PV10`, and malformed-object diagnostics | Wireshark/TShark with Lua support |

[`packclient_proto.py`](../tools/packclient_proto.py) and [`packclient_pcap.py`](../tools/packclient_pcap.py) provide the shared decoding, while [`packclient_artifacts.py`](../tools/packclient_artifacts.py) performs bounded PE inspection and atomic artifact export. AES-256-CBC is implemented without third-party dependencies and checked against [NIST FIPS 197](https://doi.org/10.6028/NIST.FIPS.197) and [SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A) known-answer vectors. Optional PLK1 raw-block LZ4 decoding uses `lz4==4.4.5`:

```sh
python -m pip install -r requirements/lz4.txt
```

The raw CLI omits supplied keys and recovered plaintext bodies from its output. Its metadata can still contain protocol fields such as IVs, challenges and authentication tags. The capture timeline omits those byte fields as well as bodies and keys, but includes captured addresses and ports. Command-line keys may be visible in shell history or process listings; use the Python API when that matters.

## Minimal example

From the repository root, create a 32-byte PLH1 object and wrap it in plaintext outer type `0x15`:

```python
from pathlib import Path
import struct
from tools.packclient_proto import TYPE_PLAINTEXT, frame_bytes

hello = struct.pack("<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1, 123456, 4242, 0)
Path("example-stream.dat").write_bytes(frame_bytes(TYPE_PLAINTEXT, hello))
```

```sh
python -B tools/packclient_decode.py example-stream.dat --direction client-to-server
```

Expected output includes `status: parsed`, `stream_length: 40`, `frame_count: 1`, frame word `0x5A400024`, type `0x00000015`, object `PLH1`, and `process_id: 4242`.

[`synthetic_stream.py`](../tests/synthetic_stream.py) extends this with PLA1 HMAC, authenticated-envelope and PLK1 cases and is exercised through [`test_raw_cli.py`](../tests/test_raw_cli.py).

## Raw streams and handshake context

```sh
python -B tools/packclient_decode.py stream.dat
python -B tools/packclient_decode.py client-stream.dat --direction client-to-server
python -B tools/packclient_decode.py server-stream.dat --direction server-to-client
python -B tools/packclient_decode.py core-stream.dat --phase core
python -B tools/packclient_decode.py stream.dat --no-lz4
```

Use `-` instead of a filename for binary standard input. Exit code 0 means the stream parsed; inspect verification and reassembly fields for incomplete transfers or unauthenticated objects. Rejected or malformed input returns 2.

Raw streams default to `--phase launcher`. Select `--phase core` for a standalone Core stream or `--phase auto` when the data includes enough validated structure to infer the phase. A phase-ambiguous type-`0x16` envelope is rejected until the phase is selected explicitly.

Canonical directions enforce PLH1/PLA1 as client-to-server and PLC1 as server-to-client. A raw invocation does not reconstruct TCP or retain handshake state across separate invocations. For separate directional byte streams, share a `HandshakeContext`:

```python
from tools.packclient_proto import HandshakeContext, StreamDecoder

context = HandshakeContext()
client = StreamDecoder(direction="client-to-server", handshake_context=context,
                       psk=known_psk)
server = StreamDecoder(direction="server-to-client", handshake_context=context)
client.decode(client_hello_frames)
server.decode(server_challenge_frames)
result = client.decode(client_authentication_frames)
```

Missing PLC1 context produces `unverifiable: PLC1 context absent`; an incorrect challenge causes HMAC verification to fail. Use the capture CLI when both directions already exist in a supported capture.

## Passive capture decoding

```sh
python -B tools/packclient_pcap_decode.py capture.pcapng
python -B tools/packclient_pcap_decode.py capture.pcap --client-endpoint 192.0.2.10:49152
python -B tools/packclient_pcap_decode.py capture.pcapng --extract-plk1 --output-dir recovered
python -B tools/packclient_pcap_decode.py capture.pcapng --extract-plk1 --extract-pv10 --output-dir recovered
```

`--client-endpoint` is a direction hint and accepts numeric addresses only; IPv6 uses `[address]:port`. Overrides that contradict validated protocol-role evidence are rejected. No port is treated as inherently PackClient.

Capture decoding defaults to `--phase auto`. After the final chunk of a complete PLK1 transfer, automatic decoding preserves the matching four-byte chunk acknowledgement as Launcher traffic, then classifies subsequent frames as Core. Plaintext Core commands are labelled conservatively, and validated type-18 `PV10` messages expose JPEG size and SHA-256 metadata without printing the image bytes.

Artifact extraction requires `--output-dir` and at least one extraction switch. PLK1 output is written only after sequence, size, optional raw-LZ4 decompression, and final SHA-256 verification. Known Core bytes receive a `PackClientCore-<digest>.dll` name; other verified PLK1 objects remain `.bin`. `PV10` output requires an exact declared length and JPEG SOI/EOI markers. Duplicate objects are written once with each observation retained in `manifest.json`.

The manifest records the capture format, size and SHA-256; artifact sizes and hashes; PLK1 header and PE metadata; flow endpoints; contributing frames and packet indexes; and repeated observations. A rejected flow or failed transfer is never exported. Writes use temporary files followed by atomic replacement; a conflicting existing file is not overwritten and leaves no temporary file behind.

The parser handles classic PCAP in either byte order, microsecond/nanosecond timestamps, and PCAPNG section/interface/enhanced/simple packet blocks. Supported link types include Ethernet with VLAN tags, raw IP, BSD null/loopback, Linux cooked v1/v2, and explicit IPv4/IPv6. Supported IPv6 extension headers are walked; IP fragments are excluded rather than reassembled.

Each TCP direction is reassembled separately. Segmentation, coalescing, out-of-order segments, identical overlap and duplicates are covered by the synthetic suite. Gaps and contradictory overlap reject the flow. The sequence-span limit is 256 MiB per direction. The CLI reads the capture into memory, so that span limit is not a total-memory cap.

Only flows beginning at a recognized frame boundary are included by default. `--all-tcp` adds other TCP payload flows for diagnostics without classifying them as PackClient. Exit code 0 means the capture was processed without a rejected flow; it does not mean PackClient traffic was found. Check `included_flow_count` and the reported flows. Included flows may also return `partial`; inspect each flow status. Rejected or malformed flows and invalid capture input return 2.

The timeline preserves TCP order within each direction. Cross-direction ordering is best effort, based on the earliest timestamp of bytes contributing to each frame, so displayed timestamps can be nonmonotonic. Missing timestamps remain explicit.

Unsupported cases include reused four-tuples representing separate connection incarnations, IP-fragment reassembly, checksum validation, mid-frame recovery and obsolete PCAPNG packet blocks.

## Authentication, encryption, and transfer verification

Both Python CLIs accept `--psk-text`, `--psk-hex`, `--use-default-psk`, `--aes-key-hex`, `--envelope-hmac-key-hex`, and `--no-lz4`. Each envelope key must be exactly 32 bytes, represented by 64 hexadecimal characters.

| Phase and supplied material | Available verification |
|---|---|
| No keys | Structural parsing, plaintext Core labels, `PV10` validation, and PLK1 checks where complete bytes exist |
| Launcher handshake PSK | PLA1 HMAC when matching PLH1 and PLC1 context exists |
| Launcher envelope HMAC key | Launcher type-`0x16` authentication |
| Launcher AES and envelope HMAC keys | Authentication before AES-256-CBC decryption, strict padding, and inner type `0x15` |
| Core `auth_psk` | Domain-separated SHA-256 key derivation, authentication before decryption, strict padding, and inner Core-message redispatch |

The fallback `pack-launch-dev-psk` is used only with `--use-default-psk`. No environment variable is read implicitly, and no Launcher envelope key is derived from the handshake PSK. Launcher envelope-key initialization remains unresolved, so those keys must be supplied independently through `--aes-key-hex` and `--envelope-hmac-key-hex`.

Core's separate type-`0x16` format is selected with `--phase core` or a validated automatic phase transition. `--core-psk-text` and `--core-psk-hex` supply the recovered `auth_psk` input from which the tool derives independent AES and HMAC keys. Launcher keys and the Core PSK are never treated as interchangeable. Both envelope paths verify HMAC before attempting AES-CBC decryption.

PLK1 verification requires a valid 56-byte header, supported version, zero-based chunk sequence, exact sizes and a matching final SHA-256. Effective sizes are bounded at 128 MiB. Version 2 transfers that use raw-block LZ4 can be verified only when the optional LZ4 dependency is available and decoding is enabled. The capture CLI writes verified payloads only when extraction is explicitly requested.

## Wireshark and TShark

From the repository root:

```sh
tshark -n -X lua_script:tools/wireshark/packclient.lua -2 -r capture.pcapng -o tcp.desegment_tcp_streams:TRUE -d tcp.port==8443,packclient -Y packclient
```

The example port is an analyst-selected **Decode As** binding, not an IOC. The heuristic requires a complete first four-byte frame word; use Decode As when that word is split across the first TCP segments.

Useful display filters:

```text
packclient
packclient.object.magic == "PLC1"
packclient.object.magic == "PLK1"
packclient.message_type == 0x16
packclient.phase == "Core"
packclient.core.command contains "SCR|PREVIEW"
packclient.pv10.magic == "PV10"
packclient.envelope.ciphertext_length == 16
```

The Lua dissector recognizes both Launcher and Core traffic, including their different type-`0x16` length encodings, observed Core commands, and `PV10` JPEG framing. It provides protocol metadata only; HMAC verification, decryption, PLK1 reconstruction and artifact extraction are handled by the Python capture tool. Unknown or malformed messages are labelled conservatively.

## Tests

```sh
python -B -m unittest discover -s tests -v
```

The Python suite contains 124 tests. Protocol coverage includes framing, direction and phase tracking, Launcher and Core envelopes, the Core KDF, AES vectors, padding, PLK1 validation and TCP reassembly. Additional tests cover safe failures, atomic extraction, Core commands, `PV10`, capture parsing, CLI behavior, the Wireshark dissector and detection rules. Optional external engines are skipped when they are not installed locally.

The [validation workflow](../.github/workflows/validate.yml) runs the Python tests on Python 3.11–3.13 with LZ4, YARA, pySigma, Suricata and TShark available. A Windows PowerShell 5.1 job runs the 15 screenshot IPC tests.

The tools were also validated against historical PackClient captures, including Core recovery and `PV10` extraction. Those captures are not included in the repository.

Detection-engine validation is documented in the [detection guide](detection-guide.md). The separate [screenshot IPC validation](screenshot-ipc-validation.md) covers the local `1RCP` peer/simulator.
