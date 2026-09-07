# Passive analysis tools

The repository includes three offline interfaces for the recovered launcher protocol: a raw-stream decoder, a PCAP/PCAPNG decoder, and a Wireshark dissector. Their wire contracts are documented in the [protocol reference](protocol-reference.md); research boundaries are summarized in [limitations](limitations.md).

## Interfaces and requirements

| Interface | Input | Output | Requirements |
|---|---|---|---|
| [`packclient_decode.py`](../tools/packclient_decode.py) | Ordered raw byte stream from a file or standard input | JSON framing, handshake, envelope and PLK1 verification metadata | Python 3.11–3.13; standard library |
| [`packclient_pcap_decode.py`](../tools/packclient_pcap_decode.py) | PCAP or PCAPNG from a file or standard input | Per-flow text timeline with direction, reassembly and verification status | Python 3.11–3.13; standard library |
| [`packclient.lua`](../tools/wireshark/packclient.lua) | TCP data in a capture opened by Wireshark/TShark | Framing, validated object labels, encrypted-envelope metadata and malformed-object expert fields | Wireshark/TShark with Lua support |

[`packclient_proto.py`](../tools/packclient_proto.py) and [`packclient_pcap.py`](../tools/packclient_pcap.py) provide the shared implementation. AES-256-CBC is implemented without third-party dependencies and checked against [NIST FIPS 197](https://doi.org/10.6028/NIST.FIPS.197) and [SP 800-38A](https://doi.org/10.6028/NIST.SP.800-38A) known-answer vectors. Optional PLK1 raw-block LZ4 decoding uses `lz4==4.4.5`:

```sh
python -m pip install -r requirements/lz4.txt
```

The raw CLI omits supplied keys and recovered plaintext bodies from its output. Its metadata can still contain protocol fields such as IVs, challenges and authentication tags. The capture timeline omits those byte fields as well as bodies and keys, but includes captured addresses and ports. Command-line keys may be visible in shell history or process listings; use the Python API when that matters.

## Minimal example

From the repository root, create a 32-byte PLH1 object and wrap it in lower type `0x15`:

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
python -B tools/packclient_decode.py stream.dat --no-lz4
```

Use `-` instead of a filename for binary standard input. Exit code 0 means the stream parsed; inspect verification and reassembly fields for incomplete transfers or unauthenticated objects. Rejected or malformed input returns 2.

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
```

`--client-endpoint` is a direction hint and accepts numeric addresses only; IPv6 uses `[address]:port`. Overrides that contradict validated protocol-role evidence are rejected. No port is treated as inherently PackClient.

The parser handles classic PCAP in either byte order, microsecond/nanosecond timestamps, and PCAPNG section/interface/enhanced/simple packet blocks. Supported link types include Ethernet with VLAN tags, raw IP, BSD null/loopback, Linux cooked v1/v2, and explicit IPv4/IPv6. Supported IPv6 extension headers are walked; IP fragments are excluded rather than reassembled.

Each TCP direction is reassembled separately. Segmentation, coalescing, out-of-order segments, identical overlap and duplicates are covered by the synthetic suite. Gaps and contradictory overlap reject the flow. The sequence-span limit is 256 MiB per direction. The CLI reads the capture into memory, so that span limit is not a total-memory cap.

Only flows beginning at a recognized frame boundary are included by default. `--all-tcp` adds other TCP payload flows for diagnostics without classifying them as PackClient. A capture with no candidate flows can return 0. Included flows may also return `partial`; inspect each flow status. Rejected or malformed flows and invalid capture input return 2.

The timeline preserves TCP order within each direction. Cross-direction ordering is best effort, based on the earliest timestamp of bytes contributing to each frame, so displayed timestamps can be nonmonotonic. Missing timestamps remain explicit.

Unsupported cases include reused four-tuples representing separate connection incarnations, IP-fragment reassembly, checksum validation, mid-frame recovery and obsolete PCAPNG packet blocks.

## Authentication, encryption, and transfer verification

Both Python CLIs accept `--psk-text`, `--psk-hex`, `--use-default-psk`, `--aes-key-hex`, `--envelope-hmac-key-hex`, and `--no-lz4`. Each envelope key must be exactly 32 bytes, represented by 64 hexadecimal characters.

| Supplied material | Available verification |
|---|---|
| No keys | Structural parsing and plaintext PLK1 checks where complete bytes exist |
| Handshake PSK | PLA1 HMAC when matching PLH1 and PLC1 context exists |
| Envelope HMAC key | Type-`0x16` authentication |
| AES key and envelope HMAC key | Authentication before AES-256-CBC decryption, strict padding and inner type `0x15` |

The fallback `pack-launch-dev-psk` is used only with `--use-default-psk`. No environment variable is read implicitly, and no envelope key is derived from the handshake PSK. Envelope-key initialization remains unresolved, so envelope keys must be supplied independently. AES decryption is attempted only after HMAC verification succeeds.

PLK1 verification requires a valid 56-byte header, supported version, zero-based chunk sequence, exact sizes and a matching final SHA-256. Effective sizes are bounded at 128 MiB. Version 2 raw-block LZ4 output is unverifiable when the optional dependency is unavailable or decoding is disabled. The CLIs do not write recovered payloads to disk.

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
packclient.envelope.ciphertext_length == 16
```

The dissector presents type-`0x16` metadata but does not verify HMAC, decrypt or reassemble PLK1 payloads. Unknown message types remain unlabeled.

## Validation

```sh
python -B -m unittest discover -s tests -v
```

The standard-library suite covers framing, direction/context handling, authentication failure before decryption, AES known-answer vectors, padding, PLK1 sequence/size/hash validation, TCP reassembly, capture-container bounds and CLI outputs.

The [validation workflow](../.github/workflows/validate.yml) runs the maintained Python suite on Python 3.11–3.13 and exercises optional engines in a separate job.

Detection-engine validation is documented in the [detection guide](detection-guide.md). The separate [screenshot IPC validation](screenshot-ipc-validation.md) covers the local `1RCP` peer/simulator.
