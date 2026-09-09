# PackClient

#### Reverse Engineering a Modular RAT Framework

<p align="center"> <img width="257" height="222" alt="Tax_Notice_23665" src="https://github.com/user-attachments/assets/e8e1c36b-f4c8-49ac-86b4-f05237083478" /> 
&nbsp;&nbsp;&nbsp; <img width="166" height="224" alt="nvdaHelperRemote" src="https://github.com/user-attachments/assets/675e5495-ff09-4227-9b39-66ebd2d16fd0" /> </p>

From Launcher to recovered Core: A technical teardown of PackClient’s PLK1 delivery, plugin loading, screen-capture paths, persistence, and historical C2 traffic.

<p align="center">
  <a href="https://ivanimmanuel-dev.github.io/PackClient/">Read the Publication</a>
  &nbsp;·&nbsp;
  <a href="https://ivanimmanuel-dev.github.io/PackClient/PackClient.pdf">Download the PDF</a>
</p>

## Findings

- Reconstruction of the worker-side `1RCP` interface: a 20-byte header, four message types, top-down BGRX framebuffer data, and an external endpoint peer.
- Recovered transport and authentication contracts: outer framing, handshake, authenticated AES-CBC receive ordering, and the PLK1 cache acceptance path.
- Byte-exact recovery of a 985,088-byte x86 `PackClientCore.dll` from eight complete historical PLK1 transfers, with matching plaintext and mapped-`.text` identities.
- Historical successful protocol progression through `PLH1 -> PLC1 -> PLA1 -> PLK1`, followed by bidirectional Core traffic and 15 `PV10` JPEG frames.
- Independent recovery of the signed host's invoked carrier export, the injected Donut package and terminal-loader ABI, the Core's modern and legacy plugin-loading contracts, and its built-in `PV10` producer.
- Core closure includes all exports, the Launcher ABI, six local configuration keys, phase-specific application encryption, staged plugin/update storage, ETCHOOK clipboard replacement, and the major command/subsystem census.
- Runtime separation of the normal full-EXE persistence path from the direct-DLL `rundll32` sandbox artifact; no second PackClient variant was established.

## Recovered architecture

```mermaid
flowchart TD
    H["Signed NVDA Host<br/>Tax_Notice_23665.exe"]
    C["Carrier DLL<br/>nvdaHelperRemote.dll"]
    V["Suspended 32-bit surrogate<br/>SysWOW64\\svchost.exe"]
    D["Injected Donut package<br/>exact x86 loader + embedded A"]

    subgraph P[" "]
        A["Executable A<br/>Wrapper / Mapper"]
        B["Executable B<br/>PackClientLauncher.exe"]
        A -->|"maps embedded PE"| B
    end

    H -->|"DLL sideload"| C
    C -->|"creates suspended process<br/>remote placement + context hijack"| V
    V -->|"call-over-data entry"| D
    D -->|"maps and starts"| A

    B --> T["Transport + Authentication<br/>PLH1 / PLC1 / PLA1"]
    B --> K["PLK1 Delivery + Cache"]
    B --> S["Active-session Handoff"]
    B --> R["1RCP Screenshot Worker"]

    K -->|"8 verified PLK1 transfers"| CORE["PackClientCore.dll<br/>985,088-byte x86 DLL"]
    CORE --> PABI["Plugin ABI + legacy Main loader"]
    CORE --> PV10["GDI/WIC PV10 JPEG producer"]
    R -. "pre-existing local endpoint" .-> PEER["External 1RCP Peer<br/>Unrecovered"]
```

## References

| Topic | Reference |
|---|---|
| Host, carrier, package and recovered components | [Architecture](docs/architecture.md) |
| `1RCP` screenshot protocol and framebuffer | [Screenshot IPC](docs/screenshot-ipc.md) |
| Benign local peer/simulator | [Synthetic IPC validation](docs/screenshot-ipc-validation.md) |
| Framing, handshake, encryption and PLK1 | [Protocol](docs/protocol-reference.md) |
| Historical artifacts, recovered Core and plugin boundaries | [Core and artifact audit](docs/core-and-artifact-audit.md) |
| Token selection and session drift | [Active-session Handoff](docs/active-session-handoff.md) |
| Runtime memory, persistence and network observations | [Runtime](docs/runtime-validation.md) |
| Artifact identities and claim boundaries | [Evidence](docs/evidence.md) |
| Research limitations | [Limitations](docs/limitations.md) |
| Passive decoders | [Tooling](docs/tooling.md) |
| Detection candidates | [Detection Guide](docs/detection-guide.md) |

## Tools

| Interface | Purpose |
|---|---|
| `tools/packclient_decode.py` | Decode supplied raw streams into structured JSON |
| `tools/packclient_pcap_decode.py` | Decode supplied PCAP/PCAPNG into per-flow timelines |
| `tools/wireshark/packclient.lua` | Display protocol metadata in Wireshark/TShark |

The Python CLIs require Python 3.11–3.13 and the standard library. LZ4 support and detection-engine tests have separate pinned optional dependencies. [The quickstart](docs/tooling.md#minimal-example) creates a deterministic synthetic input without any malware.

```sh
python -B -m unittest discover -s tests -v
```

The optional [synthetic IPC kit](docs/screenshot-ipc-validation.md) exercises the reconstructed `1RCP` contract using benign deterministic inputs and outputs, without malware or desktop capture.

## Detection

The Sigma, Suricata and YARA rules are included as experimental detection candidates with regression coverage. Production accuracy has not been measured.

## Scope and Limitations

The Core and historical successful Launcher-to-Core transport are now recovered. The available evidence still does not identify the external `1RCP` peer, contain a delivered plugin binary, prove a bridge between `1RCP` and Core `PV10`, recover the server implementation, establish a complete real `1RCP` exchange, or prove the causal diagnosis of the worker failure. The two September reruns reached the server but received no application response.

Additional reproducibility gaps are documented in [Evidence](docs/evidence.md) and [Limitations](docs/limitations.md).

## Prior Work

PackClient was previously documented by Proofpoint and Deception.Pro. This work adds implementation details from the recovered carrier, Launcher and Core build while separating prior reporting from independent reconstruction. See [Prior Work](docs/prior-work.md) for more details.

## Citation

Use [CITATION.cff](CITATION.cff) to cite the report. 

Research cut-off: 9 September 2026.

Updated publication date: 9 September 2026.
