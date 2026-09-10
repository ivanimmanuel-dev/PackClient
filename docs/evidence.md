# Evidence

The analysis in this repository is anchored in recovered binaries, historical public sandbox traffic and memory, and controlled local runtime observations. This page identifies the artifacts behind the main findings, separates observed behavior from recovered code paths, and records what remains unresolved.

## Artifact identities

| Artifact | Size | SHA-256 |
|---|---:|---|
| Campaign ZIP | 248,759 bytes | `7108FF29916D064216AA2ECE7FB395F1E3A73D12D19895BFFC0BD46806CBF85A` |
| `Tax_Notice_23665.img` | 641,024 bytes | `38EC1F5E23F65B10AE3027BEABFA0BF7F9FB686355A9E33C7E7E44E6A998E04C` |
| Signed host `Tax_Notice_23665.exe` | 120,984 bytes | `93DD8B7B393289F88493596FAA4AE70054D9EB4FE47F2DD334F0C6BB5262F2A8` |
| Carrier `nvdahelperremote.dll` | 455,527 bytes | `7295090C2CB63EBC43F932451971C41F9D015D2741E97AE3D9855F5AE87CFF94` |
| XOR-decoded package record | 415,071 bytes | `0419AE7381CAA97172C40F5AEA601B8A22F1F58D27F3930509AF5808E043F65E` |
| Executable A, the wrapper/mapper | 397,312 bytes | `28B8EB812E0F0AB724475BD51E3DC1F618BCB08B05998C414D4193009BF8D598` |
| Executable B, the Launcher | 271,872 bytes | `46B34789196733FAB62193F0AAEDB198B09F1362F9B10CA1DD70CF81D68B01AD` |
| Compressed PLK1 Core object | 669,717 bytes | `502A7D2D72BEFA9114417936A1B3C2DD8EC84FCD4AE9EF9A09FFF3604FC05CCE` |
| Recovered `PackClientCore.dll` | 985,088 bytes | `4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C` |
| Recovered Core `.text` section | 753,664 bytes | `F06FF7AB6D62B761344CAECBCC6857912F7543F43C0E5FF462D2174BADB0CA3F` |

The IMG contains the signed host and its colocated carrier. At host RVA `0x1004`, the host calls the imported `nvdaHelperRemote.dll!injection_initialize` function. The carrier decodes the embedded package, creates a suspended `C:\Windows\SysWOW64\svchost.exe`, places the package in that process, changes the primary thread context, and resumes it.

The package contains a Donut loader followed by Executable A and Executable B. The 11,647-byte loader body is byte-identical to Donut's official `LOADER_EXE_X86` at source revision `47758d787209dd1744f58c140102ac91b649df16`. Its SHA-256 is `0C29CCCFF1B027D57C467564A333E9ADE455144649909A4B797B09B43002AC71`; the adjacent four-byte ABI glue and 23 bytes of zero padding are not part of that comparison. Donut starts Executable A, which maps Executable B inside the surrogate. Executable B is the PackClient Launcher.

## Runtime observations

| Observation | What it establishes | Boundary |
|---|---|---|
| The signed host loaded the colocated carrier. | The initial execution path is DLL sideloading through the signed host. | The host signature does not authenticate the carrier. |
| Public Triage runs show a fresh suspended `SysWOW64\svchost.exe`, 53 sandbox-labelled remote writes into a private region at `0x00440000` with length `0x66000`, and `SetThreadContext` on its primary thread. | The package is written into a surrogate and started through primary-thread context hijacking. | The exact carrier write call site and the installed instruction-pointer value have not been recovered. |
| Full-EXE execution created the `NvSvc` scheduled task for a copied `Tax_Notice_23665.exe`. | This is the normal persistence path observed for the complete executable chain. | The task behavior is specific to the examined build and environment. |
| Direct-DLL sandbox execution through `rundll32.exe` created `NvSvc` for a copied `rundll32.exe` without the DLL argument. | A second execution path reaches the same persistence routine with different process state. | The resulting task cannot replay the original DLL invocation and does not establish a second PackClient variant. |
| Local runs attempted connections to `154[.]36[.]188[.]201:443`; the September reruns established TCP sessions and transmitted valid `PLH1` greetings, but none reproduced the successful July application session. | The later executions reached the server far enough to transmit the Launcher greeting. | Server inactivity, filtering, configuration drift and client-profile differences cannot be distinguished from the available evidence. |
| The Launcher contains active-session replacement logic and a separate `1RCP` screenshot worker. | Their command lines, token handling and local message formats were recovered. | No successful active-session replacement, real external `1RCP` peer or complete worker exchange was captured. |

The remote-write and thread-context sequence appears across the reviewed July and August Triage runs. It establishes the placement and start method at the behavioral level; it should not be described as classic image replacement or remote-thread creation.

## Historical traffic

The July Triage reports [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l) and [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) capture successful `PLH1 -> PLC1 -> PLA1 -> PLK1` progression followed by bidirectional Core traffic. Each report contains four complete copies of the same PLK1 transfer. One complete copy is sufficient to recover the Core; the repeated copies confirm that the delivered bytes are consistent across both sessions.

Each PLK1 header declares wire version 2, raw-LZ4 compression, a 669,717-byte compressed body, a 985,088-byte decompressed object, and the Core SHA-256 listed above. The body is carried by eleven ordered type-`0x15` chunks with sequence numbers 0 through 10: ten chunks contain 65,536 bytes and the final chunk contains 14,357 bytes. Raw-LZ4 decompression produces the 985,088-byte PE32 `PackClientCore.dll`. The same 753,664-byte `.text` identity appears in 352 memory mappings from eight Core processes.

Post-delivery traffic includes startup exchange, host inventory, offline-keylogger status, preview control and 15 client type-18 `PV10` JPEG frames. It does not contain a Core type-`0x16` encrypted message, plugin delivery, a Core update or ETCHOOK activation.

The filtered PCAPNG distributed with the research material is a 762,668-byte derivative of `260715-wd77daas7l/behavioral1`, not a separate collection. Its SHA-256 is `AB437D0EAE5E3C93764B89A3ECC5F6940D3CBEE0C2BE8D80D34CD7CB4CA38875`.

## Implemented and observed behavior

| Capability | Recovered implementation | Runtime or traffic observation |
|---|---|---|
| Launcher handshake and PLK1 delivery | Framing, `PLH1`, `PLC1`, `PLA1`, HMAC authentication, PLK1 sequencing, raw-LZ4 decompression and SHA-256 acceptance were recovered. | Complete successful exchanges and Core delivery appear in the July traffic. |
| Launcher type-`0x16` envelope | The receive path authenticates the envelope before AES-256-CBC decryption. | Launcher envelope-key initialization and an encrypted Launcher session were not recovered. |
| Active-session handoff | Token selection, command-line construction, privilege adjustment and session-drift handling were recovered. | No successful replacement into another interactive session was observed. |
| Launcher `1RCP` screenshot worker | The 20-byte header, four message types and top-down BGRX framebuffer format were recovered and exercised with a benign local peer. | The external peer and any bridge to Core `PV10` traffic remain unknown; no complete real-worker exchange was captured. |
| Core plugin system | Modern and legacy loading contracts, delivery staging, cache metadata, machine binding, DPAPI protection and migration logic were recovered. | No plugin binary, paired cache artifact, completed delivery or activated plugin was present in the available material. |
| Core updates | The `CLIENTCOREUPD` command path and DPAPI-protected update store were recovered. | No Core-update transaction was observed. |
| Core type-`0x16` envelope | The domain-separated SHA-256 derivation for independent AES and HMAC keys, authenticated AES-CBC receive path and phase-specific byte order were recovered. | No encrypted Core frame was present in the July traffic. |
| Core `PV10` screenshots | The built-in GDI/WIC JPEG producer and its command handlers were recovered. | Fifteen valid `PV10` JPEG frames were captured. |
| ETCHOOK clipboard replacement | The replacement engine, built-in pattern families, and `PERCLIENT` and `SYNC` control formats were recovered. | ETCHOOK activation does not appear in the captured traffic. |

Detailed limitations and unresolved questions are documented in [Limitations](limitations.md). Supporting analysis is available in [Launcher architecture](launcher-architecture.md), [Launcher protocol](launcher-protocol.md), [Core analysis](core-analysis.md), [Runtime analysis](runtime-analysis.md), [Screenshot IPC](screenshot-ipc.md), and [Active-session handoff](active-session-handoff.md).
