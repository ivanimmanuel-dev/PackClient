# Recovered Core and public-artifact audit

Research cut-off: **9 September 2026 (UTC)**.

This reference separates four evidence classes:

- **Public reporting:** claims made by Proofpoint or public sandbox reports.
- **Sandbox observation:** process, persistence, file and packet evidence recorded by Triage or Hybrid Analysis.
- **Independent reconstruction:** results reproduced from preserved bytes, packet streams, memory images or static code.
- **Hypothesis:** an explanation consistent with the evidence but not established by it.

The complete working record, source ledger and all analyst screenshots remain in the PackClient-LAB repository. This publication includes only the findings that survived the audit.

## Source set and provenance

| Source | Role in this audit | Boundary |
|---|---|---|
| [PackClient-LAB Phase 5A audit](https://github.com/ivanimmanuel-dev/PackClient-LAB/blob/fd24a91234dbe13fc1a57a26d67f42075a0a581c/docs/phase5a-public-artifact-core-and-detection-audit.md) | Complete working record, machine-readable ledgers, modular reports and figure provenance | Commit-pinned research source of record; raw malware, memory and packet bytes remain excluded from Git |
| [Proofpoint, *Carry-On Compromise: TA4922 Packs PackClient*](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) | Campaign anchor, family naming, prior protocol/plugin reporting and ET coverage | Public reporting, not independent validation of the artifacts below |
| [Deception.Pro, *New PackClient & HOK (Aug 2026)*](https://blog.deception.pro/blog/new-packclient-hok-aug2026) | Later PackClient/hands-on-keyboard and ManageEngine follow-on context | Public prior reporting; private backend artifacts were not available to this audit |
| [MalwareBazaar `7108FF…F85A`](https://bazaar.abuse.ch/sample/7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a/) | Public campaign ZIP identity and source of the Tax Notice lineage | Artifact identity only |
| Triage [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l/behavioral3) and [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) | Four complete PLK1 transfers in each run plus post-Core traffic | Historical sandbox observation; the filtered Wireshark capture is a derivative of `260715-wd77daas7l/behavioral1`, not another run |
| [Triage `260828-py7ysahr4y`](https://tria.ge/260828-py7ysahr4y) | Later public behavioral comparison | Sandbox observation |
| [Triage `260908-zwr5naybjb`](https://tria.ge/260908-zwr5naybjb) | Full-EXE and direct-DLL persistence comparison | Researcher-run sandbox observation |
| [Triage `260909-abma8sab28`](https://tria.ge/260909-abma8sab28) | One-hour repeat of the full-EXE path | Researcher-run sandbox observation |
| [Hybrid Analysis `7295090C…CFF94`](https://hybrid-analysis.com/sample/7295090c2cb63ebc43f932451971c41f9d015d2741e97ae3d9855f5ae87cff94/6a917e4b5211eca77507e3a8) | Carrier behavioral report and historical process evidence | Public sandbox report; unavailable downloads are not treated as recovered evidence |

The audit also reviewed the exact public revisions of [Sigma PR #6280](https://github.com/SigmaHQ/sigma/pull/6280) and [Wireshark MR !26404](https://gitlab.com/wireshark/wireshark/-/merge_requests/26404). Their retained source-snapshot identities in the LAB ledger are `507999AB2ED9A3B48714E62E97753D7BE65FCC7DF7285BEF4D69DB25F62BC2AE` for the Sigma diff, `74F546F4335F066BA3364CE707A7F310E8CC4C56A091EF6E3807EB7681BE4FC6` for `packet-packclient.c`, and `2C06F595794A2B2EF944224ABFCCC379904428933319934C629574B8110794B6` for its automated test group. No upstream submission is modified by this publication patch.

The retained working method used nine offline Python analyzers and nine Ghidra exporters. Their machine-readable outputs and source snapshots are commit-pinned in the LAB; raw malware, memory and packet inputs are intentionally excluded. Several scripts retain original analyst path assumptions, and the Ghidra exporters do not independently enforce the input hashes recorded by the surrounding ledger. A clean third-party rerun therefore requires reacquiring the exact inputs, verifying their hashes and configuring local paths before executing the retained tools. The findings below rely on the pinned outputs plus cross-checks against packet, memory and static evidence, not on tool names alone.

At the pinned LAB revision, the retained offline Python analyzers are:

| Analyzer | Retained purpose |
|---|---|
| `analyze_memory_corpus.py` | Inventory and hash sandbox memory records, identify PE layouts and compare mapped artifacts without execution |
| `analyze_packclient_c2_streams.py` | Parse preserved PackClient stream artifacts and inventory framing, directions and application records |
| `audit_et_and_core_wire.py` | Compare reviewed ET packet predicates with reassembled Launcher/Core wire evidence |
| `bulk_decode_captures.py` | Run the offline capture decoder across the retrieved PCAP/PCAPNG corpus |
| `core_capstone_audit.py` | Perform a bounded instruction/XREF audit of the reconstructed Core with Capstone |
| `core_targeted_xrefs.py` | Trace selected Core strings and conservative direct-call relationships without claiming decompiler recovery |
| `summarize_capture_decodes.py` | Reduce per-capture decode JSON into a flow and coverage summary |
| `validate_core_yara_strings.py` | Emulate the proposed PE/string condition over the retained corpus in Python; it is not a YARA-engine run |
| `verify_plk1_corpus.py` | Reassemble every complete PLK1 transfer, decompress raw LZ4 and verify declared sizes and digests |

The retained Ghidra exporters are:

| Exporter | Retained purpose |
|---|---|
| `DumpPluginData.java` | Export compiler-hidden plugin-protocol literals and data probes |
| `DumpTargetData.java` | Export narrow data-table values referenced by targeted decompilation |
| `ExportCoreAbiTransport.java` | Recover the Core export ABI, configuration application and transport/crypto paths |
| `ExportCoreClosureTargets.java` | Export the bounded queue of functions selected for final coverage closure |
| `ExportCoreConfigCallers.java` | Census Core INI/profile call sites and their callers |
| `ExportCoreCoverageClosure.java` | Census exports, imports, configuration, protocol vocabulary and major subsystems, then prioritize unexplained functions |
| `ExportPluginProtocol.java` | Locate and decompile the staged `Q|PLUGIN|` protocol handlers |
| `ExportTargetFunctions.java` | Export targeted plugin ABI/store, preview and related Core functions |
| `ExportTerminalLoader.java` | Identify and export the injected terminal region and Donut loader evidence |

These names document the retained method; they are not a turnkey reproduction bundle. Exact inputs must be reacquired and hash-checked against the LAB ledger before rerunning any analyzer or exporter.

## Core recovery from PLK1

Eight complete PLK1 transfers reconstruct the same object: four in `260715-wd77daas7l` and four in `260716-dhnz7aft6z`. Every transfer declares wire version 2, raw LZ4, transferred size 669,717, original size 985,088, and the same expected plaintext digest.

The transfer body is eleven ordered lower type-`0x15` data records with sequence values 0 through 10. Records 0–9 each carry 65,536 data bytes; record 10 carries 14,357 bytes:

```text
10 * 65,536 + 14,357 = 669,717 compressed bytes
```

The concatenated raw-LZ4 derivative has SHA-256:

```text
502A7D2D72BEFA9114417936A1B3C2DD8EC84FCD4AE9EF9A09FFF3604FC05CCE
```

Decompression produces a 985,088-byte PE32 DLL with SHA-256:

```text
4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C
```

This equals the sender-declared PLK1 plaintext digest in all eight transfers. A separate memory census found 352 mapped Core images whose 753,664-byte `.text` region matches SHA-256:

```text
F06FF7AB6D62B761344CAECBCC6857912F7543F43C0E5FF462D2174BADB0CA3F
```

This is byte-level recovery, not a role inference from Launcher strings.

The filtered PCAPNG used for the Wireshark validation is 762,668 bytes with SHA-256 `AB437D0EAE5E3C93764B89A3ECC5F6940D3CBEE0C2BE8D80D34CD7CB4CA38875`. It retains the relevant Launcher flow from `260715-wd77daas7l/behavioral1` and is derivative evidence.

## Core identity and entry surface

The recovered object identifies as `PackClientCore.dll`; its CodeView path ends in `\Project\Bin\Plugins\Win32\PackClientCore.pdb`. It is a PE32/IA-32 DLL with preferred image base `0x10000000`, image size 1,114,112 bytes, entry RVA `0x81502`, six sections and 358 imports from 16 Windows DLLs. The entry point is ordinary DLL/security-cookie startup, not another exported command path.

All 11 exports are accounted for:

| Ordinal | Export | RVA | Recovered role |
|---:|---|---:|---|
| 1 | `Main` | `0xC0BD` | Main runtime |
| 2 | `MainMinimal` | `0xC23C` | Thin probe returning 7 |
| 3 | `MainWithConfig` | `0xC240` | Stores two endpoint tuples and enters `Main` |
| 4 | `PackClientDll_AbiVersion` | `0x232B` | Returns ABI 1 |
| 5 | `PackClientDll_Run` | `0x232F` | Primary Launcher configuration-view ABI |
| 6 | `PackClientDll_TrySystemSessionHandoff` | `0x2761` | Session-handoff entry |
| 7 | `PackClient_AllocStoredPluginImageW` | `0x19C6F` | Stored plugin-image allocation wrapper |
| 8 | `PackClient_FreeStoredPluginImage` | `0x19D4D` | Matching release wrapper |
| 9 | `ProbeEntry` | `0xC459` | Thin probe returning 1234 |
| 10 | `RunDualWithConfig` | `0xC45F` | Dual-link startup |
| 11 | `RunWithConfig` | `0x276D` | Single-tuple wrapper |

## Launcher-to-Core ABI closure

`PackClientDll_Run(view, flags)` interprets the Launcher-supplied view as:

| Offset | Core interpretation |
|---:|---|
| `+0x00` | Required nonempty host pointer |
| `+0x04` | Required nonzero 16-bit port |
| `+0x08` | Group pointer; absent/empty becomes `default` |
| `+0x0C` | Optional tag pointer |
| `+0x10` | Optional configuration-string pointer |

This confirms the Launcher's previously reconstructed calling edge. The pre-dispatch gate requires at least `RunWithConfig` or `Main` to be present even though the Launcher also resolves `PackClientDll_Run`. After that gate, Launcher requires ABI 1, prefers `RunWithConfig`, otherwise calls `PackClientDll_Run(view, 0)`, and only then falls back to `Main`.

## Historical successful transport

The July Triage captures progress through the complete Launcher delivery sequence:

```text
PLH1 (client) -> PLC1 (server) -> PLA1 (client) -> PLK1 (server)
```

The endpoint is `154[.]36[.]188[.]201:443`. The traffic is raw PackClient framing on TCP/443, not TLS. After Core delivery, the same historical captures contain bidirectional Core application traffic. Representative plaintext records include:

```text
INP|HELLO|uuid=...|S1|iid=
SYS|Q|EXT|STARTUP|PROBE|
SYS|R|EXT|STARTUP|OK|tags=
TLM|U|KTL|OFFLINE|1
SCR|PREVIEW|ENABLE|1
SCR|PREVIEW|REQ
SCR|PREVIEW|ACK|SEQ|1
SCR|PREVIEW|ACK|SEQ|2
```

Type 11 carries Windows/sandbox network and device inventory. The captures also contain 15 type-18 `PV10` JPEG frames.

The observed-versus-static boundary is:

| Surface | Historical sandbox observation | Independently reconstructed Core implementation | Present boundary |
|---|---|---|---|
| Session/startup | `INP|HELLO|...`, `SYS|Q|EXT|STARTUP|PROBE|` and `SYS|R|EXT|STARTUP|OK|...` | Session/control routing plus the `Q|EXT|STARTUP|PROBE` branch | Establishes live Core command exchange, not server implementation |
| Preview | `ENABLE`, `REQ`, two `ACK` sequences and 15 type-18 `PV10`/JPEG frames | Built-in GDI capture, WIC JPEG encoding and bytewise `PV10` serialization | No recovered component bridges the separate Launcher `1RCP` interface to this producer |
| Keylogger telemetry | `TLM|U|KTL|OFFLINE|1` | Key-state/hook, offline archive, synchronization and clipboard-telemetry paths | The record establishes status/telemetry, not captured keystroke contents |
| Plugin delivery | No `Q|PLUGIN|` transaction, plugin bytes or plugin-cache pair | Staged delivery, feature ABI, memory loader, activation policy and DPAPI cache | Capability and recovery targets only; no plugin PE was recovered |
| Core update | No matching update transaction | `Q|EXT|CLIENTCOREUPD|` validation and a DPAPI-protected current-user registry store | Static implementation only; WinHTTP is not established as this branch's transport |
| Authenticated Core envelope | Zero type-`0x16` Core frames | Optional `auth_psk` SHA-256 KDF and little-endian AES-CBC/HMAC envelope | No deployed PSK or encrypted Core message was recovered |
| ETCHOOK | No activation or replacement traffic | Regex-controlled ANSI/Unicode clipboard replacement with per-client and bulk synchronization | Static capability only; public reporting had already established clipper capability |

Aggregate post-delivery frame counts across the eight successful captures are:

| Direction/type | Frames |
|---|---:|
| Client types 1 / 2 / 3 / 11 / 17 / 18 | 654 / 160 / 363 / 343 / 42 / 15 |
| Server types 1 / 2 / 3 / 10 | 160 / 643 / 392 / 33 |
| Either direction type 22 (`0x16`) | 0 |

All 15 client type-18 frames begin with `PV10` and contain valid JFIF/JPEG structure. No encrypted-Core type-`0x16` frame appears in the July corpus, so the visible commands are genuine plaintext observations and missing plugin traffic cannot be blamed on unavailable decryption.

This establishes a successful historical C2/application session in those public runs. It does **not** establish that the September reruns succeeded: `260908-zwr5naybjb` and `260909-abma8sab28` completed TCP/greeting attempts but received no application response, so they show repeated PLH1 retries and no PLC1, PLK1, Core or plugin delivery.

The two-mode `260908-zwr5naybjb` task reconstructed 492 complete greetings and 19,680 client application bytes in full-EXE mode, plus 501 greetings and 20,040 bytes in direct-DLL mode; both received zero server application bytes. The later `260909-abma8sab28` full-EXE task reconstructed 283 complete greetings and 11,320 client application bytes, again with zero server bytes. DNS for `c.pki.goog` and an HTTP CRL response independently establish working general sandbox networking in the latter run; the Windows NCSI icon was not proof of network isolation.

## Core configuration and authenticated application envelope

The complete Core-local `settings.ini` key set is:

| Section | Key | Default | Recovered role |
|---|---|---:|---|
| `pack` | `fragment_assembler_max_mb` | 0 | Fragment-assembler size override |
| `pack` | `uplink_dns_poll_sec` | 300 | Uplink DNS re-resolution interval |
| `pack` | `tls_ca_path` | empty | Optional CA path |
| `pack` | `tls_skip_verify` | 0 | TLS-verification bypass flag |
| `pack` | `auth_psk` | empty | Optional application-envelope PSK |
| `preview` | `enabled` | 1 | Built-in preview gate |

When `auth_psk` is absent or empty, Core clears the application-crypto-ready flag and zeroes both keys. Otherwise it derives them directly:

```text
AES_key  = SHA256(ASCII("PACKAPP|AES256|v1|") || raw_auth_psk_bytes)
HMAC_key = SHA256(ASCII("PACKAPP|HMAC|v1|")   || raw_auth_psk_bytes)
```

This is not PBKDF2 and is separate from Launcher handshake authentication. Core's authenticated outer type-`0x16` body is version 1, a 16-byte random IV, a four-byte little-endian ciphertext length, AES-256-CBC ciphertext with block padding, and a 32-byte HMAC-SHA-256 over `version || IV || LE32(length) || ciphertext`. Its total envelope length is `ciphertext_length + 0x35`. Authentication precedes decryption. Outbound wrapping encrypts a complete Core message—its original 32-bit type plus payload—except messages already typed `0x15` or `0x16`; inbound plaintext is redispatched using its own first four bytes as the Core message type. The Launcher instead uses a big-endian length field and requires its decrypted inner type to be `0x15`, so phase-aware parsing is mandatory.

## Core plugin system and missing plugin bytes

The Core contains two plugin-loading paths:

1. The modern path requires `PackPlugin_GetFeatureId`; optional `PackPlugin_GetAbiVersion` must return 1, and optional `PackPlugin_OnLoad` is called when present. ScreenCore, VirtualDesktop and FastGuiScreen additionally require their feature-specific `BindHostAtomics` export.
2. The legacy/cache-run path maps an in-memory PE, resolves literal export `Main`, verifies with `VirtualQuery` that the export belongs to that image, and starts it in a thread.

Canonical feature mappings recovered from Core are:

| Feature | Canonical DLL |
|---|---|
| `remote_screen` | `PackPlugin.ScreenCore.dll` |
| `virtual_desktop` | `PackPlugin.VirtualDesktop.dll` |
| `file_management` | `PackPlugin.FileManager.dll` |
| `system_management` | `PackPlugin.SystemManagement.dll` |
| `registry` | `PackPlugin.Registry.dll` |
| `remote_terminal` | `PackPlugin.RemoteTerminal.dll` |
| `proxy_tunnel` | `PackPlugin.Proxy.dll` |
| `remote_video` | `PackPlugin.RemoteVideo.dll` |
| `fast_gui_screen` | `PackPlugin.FastGuiScreen.dll` |
| `tg_tool` | `PackPlugin.TgTool.dll` |
| `browser_mgr` | `PackPlugin.BrowserMgr.dll` |

The broader classifier maps `screenblank` and `openh264*.dll` to `remote_screen`, `webcam` to `remote_video`, and `turbojpeg*.dll` to `fast_gui_screen`; those codec files can therefore be sidecars rather than primary plugins.

Modern `Q|PLUGIN|op=2` delivery is an `init -> chunk -> commit` transaction. It carries a request/transaction ID, normalized base64 filename, mandatory MD5, optional SHA-256, original and compressed sizes, offset and base64 data. Staged mode uses raw LZ4 and bounds plaintext at 128 MiB and compressed input at 256 MiB. Receipt is ordered and idempotent: exact retransmission is accepted as `chunk_dup`, matching overlap appends only the new tail, future offsets return `chunk_offset`, and conflicting overlap returns `chunk_conflict`. Commit requires exact compressed length, decompressed size and digest agreement. Legacy op=2 also accepts a complete LZ4/zlib object; `kind=uprun` is a separate executable-write/launch path, not a plugin-DLL variant.

The file-backed plugin store uses current-user DPAPI with description `PackMonitorClient.PluginStore`, entropy `PackMonitorClient.PluginStore.v1` and UI-forbidden mode. Its root derives from the host executable directory; when that directory ends in `Launcher\x64` or `Launcher\Win32`, Core first moves two directories upward. Its primary x86 layout is:

```text
<derived-root>\pluginsdata\x86\blobs\<normalized-file>.pblob
<derived-root>\pluginsdata\x86\meta\<normalized-file>.json
```

The legacy fallback omits the `x86` component. A valid fallback pair is migrated to the primary layout and then removed. Writes use a `.tmp` file, flush it and replace the destination with write-through. Metadata is:

```json
{"version":1,"file":"%s","md5":"%s","machine":%u,"enc":"dpapi_current_user_v1","blob":"%s","root":"%s"}
```

Loading requires the paired blob and JSON, the same user DPAPI context, MD5 agreement and expected PE machine. A `.pblob` alone is insufficient. This MD5/machine-tagged plugin schema is distinct from the Launcher's SHA-256 Core cache. Protocol text `store=registry` refers to Core's internal module registry, not a Windows Registry location. Sidecars are stored but not directly loaded; some primary features are registry-only until later activation. Plugin operation 4 starts a feature-specific physical channel with an optional TTL defaulting to 300 seconds; operation 5 authenticates a channel using feature, channel ID, nonce and HMAC fields. No reviewed task exercised them.

No plugin PE, sidecar, paired `.pblob`/JSON, plugin-only mapping, plaintext staged transaction, completed activation, or encrypted Core frame was present in the captured PLK1, packet, memory, cache or dumped-file corpus. This negative result is scoped to preserved evidence: static analysis cannot manufacture missing plugin bytes. Future recovery requires a decrypted transaction, paired cache plus DPAPI context, post-activation memory, or a backend-only sandbox object.

## Core-update storage

`Q|EXT|CLIENTCOREUPD|op=put` receives base64 LZ4/zlib content over the existing command channel, validates the decompressed size and MD5, then protects it with current-user DPAPI. WinHTTP belongs to other branches of the same large dispatcher and is not the Core-update delivery mechanism.

The update store is:

```text
HKCU\Software\PackMonitorClient\LauncherDllStore\<bits>\Primary
```

It records plaintext SHA-256, encoding label `dpapi_v1`, protected size, chunk count, and protected binary chunks `p%u` of at most `0x80000` bytes. The DPAPI description is `PackMonitorClient.LauncherDllStore` and entropy is `PackMonitorClient.LauncherDllStore.Primary.v1`. The older `Q|COREUPD|CHECK|` branch reads the same store. No matching update transaction was observed.

## Built-in PV10 producer

Static reconstruction identifies the Core's built-in screenshot-preview path:

```text
GDI capture / StretchBlt / GetDIBits
  -> WIC JPEG encoding with ImageQuality
  -> bytewise PV10 serializer
  -> Core transport type 18
```

The implementation spans GDI capture/scaling at RVA `0x23B4F`, WIC JPEG encoding at `0x231AC`, and the bytewise `PV10` serializer at `0x236D0`. The normal thumbnail path at `0x241ED` uses a maximum dimension of 160 and quality 35; adaptive `VIEW` handling at `0x22C39` retries within a requested size limit. The `PREVIEW|REQ` dispatcher is at `0x313B3`.

The serializer appends `P`, `V`, `1`, `0`, a four-byte little-endian JPEG length and the JPEG bytes. All 15 historical type-18 frames agree exactly, including JFIF prefix structure. This establishes that Core itself produces the observed JPEG preview traffic. It does not prove that the Launcher's separate raw-BGRX `1RCP` worker feeds this path; the endpoint creator/consumer that would bridge those two interfaces remains missing.

## Command, subsystem and ETCHOOK closure

Every export, Core-specific INI key, code-referenced primary command family, major subsystem and previously unexplained function of at least 2,000 bytes was classified. The inventory covers system/file/process/registry/task queries; plugin, payload and Core-update paths; extension routing; screen/input/preview channels; `PIPE|FGUI|`, `PIPE|PHYS|` and `PIPE|990|`; keylogger/clipboard operations; TCP/UDP/proxy/admin forwarding; shell commands; and webcam handling. Imports and handlers prove capability, not operator activation.

The concrete ETCHOOK path reads ANSI and Unicode clipboard text, evaluates configured regular expressions, replaces matching text, empties the clipboard and writes both Unicode and ANSI replacement values. Its built-in table includes address-pattern families consistent with Bitcoin, Litecoin, `t1`/`t3`, NEAR, ICP, Ethereum-style `0x`, and `cro1`. `Q|EXT|ETCHOOK|PERCLIENT|` carries state plus `regex_b64` and `repl_b64`; `Q|EXT|ETCHOOK|SYNC|` accepts a bulk/base64 rule object. Proofpoint had already reported clipper capability; the implementation, default pattern families and control grammar are the independently reconstructed addition. No reviewed task proves activation.

The Core contains 6,710 detected functions. This is not a claim that every compiler/runtime helper was semantically renamed. Research-relevant functional coverage is estimated at 85–90%; remaining small functions are predominantly runtime, STL/compiler, formatting, codec or local utilities. No unexplained large protocol-bearing branch remains.

## Carrier closure

Static analysis of the signed host shows a direct imported call to `nvdaHelperRemote.dll!injection_initialize` at host RVA `0x1004`, through helper IAT slot RVA `0xF268`. Its only other imported function is `KERNEL32!ExitProcess`.

Across twelve retained July/August Triage tasks, the carrier creates a fresh suspended 32-bit `SysWOW64\svchost.exe`, performs remote writes of a stable 417,792-byte (`0x66000`) protected allocation with SHA-256 `E49581067CC2AA5ABD09C8DF42D6FBD87CB064A9363FE8B52D8369FD1C51FFE5`, and applies `SetThreadContext` to the target primary thread before execution continues. This complete allocation is distinct from the 415,071-byte logical transformed record recovered from the carrier; the evidence does not assign a role to the additional 2,721 allocation bytes.

The clearest exemplar is Triage `260828-py7ysahr4y/behavioral1`: at approximately 2,703 ms, Tax Notice PID 952 creates x86 surrogate PID 844, performs 53 sandbox-labelled `WriteProcessMemory` events, produces a protected private region at `0x00440000` with length `0x66000`, and calls `SetThreadContext` for primary thread 4600. The package begins with a `CALL` that pushes the embedded Donut-instance address and transfers to terminal glue at record offset `0x627C5`.

That four-byte glue (`pop ecx; pop edx; push ecx; push edx`) recovers the instance pointer while preserving the caller return address. The following 11,647 bytes at offset `0x627C9` are an exact match for Donut `LOADER_EXE_X86` at commit `47758d787209dd1744f58c140102ac91b649df16`, SHA-256 `0C29CCCFF1B027D57C467564A333E9ADE455144649909A4B797B09B43002AC71`; 23 zero bytes follow. The whole 11,674-byte terminal region is therefore not itself the compared loader.

The parsed Donut instance uses exit option 3, no entropy/encryption, original entry point 0, 63 API hashes, dependency list `ole32;oleaut32;wininet;mscoree;shell32`, no requested AMSI/WLDP/ETW bypass, header overwrite, an embedded unmanaged executable, thread execution, no compression, and a 397,312-byte module matching executable A. Donut maps and starts A, which maps Launcher B. This independently closes the Donut attribution and call-return-address ABI.

The supported injection classification is remote package placement into a newly created suspended surrogate followed by primary-thread execution hijacking (`T1055.003`). The evidence does not establish original-image unmapping/replacement, a remote thread, or Donut network staging. The carrier's exact static call site/API responsible for Triage's normalized remote-write events and the exact instruction-pointer value installed by `SetThreadContext` remain unresolved.

## Persistence-mode comparison

The full-EXE analysis preserves `Tax_Notice_23665.exe` under `C:\ProgramData\NVIDIA Corporation\NvSvc\` and creates `\NvSvc` with that EXE as its action.

The direct-DLL analysis begins from `rundll32.exe …\nvdahelperremote.dll,#1`. Because that invocation bypasses the expected signed-host context, the carrier's self-location/install logic treats the sandbox host as its executable and persists a copied `rundll32.exe` without the DLL argument. That persisted action cannot replay the original DLL entry and is nonfunctional as captured.

Accordingly, `NvSvc -> Tax_Notice_23665.exe` is the intended full-chain persistence path. `NvSvc -> rundll32.exe` is a direct-DLL sandbox artifact/execution mode, not evidence of a second PackClient family variant. The directory name alone is not sufficient detection: a genuine NVIDIA installation may use NVIDIA-branded ProgramData paths.

## Historical network-indicator ledger

These are time-sensitive pivots from the consulted public reporting and sandbox evidence, not family-unique or presumed-live indicators:

| Indicator | Evidence class/context |
|---|---|
| `154[.]36[.]188[.]98:8080`, `206[.]238[.]196[.]96:6666`, `64[.]81[.]30[.]99` | Proofpoint/public campaign reporting |
| `192[.]252[.]180[.]45:6666` | Deception.Pro later PackClient/HOK reporting |
| `154[.]36[.]188[.]201:443` | July successful Launcher/Core sessions; August/September greeting-only retries |
| `192[.]229[.]87[.]219:8383` and `:8027` | Public campaign reporting |
| `gov12366[.]com`, `opkjhblll[.]cc` | Public campaign reporting |
| `xzz[.]cam` | July sandbox DNS activity and Core plaintext |

No detection recommendation here depends only on one infrastructure value.

## Detection and tooling consequences

- **Proofpoint/ET:** static object-magic rules cover the visible handshake markers but are sensitive to TCP segmentation and do not validate the ordered PLH1/PLC1/PLA1/PLK1 stream state or the Launcher-to-Core phase change. A stream-aware stateful signature is a genuine coverage improvement; another raw magic rule is duplicative.
- **Sigma #6280:** retain the high-confidence behavior join. Do not broaden it to generic `rundll32.exe` or the `NvSvc` directory alone; the observed direct-DLL persistence is a sandbox-induced nonfunctional replay. No recovered Core behavior requires a change to the submitted rule.
- **Wireshark dissector:** the repository Lua parser recognizes the Launcher handshake and PLK1 metadata in a flow-filtered derivative of historical Triage capture `260715-wd77daas7l/behavioral1`. That validates the Lua parser against real Launcher traffic; it does not by itself establish an exact build/TShark regression for the separate upstream C MR. A future revision should model the Launcher/Core phase boundary and the opposite type-`0x16` length endianness. This audit does not modify the open MR.
- **YARA:** a non-duplicative Core candidate requires PE structure plus all of `PackClientCore.dll`, `PackClientDll_Run`, and `PackClient_AllocStoredPluginImageW`, and at least three of `PackMonitorClient.PluginStore.v1`, `PackPlugin_GetFeatureId`, UTF-16 `PackPlugin.Registry.dll`, and `PackPlugin_BrowserMgr_TryHandleExtRemote`. An offline Python implementation of that exact byte-string/PE condition matched the raw Core and 352/352 mapped Core images while matching 0/86 mapped Launchers and 0/30 surrounding/non-PE allocations. No Core `.yar` file was compiled or run against that case corpus. This is strong within-case candidate separation, not YARA-engine or production validation; a representative benign and unrelated-malware corpus is still required.
- **Suricata:** new stateless rules for `PLH1`, `PLC1`, `PLA1`, `PLK1` or `PV10` would duplicate existing public coverage. The defensible new work is reassembly-aware ordering/state, with phase-aware Core handling. Observed non-duplicative sequence candidates are startup probe/response, preview enable/request/ack plus type-18 response, and keylogger-offline telemetry. Static-only plugin/update grammars still need positive fixtures and prevalence testing.

## Remaining boundaries

- No plugin binary was delivered or recovered.
- No second Core build, deployed Core `auth_psk`, or encrypted-Core packet was recovered.
- The external Launcher's `1RCP` peer and any bridge to Core `PV10` remain unidentified.
- The carrier's exact static remote-write call site/API and the precise instruction-pointer value installed by `SetThreadContext` remain unresolved.
- The C2/server implementation and challenge-generation code are not available.
- The September server non-response does not reveal whether infrastructure was inactive, gated or deliberately suppressing application responses.
- Representative benign-corpus measurements for proposed Core YARA and production false-positive rates for network/host rules have not been completed.
