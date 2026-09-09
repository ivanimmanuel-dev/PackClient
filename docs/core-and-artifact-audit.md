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
| [Proofpoint, *Carry-On Compromise: TA4922 Packs PackClient*](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) | Campaign anchor, family naming, prior protocol/plugin reporting and ET coverage | Public reporting, not independent validation of the artifacts below |
| [Deception.Pro, *New PackClient & HOK (Aug 2026)*](https://blog.deception.pro/blog/new-packclient-hok-aug2026) | Later PackClient/hands-on-keyboard and ManageEngine follow-on context | Public prior reporting; private backend artifacts were not available to this audit |
| [MalwareBazaar `7108FF…F85A`](https://bazaar.abuse.ch/sample/7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a/) | Public campaign ZIP identity and source of the Tax Notice lineage | Artifact identity only |
| Triage [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l/behavioral3) and [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) | Four complete PLK1 transfers in each run plus post-Core traffic | Historical sandbox observation; the filtered Wireshark capture is a derivative of `260715-wd77daas7l/behavioral1`, not another run |
| [Triage `260828-py7ysahr4y`](https://tria.ge/260828-py7ysahr4y) | Later public behavioral comparison | Sandbox observation |
| [Triage `260908-zwr5naybjb`](https://tria.ge/260908-zwr5naybjb) | Full-EXE and direct-DLL persistence comparison | Researcher-run sandbox observation |
| [Triage `260909-abma8sab28`](https://tria.ge/260909-abma8sab28) | One-hour repeat of the full-EXE path | Researcher-run sandbox observation |
| [Hybrid Analysis `7295090C…CFF94`](https://hybrid-analysis.com/sample/7295090c2cb63ebc43f932451971c41f9d015d2741e97ae3d9855f5ae87cff94/6a917e4b5211eca77507e3a8) | Carrier behavioral report and historical process evidence | Public sandbox report; unavailable downloads are not treated as recovered evidence |

The audit also reviewed the exact public revisions of [Sigma PR #6280](https://github.com/SigmaHQ/sigma/pull/6280) and [Wireshark MR !26404](https://gitlab.com/wireshark/wireshark/-/merge_requests/26404). Their retained source-snapshot identities in the LAB ledger are `507999AB2ED9A3B48714E62E97753D7BE65FCC7DF7285BEF4D69DB25F62BC2AE` for the Sigma diff, `74F546F4335F066BA3364CE707A7F310E8CC4C56A091EF6E3807EB7681BE4FC6` for `packet-packclient.c`, and `2C06F595794A2B2EF944224ABFCCC379904428933319934C629574B8110794B6` for its automated test group. No upstream submission is modified by this publication patch.

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

The recovered object identifies as `PackClientCore.dll`; its CodeView path ends in `\Project\Bin\Plugins\Win32\PackClientCore.pdb`. Its exported surface includes:

- `Main`, `MainMinimal`, `MainWithConfig` and `RunWithConfig`;
- `PackClientDll_AbiVersion`, `PackClientDll_Run`, and `PackClientDll_TrySystemSessionHandoff`;
- `PackClientDll_PluginStore_AllocImage` and `PackClientDll_PluginStore_FreeImage` wrappers;
- `ProbeEntry` and `RunDualWithConfig`.

The Launcher export-resolution order documented elsewhere is therefore confirmed against an independently reconstructed implementation.

## Historical successful transport

The July Triage captures progress through the complete Launcher delivery sequence:

```text
PLH1 (client) -> PLC1 (server) -> PLA1 (client) -> PLK1 (server)
```

The endpoint is `154[.]36[.]188[.]201:443`. The traffic is raw PackClient framing on TCP/443, not TLS. After Core delivery, the same historical captures contain bidirectional Core application traffic, including plaintext `INP` hello, `SYS` startup probe/response, `KTL OFFLINE`, screen-preview enable/request acknowledgements, and 15 type-18 `PV10` JPEG frames.

This establishes a successful historical C2/application session in those public runs. It does **not** establish that the September reruns succeeded: `260908-zwr5naybjb` and `260909-abma8sab28` completed TCP/greeting attempts but received no application response, so they show repeated PLH1 retries and no PLC1, PLK1, Core or plugin delivery.

## Core plugin system and missing plugin bytes

The Core contains two plugin-loading paths:

1. A modern ABI path resolves `PackPlugin_GetAbiVersion`, `PackPlugin_GetFeatureId` and `PackPlugin_OnLoad`, validates feature identity, and binds feature-specific host functions.
2. A legacy path resolves `Main` from a loaded plugin image.

Recovered feature contracts include screen/remote-screen, virtual desktop and fast-GUI bindings. The network grammar includes staged `Q|PLUGIN|…` requests and cache-store paths. These prove that the recovered Core can request, validate, cache and activate additional modules.

No plugin PE was present in the captured PLK1 transfers, mapped-memory census, cache artifacts or available dumped files. No `CLIENTCOREUPD` transaction was observed. The absence is scoped to the preserved evidence: the protocol and loader are present, but no plugin binary can be responsibly published or attributed from these runs.

## Built-in PV10 producer

Static reconstruction identifies the Core's built-in screenshot-preview path:

```text
GDI capture / StretchBlt / GetDIBits
  -> WIC JPEG encoding with ImageQuality
  -> bytewise PV10 serializer
  -> Core transport type 18
```

The serializer emits the `PV10` marker and matches all 15 historical type-18 frames. This establishes that Core itself produces the observed JPEG preview traffic. It does not prove that the Launcher's separate raw-BGRX `1RCP` worker feeds this path; the endpoint creator/consumer that would bridge those two interfaces remains missing.

## Core authentication and type-0x16 phase boundary

Core configuration includes local settings and an `auth_psk` path deriving 64 bytes with PBKDF2-HMAC-SHA-256, 100,000 iterations and salt `PackClientCore.AppAuth`, split into AES and HMAC material. Core's type-`0x16` record uses a little-endian ciphertext length. The Launcher's pre-Core type-`0x16` envelope uses a big-endian ciphertext length and separate unresolved key state.

The shared outer type number therefore does not imply one wire layout. Any parser or dissector must select the layout by protocol phase/connection state rather than attempting a single endian interpretation.

## Carrier closure

Static analysis of the signed host shows a direct imported call to `nvdaHelperRemote.dll!injection_initialize` at host RVA `0x1004`.

The carrier's surrogate path is now identified as section-backed local-to-remote mapping and primary-thread-context redirection:

1. create a pagefile-backed section with `NtCreateSection`;
2. map it into the carrier and suspended surrogate with `NtMapViewOfSection`;
3. copy the payload into the local view with `RtlCopyMemory`;
4. unmap the local view;
5. on the x64-to-WOW64 path, set the primary thread's EIP to the remote base with `Wow64SetThreadContext`;
6. resume the thread.

The terminal 11,674-byte stub is byte-identical to the pinned official Donut v1.1 loader family. Its call-return-address `pop` supplies the embedded loader/config pointer. This attribution is stronger than the earlier automated family label and replaces the previous unresolved wording.

## Persistence-mode comparison

The full-EXE analysis preserves `Tax_Notice_23665.exe` under `C:\ProgramData\NVIDIA Corporation\NvSvc\` and creates `\NvSvc` with that EXE as its action.

The direct-DLL analysis begins from `rundll32.exe …\nvdahelperremote.dll,#1`. Because that invocation bypasses the expected signed-host context, the carrier's self-location/install logic treats the sandbox host as its executable and persists a copied `rundll32.exe` without the DLL argument. That persisted action cannot replay the original DLL entry and is nonfunctional as captured.

Accordingly, `NvSvc -> Tax_Notice_23665.exe` is the intended full-chain persistence path. `NvSvc -> rundll32.exe` is a direct-DLL sandbox artifact/execution mode, not evidence of a second PackClient family variant. The directory name alone is not sufficient detection: a genuine NVIDIA installation may use NVIDIA-branded ProgramData paths.

## Detection and tooling consequences

- **Proofpoint/ET:** static object-magic rules cover the visible handshake markers but are sensitive to TCP segmentation and do not validate the ordered PLH1/PLC1/PLA1/PLK1 stream state or the Launcher-to-Core phase change. A stream-aware stateful signature is a genuine coverage improvement; another raw magic rule is duplicative.
- **Sigma #6280:** retain the high-confidence behavior join. Do not broaden it to generic `rundll32.exe` or the `NvSvc` directory alone; the observed direct-DLL persistence is a sandbox-induced nonfunctional replay. No recovered Core behavior requires a change to the submitted rule.
- **Wireshark dissector:** the real filtered July capture validates the Launcher parser on an independently captured positive flow. A future revision should model the Launcher/Core phase boundary and the opposite type-`0x16` length endianness. This audit does not modify the open MR.
- **YARA:** a Core rule based on multiple stable implementation anchors could be non-duplicative, but it requires a benign-corpus collision check before publication. A single export, PDB path, `PV10` string or plugin API name is too weak.
- **Suricata:** new stateless rules for `PLH1`, `PLC1`, `PLA1`, `PLK1` or `PV10` would duplicate existing public coverage. The defensible new work is reassembly-aware ordering/state, with phase-aware Core handling.

## Remaining boundaries

- No plugin binary was delivered or recovered.
- The external Launcher's `1RCP` peer and any bridge to Core `PV10` remain unidentified.
- The C2/server implementation and challenge-generation code are not available.
- The September server non-response does not reveal whether infrastructure was inactive, gated or deliberately suppressing application responses.
- Representative benign-corpus measurements for proposed Core YARA and production false-positive rates for network/host rules have not been completed.
