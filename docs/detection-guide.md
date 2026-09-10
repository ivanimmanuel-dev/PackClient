# PackClient detection and hunting guide

PackClient is best detected by joining its sideload, persistence, surrogate-process, and protocol behavior. Individual filenames and paths overlap legitimate NVDA, NVIDIA, and Windows components and should be treated as pivots rather than standalone verdicts.

The repository provides:

- Sigma rules for the observed `NvSvc` task, a bare 32-bit `svchost.exe`, screenshot-worker mode, and active-session mode;
- a YARA rule for the recovered Launcher's marker constellation;
- Suricata rules that reproduce the plaintext Launcher handshake markers for local regression testing.

The rules under [`detections/`](../detections) are experimental. Their tests verify matching behavior but do not establish production accuracy.

## Host behavior

### Signed-host DLL sideload

Hunt for a signed NV Access/NVDA executable loading a colocated `nvdaHelperRemote.dll` from:

- a mounted image, archive extraction directory, download directory, or other user-writable location;
- `ProgramData` outside an approved NVDA installation;
- the process current directory when it differs from the installed NVDA directory.

Correlate the host and DLL paths, hashes, signatures, original filenames, parent process, current directory, and adjacent file creation. The DLL name is legitimate in normal NVDA installations and is not sufficient by itself.

### `NvSvc` scheduled task

The observed full-executable path created `\NvSvc` with an `ONLOGON` trigger, `HIGHEST` run level, and this target:

```text
C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe
```

High-signal combinations include:

- task name `NvSvc` with a target that is not NVIDIA-signed;
- the exact target directory above;
- creation by the staged host or a related process;
- `/Create`, `/TR`, `/SC ONLOGON`, and `/RL HIGHEST` in the same `schtasks.exe` command line;
- task creation within seconds of the host and companion DLL being staged.

Collect process creation, Task Scheduler Operational events, Security event 4698, task XML, target hashes, and signer data. A direct-DLL sandbox run instead scheduled a copied `rundll32.exe` without the original DLL argument; that nonfunctional replay does not justify a broad rule for generic `rundll32.exe` activity.

### Suspended 32-bit surrogate

The carrier creates `C:\Windows\SysWOW64\svchost.exe` suspended, places the protected package in it, changes the primary thread context, and resumes execution. In the retained Triage telemetry, one instance received 53 cross-process writes into a private region at `0x00440000` with length `0x66000` before `SetThreadContext`.

Prioritize a surrogate when several of these conditions occur together:

- the command line contains only the full `SysWOW64\svchost.exe` path;
- the parent is not `services.exe` or ordinary service-control infrastructure;
- it runs as an interactive user;
- its current directory points to a staging, download, or mounted-image location;
- private executable memory or thread start addresses do not map to ordinary loaded images;
- cross-process memory writes and primary-thread context changes precede execution.

The fixed address and write count are case anchors, not universal detection requirements. Process metadata alone does not establish the injection technique.

### Launcher execution modes

The recovered Launcher recognizes these exact controls:

```text
/scr_cap_worker <endpoint> [monitor-index]
-acsi
--active-session
```

`/scr_cap_worker` remains distinctive after file renaming. Pair `-acsi` and `--active-session` with Launcher image identity, original filename, or other PackClient behavior.

### Cache and update storage

Launcher Core-cache leads include:

```text
pluginsdata\x86\blobs\PackClientCore.primary.dll.pblob
pluginsdata\x86\meta\PackClientCore.primary.dll.json
```

Core's plugin cache uses paired files under:

```text
pluginsdata\x86\blobs\<name>.pblob
pluginsdata\x86\meta\<name>.json
```

Useful metadata and DPAPI markers include:

```text
PackMonitorClient.PluginStore
PackMonitorClient.PluginStore.v1
dpapi_current_user_v1
```

Core updates use current-user DPAPI under:

```text
HKCU\Software\PackMonitorClient\LauncherDllStore\<bits>\Primary
```

The cache filenames and markers are supporting evidence. No populated plugin cache or Core-update store was recovered from the observed executions.

## Memory and local IPC

For a suspicious surrogate, preserve private executable mappings, thread start addresses, thread context changes, loaded images, tokens, parentage, command line, current directory, and named-pipe handles.

The Launcher's local screenshot interface uses a 20-byte `1RCP` header. A structured match should require:

- little-endian magic `0x50435231` (`1RCP`);
- message type `1`, `2`, `3`, or `5`;
- positive width and height for types 1 and 2;
- zero payload length for READY or exactly `width × height × 4` bytes for a framebuffer.

A raw `1RCP` string match is weak without the surrounding fields. The full interface is documented in [Screenshot IPC](screenshot-ipc.md).

## Network detection

The Launcher handshake is plaintext inside the outer PackClient frame:

| Direction | Object | Exact prefix |
|---|---|---|
| Client → server | `PLH1` | `24 00 40 5A 15 00 00 00 50 4C 48 31` |
| Server → client | `PLC1` | `1C 00 40 5A 15 00 00 00 50 4C 43 31` |
| Client → server | `PLA1` | `2C 00 40 5A 15 00 00 00 50 4C 41 31` |
| Server → client | `PLK1` | `3C 00 40 5A 15 00 00 00 50 4C 4B 31` |

The first four bytes encode the outer body length and frame prefix. Prefer reassembled stream logic that validates the ordered `PLH1 → PLC1 → PLA1 → PLK1` exchange over isolated magic-string alerts. Normal TCP segmentation, coalescing, retransmission, and reordering can defeat packet-size assumptions.

The repository Suricata rules match the first three prefixes plus wire version 1 in reassembled TCP data.
Core screenshot responses use type 18 with:

```text
PV10 || LE32(JPEG length) || JPEG bytes
```

Launcher and Core both use outer type `0x16`, but the Launcher stores ciphertext length as big-endian while Core uses little-endian. Phase-aware inspection is required to interpret that shared type correctly, and encrypted Core traffic will hide plaintext commands.

## Core YARA candidate

A Core-specific YARA rule is not currently shipped. A useful starting condition requires PE structure plus all three of:

```text
PackClientCore.dll
PackClientDll_Run
PackClient_AllocStoredPluginImageW
```

and at least three of:

```text
PackMonitorClient.PluginStore.v1
PackPlugin_GetFeatureId
PackPlugin.Registry.dll                 (UTF-16)
PackPlugin_BrowserMgr_TryHandleExtRemote
```

This constellation separated the recovered Core from the Launcher and surrounding non-PE case material. It still requires testing against broad benign and unrelated-malware corpora before publication as a production rule.

## Historical network indicators

These values are historical pivots from public reporting and sandbox traffic. They are not family-unique and should not be treated as currently active infrastructure.

| Indicator | Source and context |
|---|---|
| `154[.]36[.]188[.]98:8080` | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient): Launcher payload host |
| `206[.]238[.]196[.]96:6666` | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient): PackClient C2 passed to the Launcher |
| `64[.]81[.]30[.]99` | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient): July post-compromise infrastructure; also recovered as a Launcher configuration value |
| `192[.]252[.]180[.]45:6666` | [Deception.Pro](https://blog.deception.pro/blog/new-packclient-hok-aug2026): PackClient C2 |
| `154[.]36[.]188[.]201:443` | Successful July Launcher/Core sessions and later greeting-only retries |
| `192[.]229[.]87[.]219:8383` and `:8027` | [Deception.Pro](https://blog.deception.pro/blog/new-packclient-hok-aug2026): attacker-operated ManageEngine Endpoint Central server, not PackClient C2 |
| `gov12366[.]com` | [Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient): initial delivery domain |
| `opkjhblll[.]cc` | [Deception.Pro](https://blog.deception.pro/blog/new-packclient-hok-aug2026): follow-on ManageEngine package host |
| `xzz[.]cam` | [Deception.Pro](https://blog.deception.pro/blog/new-packclient-hok-aug2026): secondary or fallback PackClient C2; also present in July sandbox traffic and Core plaintext |

Use these values as supporting pivots rather than standalone detections.

## Artifact hashes and filenames

| Artifact | SHA-256 |
|---|---|
| Campaign ZIP | `7108FF29916D064216AA2ECE7FB395F1E3A73D12D19895BFFC0BD46806CBF85A` |
| Staged IMG | `38EC1F5E23F65B10AE3027BEABFA0BF7F9FB686355A9E33C7E7E44E6A998E04C` |
| `Tax_Notice_23665.exe` | `93DD8B7B393289F88493596FAA4AE70054D9EB4FE47F2DD334F0C6BB5262F2A8` |
| `nvdaHelperRemote.dll` | `7295090C2CB63EBC43F932451971C41F9D015D2741E97AE3D9855F5AE87CFF94` |
| Protected injected allocation (417,792 bytes) | `E49581067CC2AA5ABD09C8DF42D6FBD87CB064A9363FE8B52D8369FD1C51FFE5` |
| Recovered Launcher B | `46B34789196733FAB62193F0AAEDB198B09F1362F9B10CA1DD70CF81D68B01AD` |
| Compressed PLK1 Core object | `502A7D2D72BEFA9114417936A1B3C2DD8EC84FCD4AE9EF9A09FFF3604FC05CCE` |
| Recovered `PackClientCore.dll` | `4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C` |
| Recovered Core `.text` | `F06FF7AB6D62B761344CAECBCC6857912F7543F43C0E5FF462D2174BADB0CA3F` |

Useful filename leads include:

```text
Tax_Notice_23665.exe
nvdaHelperRemote.dll
PackClientLauncher.exe
PackClientConsole.exe
PackClientCore.primary.dll.pblob
PackClientCore.primary.dll.json
```

Hashes identify this lineage only, and filenames are mutable.

## ATT&CK mapping

| Technique | PackClient behavior |
|---|---|
| [T1574.001 — DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) | Signed host resolves the colocated malicious helper DLL |
| [T1053.005 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/005/) | `NvSvc` at-logon persistence |
| [T1055.003 — Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/) | Remote package placement followed by primary-thread `SetThreadContext` and resume |
| [T1134.002 — Create Process with Token](https://attack.mitre.org/techniques/T1134/002/) | Active-session path duplicates and retargets a token for `CreateProcessAsUserW` |
| [T1113 — Screen Capture](https://attack.mitre.org/techniques/T1113/) | Launcher implements raw-BGRX `1RCP`; Core implements GDI/WIC capture and `PV10` JPEG output |

## Investigation checklist

1. Preserve the suspicious host, companion DLL, hashes, signatures, parentage, command lines, and image-load telemetry.
2. Export `\NvSvc` task XML and verify its creator, principal, trigger, run level, target, signer, and neighboring persistence.
3. Inspect bare `SysWOW64\svchost.exe` instances for their parent, user, current directory, private executable mappings, thread starts, and context changes.
4. Search the affected user profile and registry for Launcher/Core cache markers and paired `.pblob`/`.json` files.
5. Reassemble captured TCP streams and validate ordered Launcher framing before treating a magic string as PackClient.
6. Scope adjacent systems using behavioral joins first and historical hashes or infrastructure second.

## Limitations

- The included rules are hunting candidates; production false-positive and detection rates have not been measured.
- The Suricata rules recognize plaintext Launcher prefixes but do not validate the complete handshake, PLK1 body, or Core phase.
- The shipped YARA rule targets the recovered Launcher. The Core constellation above is not yet an included rule.
- The `1RCP` worker was reconstructed and tested synthetically, but no complete real worker exchange was captured.
- Exact hashes cover this lineage only; paths, filenames, task names, and infrastructure can change.
