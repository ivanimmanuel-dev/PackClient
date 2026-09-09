# PackClient detection and hunting guide

Research cut-off: 2026-09-09 (UTC)

## Detection strategy

Prefer behavior joins over single strings or filenames. `svchost.exe` and `nvdaHelperRemote.dll` are legitimate names in normal contexts; the useful signal is their path, parentage, command line, signer/origin, and nearby persistence activity.

The repository includes the following detection rules under [`detections/`](../detections):

- Sigma rules for the observed `NvSvc` task, suspicious bare 32-bit service host, screenshot-worker mode, and active-session mode;
- a YARA rule for the recovered launcher's distinctive marker constellation;
- Suricata rules for candidate PLH1/PLC1/PLA1 frame prefixes and version bytes.

The included rules are experimental and should be validated against local telemetry and legitimate NVDA deployments.

## September audit decisions

| Candidate change | Decision | Reason |
|---|---|---|
| Broaden Sigma #6280 to generic `rundll32.exe` or the `NvSvc` directory | **Do not broaden** | The direct-DLL Triage task caused the carrier to copy/persist its sandbox host without the original DLL argument; that nonfunctional replay is an execution-context artifact, while NVIDIA-branded ProgramData paths can be legitimate |
| Add more stateless Suricata rules for `PLH1`, `PLC1`, `PLA1`, `PLK1` or `PV10` | **Do not add duplicates** | Public/ET and repository rules already cover the visible markers; another magic match does not fix segmentation or phase ambiguity |
| Add stream/transaction state | **High-value future work** | Historical captures validate the order `PLH1 -> PLC1 -> PLA1 -> PLK1`; reassembly-aware ordering is more discriminating and less packetization-sensitive |
| Add Core YARA | **Hold for corpus testing** | The recovered Core supplies a stable constellation, but exports, PDB fragments or `PV10` alone are not sufficient and a benign-collision study is still missing |
| Change the Wireshark MR | **Follow-up needed, not changed here** | The Launcher parser matches the positive July flow; Core reuses type `0x16` with the opposite ciphertext-length endianness, so decoding must be phase-aware |

## Correlated observations

| Signal | Evidence relationship |
|---|---|
| Staged signed host and colocated helper | Static sideload evidence; observed in the PID 5812 session |
| Bare 32-bit `svchost.exe` | Descendant in the PID 5812 process tree |
| `NvSvc` task creation | In the PID 5812 session, the process tree places task creation beneath that surrogate. In the PID 3696 session, elevated host PID 2116 creates both PID 3696 and `schtasks` PID 4600; the latter two are siblings. Task XML confirms the configured action. |
| `/scr_cap_worker` and session controls | Recovered launcher functionality; the worker was exercised separately and was not demonstrated as part of the preserved runtime chain |

Treat individual signals as pivots and correlate them with process ancestry, task creation, file activity, and runtime timing. Scope joins to the VM, time interval, and process creation identity (ProcessGuid where available), not a bare PID. The PID 3696 session shows an earlier unrelated PID 8248 before that number is reused for the later console child. Use lifecycle events or a live process view to confirm process lifetime. See [runtime validation](runtime-validation.md).

## Host pivots

### 1. NVDA helper sideload

Hunt for a signed NV Access/NVDA executable loading `nvdaHelperRemote.dll` from:

- user-writable directories;
- disk-image extraction/staging directories;
- `ProgramData` paths unrelated to an approved NVDA installation;
- the process current directory when it is not the installed NVDA directory.

Useful telemetry:

- process image path, signer, original filename, hash, parent, and current directory;
- image-load path/hash/signature status;
- adjacent file creation for the host and DLL;
- whether the DLL has the expected organization/signature for the deployed NVDA version.

False-positive control: `nvdaHelperRemote.dll` is a legitimate NVDA component name. Never alert on the filename alone.

### 2. `NvSvc` scheduled task

The observed task was named `\\NvSvc`, triggered at logon, and launched:

```text
C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe
```

High-signal conditions include:

- task name exactly `NvSvc` combined with a non-NVIDIA-signed target;
- a target under the exact `ProgramData` subdirectory above;
- creation by a recently staged executable or its descendant;
- `/SC ONLOGON` plus `/RL HIGHEST` in the creating command line;
- creation within seconds of the host/carrier pair.

Telemetry sources include process creation, Task Scheduler Operational events, Security 4698, and endpoint task inventories. Normalize XML before comparing quoted action paths.

### 3. Bare 32-bit `svchost.exe` surrogate

Prioritize a process when several of these hold:

- image is `C:\Windows\SysWOW64\svchost.exe`;
- command line is only the image path, without ordinary `-k`, `-s`, or COM-server arguments;
- parent is not `services.exe`/service-control infrastructure;
- user is an interactive user rather than the expected service identity;
- current directory points to a staging, download, mounted-image, or sample directory;
- start time aligns with the suspicious host/carrier or task creation;
- thread start addresses or executable mappings fall outside ordinary file-backed images.

Process metadata alone does not identify the injection subtype; memory mappings and thread starts provide the stronger discriminator.

### 4. Launcher special arguments

The recovered launcher recognizes exact controls including:

```text
/scr_cap_worker <endpoint> [monitor-index]
-acsi
--active-session
```

`/scr_cap_worker` is particularly distinctive even after launcher renaming. `-acsi` and `--active-session` are less distinctive and should be paired with launcher image or original-filename identity. The Sigma rules keep those behaviors separate so ATT&CK metadata follows the matched execution mode.

### 5. Cache and filesystem leads

Recovered cache strings describe a current-user protected layout containing:

```text
pluginsdata\x86\blobs\PackClientCore.primary.dll.pblob
pluginsdata\x86\meta\PackClientCore.primary.dll.json
```

and metadata markers:

```text
PackMonitorClient.PluginStore
PackMonitorClient.PluginStore.v1
dpapi_current_user_v1
```

The absolute base path was not resolved. Search user-profile and application-data locations, but treat filename/string hits as supporting evidence. The reconstructed active call path does not select the secondary slot.

## Memory and local IPC pivots

For a suspicious surrogate, useful collection targets include:

- mapped file list and signature status;
- virtual memory type/protection/size;
- thread start addresses and owning regions;
- process and thread token/session data;
- command line, parent, current directory, environment metadata, and handles;
- local named-pipe handles and peer PIDs where available.

A plausible `1RCP` header is 20 bytes:

| Offset | Field | Check |
|---:|---|---|
| `0x00` | magic | LE32 `0x50435231` / ASCII `1RCP` |
| `0x04` | type | `1`, `2`, `3`, or `5` in this worker |
| `0x08` | width | positive for types 1 and 2; impose an analyst size bound |
| `0x0C` | height | positive for types 1 and 2; impose an analyst size bound |
| `0x10` | payload length | zero for READY; exact `width * height * 4` for frame |

For requests of type 3 or 5, B ignores DWORDs 2–4. A raw `1RCP` string hit is weak; require the full 20-byte structure and field consistency.

## Network detection

The initial handshake is plaintext inside the verified outer frame. Exact stream prefixes are:

| Direction | Object | Exact prefix |
|---|---|---|
| client -> server | PLH1 | `24 00 40 5A 15 00 00 00 50 4C 48 31` |
| server -> client | PLC1 | `1C 00 40 5A 15 00 00 00 50 4C 43 31` |
| client -> server | PLA1 | `2C 00 40 5A 15 00 00 00 50 4C 41 31` |

The lengths encode `4-byte type + object size`. The Suricata rules additionally match little-endian version 1 and inspect reassembled TCP data at any buffer offset. In particular PLA1 follows PLH1 in the client stream; anchoring it with `startswith` can miss a coalesced buffer. These signatures match protocol prefixes rather than fully validating framing or HMAC state; TCP reassembly still matters.

The [Proofpoint IOC table](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) lists `154.36.188[.]201` as post-infection infrastructure for July 15, without a port. The preserved process dump separately records a timed-out attempt to that address on TCP/443. Historical July Triage captures additionally establish successful raw PackClient framing on the same endpoint, including the ordered Launcher handshake, PLK1 Core delivery and post-Core application traffic. Port 443 must not be labelled TLS without TLS records.

The filtered positive-flow PCAPNG validates the current Wireshark Lua dissector's Launcher-side recognition and PLK1 metadata on an independently captured stream. Its SHA-256 is `AB437D0EAE5E3C93764B89A3ECC5F6940D3CBEE0C2BE8D80D34CD7CB4CA38875`; it is a derivative of `260715-wd77daas7l/behavioral1`, not a separate collection.

### Proofpoint Emerging Threats coverage audit

The reviewed ET PackClient block, SIDs 2069878–2069890, covers representative greeting, challenge, authentication, PLK1, acknowledgement, basic Core status/heartbeat/information and `PV10`/JFIF objects. Several rules encode one observed packetization with `tcp-pkt` and exact `dsize` expectations. For example, SID 2069878 expects the four-byte frame word in a four-byte packet and SID 2069879 expects a 36-byte packet beginning with type `0x15` and `PLH1`; SIDs 2069880–2069883 make comparable split/size assumptions.

Normal TCP can split, coalesce, retransmit or reorder those bytes. The rules match the source captures' packetization but can miss the same protocol objects under another segmentation pattern. The non-duplicative transport improvement is reassembled stream/frame state with ordered `PLH1 -> PLC1 -> PLA1 -> PLK1` validation and deliberate retry thresholding, not another content rule for the same magic.

The reviewed rules do not semantically join higher-layer Core exchanges such as startup probe/response or preview enable/request/ack. Static `Q|PLUGIN|` staging and `Q|EXT|CLIENTCOREUPD|` are distinctive research surfaces, but no corresponding live transaction was captured; they should not become upstream raw-wire signatures without a positive fixture, phase/flow design and benign-prevalence testing. Core `auth_psk` can also wrap later messages in type `0x16`, defeating plaintext-only command matches.

### Non-duplicative YARA boundary

A reconstructed-Core candidate separated all 352 mapped Core records from 86 within-case non-Core records in the retained audit corpus. That is useful internal discrimination, not production validation. A publishable rule should combine several implementation anchors—rather than a single export, PDB suffix, plugin API or `PV10` literal—and must be checked against a broad benign corpus first. The main repository therefore records the candidate direction without presenting an unvalidated new rule as production-ready.

## Hash and filename IOCs

| Artifact | SHA-256 | Confidence/source |
|---|---|---|
| Campaign ZIP | `7108FF29916D064216AA2ECE7FB395F1E3A73D12D19895BFFC0BD46806CBF85A` | Exact public/research lineage |
| Staged IMG | `38EC1F5E23F65B10AE3027BEABFA0BF7F9FB686355A9E33C7E7E44E6A998E04C` | Exact artifact identity |
| `Tax_Notice_23665.exe` | `93DD8B7B393289F88493596FAA4AE70054D9EB4FE47F2DD334F0C6BB5262F2A8` | Exact host identity |
| `nvdaHelperRemote.dll` | `7295090C2CB63EBC43F932451971C41F9D015D2741E97AE3D9855F5AE87CFF94` | Exact carrier identity |
| Embedded launcher B | `46B34789196733FAB62193F0AAEDB198B09F1362F9B10CA1DD70CF81D68B01AD` | Static reconstruction; derived bytes not published |
| Reconstructed `PackClientCore.dll` | `4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C` | Eight identical historical PLK1 transfers |
| Reconstructed Core `.text` | `F06FF7AB6D62B761344CAECBCC6857912F7543F43C0E5FF462D2174BADB0CA3F` | Exact match across 352 mapped Core images |

Filename leads:

- `Tax_Notice_23665.exe`
- `nvdaHelperRemote.dll`
- `PackClientLauncher.exe`
- `PackClientConsole.exe`
- `PackClientCore.primary.dll.pblob`
- `PackClientCore.primary.dll.json`

Names are mutable and should not be the only detection condition.

## ATT&CK mapping

| Technique | Mapping | Confidence |
|---|---|---|
| [T1574.001 — DLL](https://attack.mitre.org/techniques/T1574/001/) | Signed host resolves malicious colocated helper DLL | Confirmed |
| [T1053.005 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/005/) | `NvSvc` at-logon persistence | Confirmed in runtime evidence |
| [T1113 — Screen Capture](https://attack.mitre.org/techniques/T1113/) | GDI worker and BGRX response contract | Confirmed implementation; live frame not completed |
| [T1134.002 — Create Process with Token](https://attack.mitre.org/techniques/T1134/002/) | Duplicated/retargeted token passed to `CreateProcessAsUserW` | Confirmed implementation |
| [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/) | Carrier creates a section, maps it locally and remotely, copies into the local view, redirects the suspended surrogate's primary thread and resumes it | Confirmed at parent-technique level; avoid over-specific hollowing terminology |

## Triage order

1. Preserve process/task/image-load metadata and hashes.
2. Verify the target/signer/path of `\\NvSvc`, neighboring tasks, Startup Apps entries, Run/RunOnce values, and user/common Startup folders. The runtime record shows an enabled Startup Apps entry but does not identify its backing registration.
3. Inspect bare/unusual `svchost.exe` instances for parent, user, current directory, modules, private executable memory, thread starts, and named mutants matching `PackClientLauncher.Session.*`.
4. Search for the exact host/carrier pair and cache markers across the affected user profile.
5. Decode already-acquired captures with the passive tools.
6. Scope adjacent hosts using behavior joins first, historical hash/IOC matches second.

## Rule limitations

- Suricata rules assume the listed prefix is contiguous in the normalized TCP stream; sensor configuration matters.
- Existing object-magic coverage can miss split/coalesced sequences or lose the ordered state between Launcher and Core. Stream-aware state is the non-duplicative improvement.
- Launcher and Core type `0x16` records use different ciphertext-length byte order; phase-blind parsing can misdecode Core traffic.
- Sigma field names and command-line normalization vary by backend.
- YARA marker rules identify a code/data constellation, not a campaign actor by themselves.
- Sigma regex/backend semantics must be checked on the destination platform. The bare-svchost rule expects an absolute drive path; aliases, environment-variable paths, and missing parent telemetry are coverage limits.
- The screenshot-worker rule accepts its distinctive token after renaming. Active-session tokens additionally require image/original-filename identity. Similarly named unrelated programs can still match.
- Tests use synthetic positive/negative examples, not the original malware or a representative benign deployment corpus. Production false-positive and detection rates have not been measured.
- Exact hashes cover this lineage only.
