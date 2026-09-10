# PackClient Core

`PackClientCore.dll` is the 32-bit runtime delivered by Launcher B after authentication. Historical PLK1 traffic reconstructs it byte-for-byte and then continues into captured Core commands and screenshot frames. The earlier loading chain is described in [Launcher architecture](launcher-architecture.md), while process and persistence observations are documented in [Runtime analysis](runtime-analysis.md).

## Recovery from PLK1

Historical PLK1 traffic reconstructs a 985,088-byte x86 `PackClientCore.dll`. Triage tasks [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l) and [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) each contain four repeated complete transfers of the same object. Every copy produces identical Core bytes.

Each PLK1 v2 transfer carries a 669,717-byte raw-LZ4 object in eleven ordered type-`0x15` chunks: ten 65,536-byte chunks followed by a 14,357-byte chunk. The compressed object has SHA-256:

```text
502A7D2D72BEFA9114417936A1B3C2DD8EC84FCD4AE9EF9A09FFF3604FC05CCE
```

Decompression produces a 985,088-byte PE32 DLL matching the plaintext SHA-256 declared by every transfer:

```text
4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C
```

A comparison against 352 memory records from eight Core processes found the same 753,664-byte `.text` identity in every case:

```text
F06FF7AB6D62B761344CAECBCC6857912F7543F43C0E5FF462D2174BADB0CA3F
```

## Core identity and exports

The recovered object identifies itself as `PackClientCore.dll` and contains the CodeView path:

```text
\Project\Bin\Plugins\Win32\PackClientCore.pdb
```

| Property | Value |
| --- | --- |
| Architecture | PE32 / IA-32 |
| File size | 985,088 bytes |
| Preferred image base | `0x10000000` |
| Image size | 1,114,112 bytes |
| Entry RVA | `0x81502` |
| Timestamp | `0x6A3F4861` |
| Sections | `.text`, `.rdata`, `.data`, `.fptable`, `.rsrc`, `.reloc` |

The entry point performs standard DLL initialization.

All 11 exports are identified:

| Ordinal | Export | RVA | Role |
| ---: | --- | ---: | --- |
| 1 | `Main` | `0xC0BD` | Main runtime |
| 2 | `MainMinimal` | `0xC23C` | Probe returning 7 |
| 3 | `MainWithConfig` | `0xC240` | Stores two endpoint configurations and enters `Main` |
| 4 | `PackClientDll_AbiVersion` | `0x232B` | Returns ABI version 1 |
| 5 | `PackClientDll_Run` | `0x232F` | Launcher configuration-view entry |
| 6 | `PackClientDll_TrySystemSessionHandoff` | `0x2761` | Active-session handoff entry |
| 7 | `PackClient_AllocStoredPluginImageW` | `0x19C6F` | Allocates a stored plugin image |
| 8 | `PackClient_FreeStoredPluginImage` | `0x19D4D` | Releases a stored plugin image |
| 9 | `ProbeEntry` | `0xC459` | Probe returning 1234 |
| 10 | `RunDualWithConfig` | `0xC45F` | Dual-endpoint startup |
| 11 | `RunWithConfig` | `0x276D` | Single-endpoint startup |

The session-handoff export is examined separately in [Active-session handoff](active-session-handoff.md).

## Launcher-to-Core ABI

`PackClientDll_Run(view, flags)` interprets the Launcher-supplied view as follows:

| Offset | Core interpretation |
| ---: | --- |
| `+0x00` | Required nonempty host pointer |
| `+0x04` | Required nonzero 16-bit port |
| `+0x08` | Group pointer; absent or empty becomes `default` |
| `+0x0C` | Optional tag pointer |
| `+0x10` | Optional configuration-string pointer |

Before dispatch, Launcher requires either `RunWithConfig` or `Main` to exist. A DLL exposing only `PackClientDll_Run` therefore fails this initial gate.

After the gate, Launcher requires ABI version 1, prefers `RunWithConfig`, otherwise calls `PackClientDll_Run(view, 0)`, and finally falls back to `Main`.

## Core transport

`RunWithConfig` starts one `S1` link, while `RunDualWithConfig` maintains separate `S1` and `S2` endpoint states. Core implements reconnect, heartbeat, and periodic DNS re-resolution; `uplink_dns_poll_sec` defaults to 300 seconds.

## Historical Core traffic

After PLK1 delivery, the July sessions continued into bidirectional plaintext Core traffic with `154[.]36[.]188[.]201:443`. Despite the port number, the captured connection carried raw PackClient traffic rather than TLS.

Representative messages include:

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

Observed type-11 messages carry host inventory, including the Windows version, local and C2 addresses, group, timestamp, desktop title, and device identifier.

Captured Core traffic included startup commands, host inventory, offline-keylogger status, preview control, and 15 type-18 `PV10` JPEG frames. No Core type-`0x16`, plugin-delivery, Core-update, or ETCHOOK messages were observed.

## Configuration and application encryption

Core reads six local settings:

| Section | Key | Default | Role |
| --- | --- | ---: | --- |
| `pack` | `fragment_assembler_max_mb` | 0 | Fragment-assembler size override |
| `pack` | `uplink_dns_poll_sec` | 300 | DNS re-resolution interval |
| `pack` | `tls_ca_path` | empty | Optional CA path |
| `pack` | `tls_skip_verify` | 0 | TLS-verification bypass |
| `pack` | `auth_psk` | empty | Optional Core application PSK |
| `preview` | `enabled` | 1 | Built-in preview gate |

When `auth_psk` is absent or empty, Core clears its crypto-ready flag and zeroes both application keys. Otherwise it derives separate AES and HMAC keys:

```text
AES_key  = SHA256(ASCII("PACKAPP|AES256|v1|") || raw_auth_psk_bytes)
HMAC_key = SHA256(ASCII("PACKAPP|HMAC|v1|")   || raw_auth_psk_bytes)
```

This PSK is separate from Launcher handshake authentication. Core's application-key derivation is recovered; the source of Launcher's earlier envelope keys remains unresolved.

Core's authenticated type-`0x16` body is:

```text
+0x00      u8        version = 1
+0x01      bytes[16] random IV
+0x11      u32le     ciphertext length C
+0x15      bytes[C]  AES-256-CBC ciphertext
+0x15+C    bytes[32] HMAC-SHA-256
```

The IV is generated through `BCryptGenRandom`. The total envelope length is `C + 0x35`, and the HMAC covers:

```text
version || IV || LE32(C) || ciphertext
```

Core verifies the HMAC before AES-CBC decryption. Outbound wrapping encrypts the complete original Core message—its 32-bit type followed by its payload—except messages already typed `0x15` or `0x16`. After authenticated decryption, the first four plaintext bytes are redispatched as the inner Core message type.

Launcher's pre-Core type-`0x16` format instead stores the ciphertext length as big-endian and only accepts inner type `0x15`. The two formats remain distinct despite sharing the same outer type.

## Plugin system

### Loading contracts

Core supports a modern ABI-aware loader and an older `Main`-export loader.

The modern loader requires `PackPlugin_GetFeatureId`. The returned feature must be one of the 11 supported identifiers, and an optional requested-feature filter must match it.

`PackPlugin_GetAbiVersion` is optional, but must return 1 when present. `PackPlugin_OnLoad` is called when exported, and unload paths reference `PackPlugin_OnUnload`.

The screen, virtual-desktop, and fast-GUI features additionally require their feature-specific `BindHostAtomics` export. An invalid ABI, unsupported feature, feature mismatch, or missing required binding causes the image to be rejected and unloaded.

The canonical feature mapping is:

| Feature | Canonical DLL |
| --- | --- |
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

Core also classifies `screenblank` and `openh264*.dll` as `remote_screen`, `webcam` as `remote_video`, and `turbojpeg*.dll` as `fast_gui_screen`. The codec DLLs may therefore be supporting files rather than standalone plugins.

The older loader maps a supplied PE from memory, resolves the literal export `Main`, verifies through `VirtualQuery` that the export belongs to the mapped image, and starts it in a new thread.

### Delivery and execution paths

Core implements four related workflows:

1. Modern staged plugin delivery.
2. Legacy one-message delivery.
3. Cached `kind=extra` execution.
4. Separate `kind=uprun` executable launch.

Modern `Q|PLUGIN|op=2` delivery follows:

```text
init → chunk → commit
```

The transaction carries:

- `rid`, echoed in responses;
- optional `tid`, which replaces `rid` as the internal transaction key;
- `name64`, decoded and normalized to `[A-Za-z0-9._-]` with a length of 1–160 bytes;
- required plaintext MD5;
- optional plaintext SHA-256;
- original size from 1 byte through 128 MiB;
- compressed size from 1 byte through 256 MiB;
- chunk offset and base64 data.

Staged delivery uses raw LZ4. Reusing a transaction with conflicting metadata is rejected.

Chunks are ordered and idempotent. Exact retransmission is accepted as a duplicate, matching overlap appends only the new tail, future offsets are rejected, conflicting overlap is rejected, and data exceeding the declared compressed size is rejected. Progress responses report the next expected offset.

Commit requires the exact compressed length, successful decompression to the declared size, MD5 agreement, and SHA-256 agreement when supplied.

Legacy `op=2` accepts a complete base64-encoded LZ4 or zlib object in one message. Cached `kind=extra` execution retrieves stored bytes and enters the older `Main` loader. `kind=uprun` writes and launches an executable and is not a plugin-DLL variant.

### Storage and activation

Delivered plugin images are checked as x86 PEs before storage or activation.

OpenH264 and TurboJPEG sidecars are stored without being loaded directly and invalidate the associated screen runtime so it can be rebuilt around the new sidecar. Some primary plugins are registered as `registry_only` until later activation. Other plugins can load immediately when their feature is not already busy.

Successful activation reports `phase=runtime_ready`. A nonreplaceable active feature returns `busy` instead of being hot-swapped.

Plugin operation 1 advertises staged-delivery support through `caps=put_stage`. Operation 4 creates a feature-specific physical channel with a default TTL of 300 seconds and can return a channel ID, session key, expiry, and peer endpoint. Operation 5 authenticates that channel using the feature, channel ID, nonce, and HMAC fields. None of these physical-channel operations appears in the captured traffic.

### Plugin cache

The file-backed plugin cache uses current-user DPAPI with:

```text
Description: PackMonitorClient.PluginStore
Entropy:     PackMonitorClient.PluginStore.v1
Flags:       CRYPTPROTECT_UI_FORBIDDEN
```

Its root is derived from the host executable directory. When the directory ends in `Launcher\x64` or `Launcher\Win32`, Core moves two directories upward before appending the plugin-store path.

The primary x86 layout is:

```text
<root>\pluginsdata\x86\blobs\<normalized-file>.pblob
<root>\pluginsdata\x86\meta\<normalized-file>.json
```

The legacy layout omits the `x86` component. A valid legacy pair is migrated into the primary layout and removed from the fallback location.

Writes use a temporary file, flush it, and replace the destination with write-through. Metadata follows this schema:

```json
{"version":1,"file":"%s","md5":"%s","machine":%u,"enc":"dpapi_current_user_v1","blob":"%s","root":"%s"}
```

Loading requires the paired `.pblob` and JSON files, the original user's DPAPI context, matching MD5, and the expected PE machine. A `.pblob` alone is insufficient.

This MD5- and machine-tagged plugin cache is separate from Launcher's SHA-256 Core cache. Protocol responses containing `store=registry` refer to Core's internal module registry, not the Windows Registry.

### No recovered plugin binaries

The Core file ends with its final PE section and contains no secondary PE or overlay. No plugin DLL or sidecar was recovered from the available traffic, process memory, or cache artifacts. The sections above describe code paths implemented by Core, not observed plugin execution.

## Core updates

`Q|EXT|CLIENTCOREUPD|op=check` loads the locally stored object and reports whether it is missing, current, has an invalid MD5, or requires replacement.

`op=put` receives the update through the existing command channel. It requires:

- a 32-character plaintext MD5;
- `lz4` or `zlib` compression;
- a declared decompressed size from 1 byte through 128 MiB;
- base64-encoded compressed data.

Core decodes and decompresses the object, verifies its size and MD5, and protects it with current-user DPAPI. WinHTTP is used by other download commands and is not the delivery mechanism for this branch.

The command-supplied `bits` value selects the registry subkey:

```text
HKCU\Software\PackMonitorClient\LauncherDllStore\<bits>\Primary
```

DPAPI parameters are:

```text
Description: PackMonitorClient.LauncherDllStore
Entropy:     PackMonitorClient.LauncherDllStore.Primary.v1
```

| Value | Stored data |
| --- | --- |
| `sha256` | Plaintext SHA-256 |
| `enc` | `dpapi_v1` |
| `sz` | Protected-byte count |
| `n` | Number of chunks |
| `p%u` | Protected binary chunks of at most `0x80000` bytes |

The older `Q|COREUPD|CHECK|` path reads the same store. No Core-update transaction appears in the captured traffic.

## Built-in PV10 screenshot producer

Core contains its own screenshot-preview implementation:

```text
GDI desktop capture and scaling
    → WIC JPEG encoding
    → PV10 serialization
    → Core message type 18
```

The relevant functions are:

- RVA `0x23B4F`: GDI capture and scaling through `StretchBlt` and `GetDIBits`;
- RVA `0x231AC`: WIC JPEG encoding;
- RVA `0x236D0`: bytewise `PV10` serialization;
- RVA `0x241ED`: normal thumbnail path;
- RVA `0x22C39`: adaptive `VIEW` encoding;
- RVA `0x313B3`: preview-request dispatch;
- RVA `0x24173`: preview acknowledgement formatting.

The serializer emits:

```text
"PV10" || LE32(JPEG length) || JPEG bytes
```

The normal thumbnail path limits the largest dimension to 160 pixels and uses JPEG quality 35. The adaptive `VIEW` path adjusts dimensions and quality until the result fits the requested size limit.

All 15 historical type-18 frames match this format: the declared little-endian length equals the payload length minus eight, and each image begins with a valid JFIF/JPEG header.

Core therefore produces the observed `PV10` frames directly. No connection to Launcher's separate raw-BGRX `1RCP` worker was recovered; that interface is described in [Screenshot IPC](screenshot-ipc.md).

## Commands and capabilities

The recovered handlers include:

- file walking, properties, upload, download, search, status, and execution;
- process, startup-item, scheduled-task, and registry operations;
- shell commands, elevation, power control, wake-screen, and UAC-related operations;
- process-guardian synchronization and process/window filtering;
- plugin delivery, cached execution, payload execution, and Core updates;
- screen capture, remote input, viewport, quality, keyframe, and preview control;
- virtual-desktop installation, startup, creation, cleanup, and execution;
- keylogger start, stop, synchronization, clipboard telemetry, and offline archives;
- TCP and UDP channels, proxy traffic, admin forwarding, and webcam handling;
- browser-manager and Telegram-tool plugin delegation;
- `PIPE|FGUI|`, `PIPE|PHYS|`, and `PIPE|990|` channels.

Only startup, inventory, offline-keylogger status, preview control, and screenshot delivery appear in captured traffic; the remaining capabilities were recovered through static analysis.

### ETCHOOK clipboard replacement

Core reads ANSI and Unicode clipboard text, applies configured regular expressions, replaces matching values, empties the clipboard, and writes both Unicode and ANSI replacements.

Its built-in patterns cover address formats consistent with Bitcoin mainnet and testnet, Litecoin, `t1` and `t3`, NEAR, ICP, Ethereum-style `0x` addresses, and `cro1`.

`Q|EXT|ETCHOOK|PERCLIENT|` supports state queries and per-client `regex_b64` and `repl_b64` values. `Q|EXT|ETCHOOK|SYNC|` accepts a bulk base64 rule object.

[Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) previously identified PackClient's clipboard-replacement capability. Analysis of this Core build adds the built-in patterns and the `PERCLIENT` and `SYNC` control formats. ETCHOOK does not appear in the captured traffic.

Historical infrastructure and detection guidance are available in the [Detection guide](detection-guide.md).
