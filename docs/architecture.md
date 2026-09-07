# Launcher architecture and lineage

This document describes the recovered July 2026 Tax Notice build. All code locations are relative virtual addresses (RVAs) within Executable B unless explicitly attributed to another component. Internal function names are analyst role labels. Runtime observations are documented in [runtime validation](runtime-validation.md).

## Component identities

| Component | Size, bytes | SHA-256 |
|---|---:|---|
| Campaign ZIP | 248,759 | `7108FF29916D064216AA2ECE7FB395F1E3A73D12D19895BFFC0BD46806CBF85A` |
| `Tax_Notice_23665.img` | 641,024 | `38EC1F5E23F65B10AE3027BEABFA0BF7F9FB686355A9E33C7E7E44E6A998E04C` |
| Signed host, `Tax_Notice_23665.exe` | 120,984 | `93DD8B7B393289F88493596FAA4AE70054D9EB4FE47F2DD334F0C6BB5262F2A8` |
| Carrier, `nvdahelperremote.dll` | 455,527 | `7295090C2CB63EBC43F932451971C41F9D015D2741E97AE3D9855F5AE87CFF94` |
| Transformed package | 415,071 | `0419AE7381CAA97172C40F5AEA601B8A22F1F58D27F3930509AF5808E043F65E` |
| Executable A, wrapper/mapper | 397,312 (`0x61000`) | `28B8EB812E0F0AB724475BD51E3DC1F618BCB08B05998C414D4193009BF8D598` |
| Executable B, `PackClientLauncher.exe` | 271,872 (`0x42600`) | `46B34789196733FAB62193F0AAEDB198B09F1362F9B10CA1DD70CF81D68B01AD` |

The verified IMG traversal contains exactly the host and carrier: carrier extent `0xF000`, host extent `0x7E800`. The host is an AMD64 NVDA/NV Access executable importing `nvdaHelperRemote.dll` by bare filename. The malicious colocated DLL uses a legitimate helper name. This supports a DLL search-order sideload configuration, subsequently corroborated by a runtime `Load Image` event. See [NV Access's helper documentation](https://github.com/nvaccess/nvda/blob/master/nvdaHelper/readme.md) and [MITRE T1574.001](https://attack.mitre.org/techniques/T1574/001/).

## Carrier and transformed package

The carrier is PE32+ AMD64, with five sections, entry RVA `0x2AE4`, and export-library name `nvdaHelperRemote_v16_5.dll`. Its exports are `injection_initialize` at carrier RVA `0x1EC0` and `injection_terminate` at `0x1ED0`. Names alone do not prove which export was invoked.

Three carrier call sites establish its process-creation contracts:

| Carrier RVA | Recovered call and arguments | Role |
|---|---|---|
| `0x1656` | `CreateProcessW`, null application name, command built from `schtasks /Create /TN NvSvc /TR … /SC ONLOGON /RL HIGHEST /F` | Creates the logon task |
| `0x18E2` | `ShellExecuteExW`, verb `runas`, current module path, null parameter and directory fields | Requests self-elevation |
| `0x1BEB` | `CreateProcessW`, `System32`/`SysWOW64` `svchost.exe` path, null command line, flags `0x08000004` (`CREATE_NO_WINDOW` plus `CREATE_SUSPENDED`) | Creates a suspended surrogate |

The last call's returned handles feed the native/WOW64 thread-context get/set and `ResumeThread` sequence in the carrier function at `0x1900`. These static paths support the task, elevation and bare-surrogate observations in [runtime validation](runtime-validation.md). The exact upstream code-placement primitive and its runtime invocation remain unresolved. None of the three launch sites constructs a screenshot-worker invocation or transfers its endpoint.

The carrier reads its own or same-directory file through a whole-file read-only mapping. The recovered path uses `GetModuleFileNameW` at carrier RVA `0x1156`, the same-buffer call at `0x1165`, and mapping function `0x2100`. It calculates the maximum PE section raw end, `0x4E00`, and reads the appended record there.

| Carrier file range, half-open | Purpose |
|---|---|
| `0x00000–0x04E00` | Conventional mapped PE headers and sections |
| `0x04E00–0x04E08` | LE32 key `0x70`; LE32 record length `0x6555F` |
| `0x04E08–0x6A367` | Record transformed bytewise with XOR `0x70` |
| `0x6A367–0x6F367` | Separate opaque `0x5000`-byte suffix; purpose unresolved |

The header bytes are `70 00 00 00 5F 55 06 00`. The deterministic transform produces the package hash above. The earlier long printable `0x70` run becomes NUL padding; constant XOR preserves entropy. The separate `0x5000`-byte suffix remains unresolved; its SHA-256 is `CA34888C3172DA092E4FFF700C4018C3FC1182BEE6B955C66B430B6FF77176B1`.

| Transformed-record range | Interpretation |
|---|---|
| `0x00000–0x00005` | Leading `E8 rel32` with displacement `0x627C0` |
| `0x00005–0x627C5` | Call-over-data span; its first DWORD repeats `0x627C0` |
| `0x0128D–0x6228D` | Executable A |
| `0x01CC1–0x442C1` | Executable B, nested inside A's `.rdata` |
| `0x6228D–0x627C5` | `0x538` bytes of NUL padding |
| `0x627C5–0x6555F` | Terminal x86 loader candidate, 11,674 bytes |

The terminal-loader ABI was not recovered. The call-over-data structure is compatible with multiple packagers, and `donut` appears only in the configuration data; the package is therefore not attributed to Donut here.

## A maps B inside the current process

A is a native PE32 x86 executable with three sections, timestamp `0x6A27AE4B`, entry RVA `0x1308`, preferred base `0x400000`, and image size `0x64000`.

At A RVA `0x2000`, the 52-byte prefix preceding B comprises ten import-thunk DWORDs (nine entries plus terminator), `PACKPAY1` at `0x2028`, and B's raw size `0x42600` at `0x2030`. B begins at A RVA `0x2034`.

A validates that descriptor and B's PE headers, allocates the declared image size, copies file-backed headers/sections, applies relocations, resolves imports, handles a TLS directory if present, and applies section protections. A calls the mapped entry at A RVA `0x145F`; B has no TLS directory. A performs this mapping in its own process. How the upstream chain placed and started A inside the surrogate remains unresolved.

## B identity and coordinate map

B is a native PE32 x86 GUI executable with six sections, timestamp `0x6A3CB0B5`, entry RVA `0x12FAC`, preferred base `0x400000`, and image size `0x48000`. Its export library identifies `PackClientLauncher.exe`; its CodeView record has GUID `EDD31459-13E4-4218-B638-FE7CF8F51C25`, age 1, and PDB suffix `\Project\Bin\Launcher\Win32\PackClientLauncher.pdb`. The PDB path is build metadata, not an available symbol file.

| Section | RVA | Virtual size | B-relative raw range |
|---|---:|---:|---|
| `.text` | `0x1000` | `0x2E836` | `0x00400–0x2EE00` |
| `.rdata` | `0x30000` | `0x10520` | `0x2EE00–0x3F400` |
| `.data` | `0x41000` | `0x1A9C` | `0x3F400–0x40000` |
| `.fptable` | `0x43000` | `0x80` | `0x40000–0x40200` |
| `.rsrc` | `0x44000` | `0x1E0` | `0x40200–0x40400` |
| `.reloc` | `0x45000` | `0x218C` | `0x40400–0x42600` |

For a B raw offset, transformed-record offset is `raw + 0x1CC1`; carrier correspondence is `raw + 0x6AC9`. This conversion refers to the XOR-transformed correspondence, not identical carrier bytes.

## Configuration and Core dispatch

A conditionally reads `PACK_MT_LAUNCH_ARGS` into a `0x200`-byte buffer. Its bridge at A RVA `0x119D` parses up to three whitespace-delimited tokens and sets `PACK_LAUNCH_PULL_HOST`, `PACK_LAUNCH_PULL_PORT`, and `PACK_LAUNCH_GROUP`. The source literals `154[.]36[.]18`, `6666`, and `donut` seed buffers, but parsing overwrites each field and writes an empty string at end-of-input. Runtime values can overwrite these seed literals through the environment/configuration path described below.

B's loader at `0xCBA2` accepts nonempty environment overrides. Port is decimal and accepted only in `1..65535`.

| B configuration offset | Role | Recovered initialization |
|---:|---|---|
| `+0x00` | Pull host string | `64[.]81[.]30[.]99`, with fallback literal `154[.]36[.]18`; nonempty host environment override |
| `+0x18` | Pull port, uint16 | 6666, then valid nonempty port environment override |
| `+0x1A` | Core-facing port | Copied from pull port |
| `+0x1C` | Optional Core host | Empty |
| `+0x34` | Stable normalized-host storage | Populated when constructing the Core view |
| `+0x4C` | Group string | `Default`, or nonempty group environment override |
| `+0x64` | Tag string | Empty |
| `+0x7C` | Config string | Empty |

Main calls pull at `0x484A`, then retries at `0x4875` after 1,500 ms on failure; both calls request slot 0. On success, `0x4938` passes `vector.begin` and `vector.end - vector.begin` to PE wrapper `0x10591`, which calls `MemoryLoadLibraryEx` at `0x10136`. PE checks enforce `MZ`, bounded `e_lfanew`, `PE\0\0`, and PE32 magic before mapping. The vector's [PLK1/cache provenance](protocol-reference.md#plk1-delivery-and-cache) is integrity checked and its use matches the expected Core role, but no independent Core image or hash was recovered.

The launcher resolves `PackClientDll_AbiVersion`, `PackClientDll_Run`, `RunWithConfig`, and `Main`. A present ABI function must return 1. Main requires at least `RunWithConfig` or `Main`, even though it also resolves the Run entry. The five-field view contains host, port, group, optional tag, and optional config; `::1` or `[::1]` is normalized to the fallback host literal. Selector `0x2E2A` prefers:

1. `RunWithConfig(host, port, group, tag, config)` when available with a view;
2. otherwise `PackClientDll_Run(config_view, 0)`;
3. otherwise `Main()`.

The lookup wrapper first tries the name, then `_<name>@0`, then a bounded manual PE export-table walk at `0x32C2`. Main unloads the memory module after the selected call returns. The separate `GetModuleHandleW(L"PackClientCore.dll")` call at `0x8B8F` is bootstrap-path discovery for [active-session handoff](active-session-handoff.md), not acquisition of Core bytes.

## Guardian, mutex, and diagnostics

B also implements process-guardian, session-mutex, diagnostic, and crash-dump functionality. The process-guardian state machine was not fully reconstructed.

| Facility | Recovered behavior | Boundary |
|---|---|---|
| Process guardian | HKCU `Software\PackMonitorClient\process_guardian`; `enabled`, `shutdown_pending`, `guardian_pid`, `business_pid`, `business_gen`; guardian-only mode without DLL pull; process watching/respawn with a 20-per-minute limiter | Guardian `--pg-slot` is distinct from Core cache slot; no direct edge to secondary promotion |
| Session/pair mutex | `Global\PackClientLauncher.Session.%016llx`; creation at `0x25B9`, owned handle at RVA `0x41BB8`; an already-existing name fails the guard | Runtime named-mutant evidence supports B-specific state; later short-lived children do not prove the exact rejection branch |
| Exported mutex release | `_PackLauncher_CloseSessionMutexIfHeld@0`, RVA `0x6F2F`, closes a non-null held handle and clears the global | No recovered caller; external consumer identity unresolved |
| Diagnostic storage | `debug-3eed5b.log`, `PackCore-runtime.log`, structured diagnostic templates and crash/snapshot writer | A filename or pre-existing log is not proof of the current run |

The crash writer dynamically resolves `MiniDumpWriteDump` and supplies the current process/PID, type `0x1001`, optional local exception information (`ClientPointers=FALSE`), and null user-stream/callback arguments. `0x1001` means `MiniDumpWithDataSegs | MiniDumpWithThreadInfo`; it does not request full/private memory or guarantee manually mapped B/Core/key pages. See [Microsoft's minidump flags](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_type).

The one-shot crash path tries `launcher_crash.dmp` beside the current process module, then a PID/tick-count filename there, then `%TEMP%\PackClientLauncherDumps\`. A separate snapshot path uses `launcher_snapshot.dmp`. These recovered self-dump contracts are distinct from the broader analyst-collected dumps in [runtime validation](runtime-validation.md).

## Evidence boundaries

The recovered launcher exposes transport, delivery/cache, session continuity, a screenshot worker and supporting lifecycle facilities. Core, the external screenshot peer, the envelope-state writer, the mutex-export consumer, and the upstream surrogate-population method remain missing. The component census does not identify opaque/headerless code outside the established structures. Full limitations and evidence grades are in [limitations](limitations.md) and [evidence](evidence.md).
