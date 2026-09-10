# Runtime analysis

Runtime captures show PackClient residing inside bare `SysWOW64\svchost.exe` processes, installing persistence, and repeatedly attempting to reach its configured endpoint. Public Triage sessions also preserve the remote-placement sequence and successful historical Core delivery, while two September runs compare normal full-EXE execution with direct invocation of the carrier DLL.

The screenshot-worker experiments are documented separately in [Screenshot IPC](screenshot-ipc.md).

## Local capture: PID 5812

### Process and persistence

The process tree records staged host PID 10164, intermediate descendant PID 9068, and bare 32-bit `SysWOW64\svchost.exe` PID 5812. The `svchost.exe` command line lacks the service-group and service-selection arguments normally used by Windows, supporting its identification as a PackClient surrogate.

Task `\NvSvc` uses a logon trigger, `InteractiveToken`, `HighestAvailable`, and the following target under the current user's principal:

```text
C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe
```

Older LastWrite values are visible in this session, but this capture alone does not prove they were backdated. The later PID 3696 trace records the timestamp changes directly.

### Memory correspondence

The user-mode dump captured the following private mappings:

| Runtime object | Address or range | Identification |
| --- | --- | --- |
| Protected package | `0x002E0000–0x00346000`, 417,792 bytes, private RX | Contains A at offset `0x128D` and B at offset `0x1CC1` |
| Mapped A | `0x02C70000–0x02CD4000`, size `0x64000` | Timestamp `0x6A27AE4B`, entry RVA `0x1308` |
| Mapped B | `0x05410000–0x05458000`, size `0x48000` | Timestamp `0x6A3CB0B5`, entry RVA `0x12FAC`, matching section layout and protections |

Thread 1884 starts at `0x02C71308`, exactly A's base plus its entry RVA. No registered module owns that address.

Copies of B's `.data`, `.fptable`, `.rsrc`, and `.reloc` sections correspond to the reconstructed Launcher image. The mapped `.rsrc` and `.reloc` sections match exactly. B's named state is also present:

```text
\BaseNamedObjects\PackClientLauncher.Session.9b2126fc5ed31443
```

The package structure, embedded offsets, mapped images, A-entry thread, section correspondence, and named mutant show that the reconstructed A/B chain was resident inside PID 5812. A contains the mapper responsible for loading B.

### Connection attempt

The process environment contains:

```text
PACK_LAUNCH_PULL_HOST=154[.]36[.]188[.]201
PACK_LAUNCH_PULL_PORT=443
```

No `PACK_LAUNCH_PSK` value was present when the environment was captured. Launcher buffers record a slot-0 pull attempt to the configured endpoint ending with `WSA=10060`, the [Windows socket timeout error](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2).

This establishes an attempted connection and timeout. It does not establish TCP completion, authentication, PLK1 delivery, Core loading, or successful C2 traffic.

No independently identifiable Core image was found in this dump. Core-related strings inside B describe its loading interface, not a resident Core DLL.

### Procmon coverage

The Procmon capture spans about **9.48 seconds** and begins roughly **44 minutes 45 seconds after** PID 5812 started. It is therefore not detonation-time coverage. No PID 5812 network activity appears in that late window, which does not cover the earlier connection attempt.

## Local capture: PID 3696

This session includes several interrupted and manual launches, so the events below describe individually correlated activity rather than one uninterrupted execution.

### Execution timeline

| Local time, September 5 | Observed event |
| --- | --- |
| `15:42:35` | Medium-integrity host PID 8492 starts; its adjacent DLL open fails with `0xC0000906`, followed by the same exit status |
| `15:48:19` | Downloads host PID 1512 repeats the adjacent-DLL failure |
| `15:50:02.607` | Medium-integrity host PID 5952 successfully loads the adjacent DLL |
| `15:50:14.734` | The host relaunches with high integrity as PID 2116; the parent exits and the elevated child loads the companion DLL |
| `15:50:17.398` | PID 2116 creates bare high-integrity `SysWOW64\svchost.exe` PID 3696 |
| `15:50:17.413–15:50:17.423` | The elevated host installs hidden ProgramData copies, changes their LastWrite times to July 15, writes HKCU Run and RunOnce values, and begins task creation |
| `15:50:17.535` | `schtasks.exe` creates the highest-available `\NvSvc` logon task |
| `15:50:28.196` | The packet capture begins recording failed connection attempts to port 443 |
| `16:22:41` | Another manual launch repeats persistence; its bare child PID 6716 survives approximately 0.33 seconds |
| `16:28:43` | Task Scheduler launches the persisted host as PID 5764; bare child PID 5748 survives approximately 0.12 seconds |
| `16:35:40` | The dump preserves the original long-lived PID 3696 |
| `16:51:55.711` | The final quoted SYN failure appears after the Procmon capture has ended |

The transition from medium to high integrity agrees with the Launcher's recovered `runas` path.

### Persistence

The elevated host writes `NvSvc` under both:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Both values point to the ProgramData copy of `Tax_Notice_23665.exe`.

Task `\NvSvc` uses:

- an at-logon trigger;
- `InteractiveToken`;
- `HighestAvailable`;
- `MultipleInstancesPolicy=IgnoreNew`;
- the same ProgramData executable.

`HighestAvailable` applies to the selected user and does not mean the task runs as SYSTEM.

The Autoruns snapshot contains both the NvSvc logon entry and scheduled-task entry. Its NV Access label comes from the legitimate signed host and does not describe the adjacent malicious DLL. A later task-owned process confirms that the persisted path was executed, although the capture does not distinguish an actual logon trigger from an on-demand task launch.

Unlike the earlier PID 5812 evidence, this trace directly records the LastWrite changes.

### Failed network activity

The packet capture contains 373 ICMP destination-unreachable messages quoting TCP SYNs sent to:

```text
154[.]36[.]188[.]201:443
```

The quoted packets have no ACK flag or payload and span 288 unique client source ports. No SYN-ACK, established TCP stream, or PackClient application exchange appears.

Process Explorer separately associates PID 3696 with `SYN_SENT` sockets to the same endpoint from local ports 54581 and 50275. Because the packet capture itself contains no process identifiers, those socket views directly identify only those two connections; the remaining quoted SYNs are correlated by time and destination.

The evidence establishes repeated connection attempts but not the reason they failed.

### Package and mapped Launcher

The PID 3696 dump preserves the long-lived surrogate and its private mappings:

| Runtime object | Coordinates | Identification |
| --- | --- | --- |
| Protected package | RX at `0x00680000`, size `0x66000` | Contains A at `0x0068128D` and raw B at `0x00681CC1` |
| Mapped B | Private image at `0x02F10000`, size `0x48000` | Matching headers, six sections, timestamp `0x6A3CB0B5`, and entry RVA `0x12FAC` |

The first 415,071 package bytes differ from the reconstructed static package at eight bytes across three ranges:

```text
0x5753–0x5756
0xDD8E–0xDD8F
0x3CDE7–0x3CDE8
```

After accounting for 4,023 expected HIGHLOW relocations and 188 import-address-table slots, `.rsrc` and `.reloc` match exactly. The remaining mapped-image differences comprise six `.text`, two `.rdata`, 608 `.data`, and eight `.fptable` bytes.

Six changed package bytes reflect three `6666`-to-`443` port substitutions. The purpose of the remaining two changed bytes was not resolved.

No independently identifiable Core image was found in this dump.

## Triage runtime evidence

### Remote placement and execution

Public Triage task [`260828-py7ysahr4y`](https://tria.ge/260828-py7ysahr4y) records `Tax_Notice_23665.exe` creating a fresh suspended 32-bit `SysWOW64\svchost.exe`, performing 53 `WriteProcessMemory` operations against it, and producing a `0x66000`-byte private region at `0x00440000`. `SetThreadContext` then targets the surrogate's primary thread.

The same high-level sequence appears in the reviewed July and August Triage reports. The September full-EXE repeat described below also records `WriteProcessMemory` and `SetThreadContext` during both the initial execution and the later persisted execution.

Together with the recovered carrier logic, this establishes remote package placement followed by primary-thread context hijacking. It supports thread execution hijacking rather than image replacement or remote-thread creation. The exact carrier write call site and the instruction-pointer value installed through `SetThreadContext` remain unknown.

### Successful historical delivery

Triage tasks [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l) and [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) preserve successful sessions with the following progression:

```text
PLH1 → PLC1 → PLA1 → PLK1 → Core traffic
```

Both sessions deliver the same 985,088-byte `PackClientCore.dll`. Post-delivery traffic contains startup exchange, host inventory, offline-keylogger status, preview control, and 15 `PV10` JPEG frames. The traffic on TCP port 443 is PackClient's own protocol rather than TLS.

No plugin delivery, Core update, ETCHOOK activation, or encrypted Core type-`0x16` message appears in these sessions. Core recovery and post-delivery behavior are detailed in [Core analysis](core-analysis.md).

## September controlled runs

### Full-EXE execution

In [`260908-zwr5naybjb/behavioral1`](https://tria.ge/260908-zwr5naybjb/behavioral1), temporary `Tax_Notice_23665.exe` PID 3892 launches `SysWOW64\svchost.exe` PID 3780. The executable copies itself and its adjacent `nvdaHelperRemote.dll` into:

```text
C:\ProgramData\NVIDIA Corporation\NvSvc\
```

It creates `Run\NvSvc`, `RunOnce\NvSvc`, and scheduled task `NvSvc`, all targeting the persisted `Tax_Notice_23665.exe`. Triage later executes that copy, which launches another 32-bit `svchost.exe` and repeats the persistence setup.

The one-hour full-EXE repeat in [`260909-abma8sab28/behavioral1`](https://tria.ge/260909-abma8sab28/behavioral1) shows the same chain:

```text
Tax_Notice_23665.exe PID 4260
  → SysWOW64\svchost.exe PID 3684
  → persisted Tax_Notice_23665.exe PID 3024
  → SysWOW64\svchost.exe PID 4912
```

Both executable launches record `WriteProcessMemory` and `SetThreadContext` against their respective surrogate processes. Both also write the Run and RunOnce values and create the same scheduled task:

```text
schtasks /Create /TN NvSvc /TR "\"C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe\"" /SC ONLOGON /RL HIGHEST /F
```

These runs confirm that full-EXE execution preserves the expected host-and-carrier relationship and produces a functional persistence command.

### Direct-DLL execution

In [`260908-zwr5naybjb/behavioral2`](https://tria.ge/260908-zwr5naybjb/behavioral2), Triage invokes the inner carrier directly:

```text
rundll32.exe C:\Users\Admin\AppData\Local\Temp\nvdahelperremote.dll,#1
```

The `rundll32.exe` process launches a 32-bit `svchost.exe`, but the persistence routine now treats `C:\Windows\System32\rundll32.exe` as its host executable. It copies `rundll32.exe` into the NvSvc directory and attempts to find `nvdaHelperRemote.dll` beside the original System32 host, where the DLL does not exist.

The resulting Run, RunOnce, and scheduled-task entries target only:

```text
C:\ProgramData\NVIDIA Corporation\NvSvc\rundll32.exe
```

The original DLL path and `,#1` export argument are not preserved. When Triage executes the persisted copy, it exits after approximately 16 milliseconds without loading PackClient.

This is a broken replay caused by direct invocation of the inner DLL. It is not a second PackClient variant or an alternative functional persistence design.

### Network results

All three one-hour executions established enough TCP connectivity to transmit valid Launcher greetings, but the server returned no PackClient application data:

| Task and mode | Complete `PLH1` greetings | Server application bytes | Result |
| --- | ---: | ---: | --- |
| `260908-zwr5naybjb/behavioral1`, full EXE | 492 | 0 | No `PLC1`, `PLA1`, `PLK1`, Core, or plugin delivery |
| `260908-zwr5naybjb/behavioral2`, direct DLL | 501 | 0 | No `PLC1`, `PLA1`, `PLK1`, Core, or plugin delivery |
| `260909-abma8sab28/behavioral1`, full EXE repeat | 283 | 0 | No `PLC1`, `PLA1`, `PLK1`, Core, or plugin delivery |

The later non-response does not negate the successful July sessions. It establishes only that the endpoint accepted repeated connections while returning no PackClient application payload during these September runs.

### Memory results

The `260908-zwr5naybjb` report contains 18 memory artifacts. Thirteen are 294,912-byte mapped PE images with the recovered Launcher's timestamp, image size, PDB identity, and protocol markers; the remaining five are surrounding or non-PE allocations.

The `260909-abma8sab28` report contains 12 memory artifacts. Nine are 294,912-byte mapped images matching the same Launcher layout, while three are adjacent or partial allocations.

Every recovered memory artifact belongs to the Launcher or its surrounding allocations. Neither run produced a completed PLK1 transfer, independently identifiable Core image, plugin DLL, or new PackClient stage.

## Runtime conclusions

The local dumps establish that the reconstructed package, A, and Launcher B were resident inside bare 32-bit `svchost.exe` surrogates. Public and controlled Triage evidence establishes remote package placement followed by primary-thread context hijacking.

The historical July sessions preserve successful authentication, Core delivery, commands, and screenshot traffic. The September runs instead establish the repeatable full-EXE persistence path, explain the broken direct-DLL `rundll32.exe` artifact, and show repeated `PLH1` transmission without a server response.

Supporting artifact identities are listed in [Evidence](evidence.md). Remaining runtime uncertainties are collected in [Scope and limitations](limitations.md).
