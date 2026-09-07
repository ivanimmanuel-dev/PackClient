# Runtime validation

Two runtime sessions connect the static reconstruction to launcher residence, persistence and failed outbound behavior. The screenshot-worker experiments are documented separately in [screenshot IPC](screenshot-ipc.md). The PID 3696 session includes interrupted and manual launches, so its observations are treated as scoped events rather than one uninterrupted baseline.

## PID 5812

The process tree records staged host PID 10164, intermediate descendant 9068 and bare 32-bit `SysWOW64\svchost.exe` PID 5812, followed by task activity. Its command line lacks the normal service-host group/selection arguments, supporting a malware-spawned surrogate. The mechanism that placed and started PackClient code inside it remains unresolved.

Task `\NvSvc` uses a logon trigger, `InteractiveToken`, `HighestAvailable`, and target `C:\ProgramData\NVIDIA Corporation\NvSvc\Tax_Notice_23665.exe` under the current user's principal. The older LastWrite values visible in this session do not by themselves establish backdating; the PID 3696 trace below records the writes directly.

Startup Apps also showed an enabled Tax Notice entry, but its backing registration was not recovered in this session.

### Memory correspondence

The user-mode dump captured private mappings and memory-information data at `2026-09-04T23:21:16Z`. A and B do not appear as ordinary registered modules.

| Runtime object | Address/range | Linkage |
|---|---|---|
| Package allocation | `0x002E0000–0x00346000`, 417,792 bytes, private RX | A at offset `0x128D`, B at `0x1CC1`, matching the transformed record |
| Mapped A | `0x02C70000–0x02CD4000`, `0x64000` | Timestamp `0x6A27AE4B`, entry RVA `0x1308`, image-sized private mapping |
| Mapped B | `0x05410000–0x05458000`, `0x48000` | Timestamp `0x6A3CB0B5`, entry RVA `0x12FAC`, exact section layout/protections |

Thread 1884 starts at `0x02C71308`, exactly A base plus entry RVA `0x1308`; no registered module owns that address. VMMap independently records the A- and B-sized allocations. The private RX package allocation contains A and B at the same offsets as the static transformed package.

Raw B copies of `.data`, `.fptable`, `.rsrc` and `.reloc` match their corresponding static sections; mapped `.rsrc` and `.reloc` also match exactly. B-specific state is present through the named mutant:

```text
\BaseNamedObjects\PackClientLauncher.Session.9b2126fc5ed31443
```

The package coordinates, PE metadata, section correspondence, A-entry thread, VMMap layout and named state provide converging evidence that the reconstructed A/B chain was resident and active. Static A contains B's local mapper. The upstream placement/injection mechanism remains unresolved.

### Configuration and connection attempt

The environment contains `PACK_LAUNCH_PULL_HOST=154[.]36[.]188[.]201` and `PACK_LAUNCH_PULL_PORT=443`; no `PACK_LAUNCH_PSK` entry is present at capture time. Launcher buffers record a slot-0 pull attempt to that endpoint with `WSA=10060`.

[Microsoft defines 10060 as WSAETIMEDOUT](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2). This establishes an attempted connection and timeout, not TCP completion, authentication, PLK1 delivery, encrypted traffic, Core loading or successful C2.

No independently identifiable Core PE was found in the dump. Core-related strings inside B describe its loading contract and do not establish a resident Core image.

### Procmon coverage

The Procmon capture spans about **9.48 seconds** and begins roughly **44 minutes 45 seconds after** PID 5812 started. It is therefore not detonation-time coverage. No PID 5812 network activity appears in that late window, which does not cover the earlier connection attempt.

## PID 3696

The Procmon timeline spans `15:27:40` to `16:49:15` local time on September 5 (`America/Toronto`); Sysmon UTC timestamps correlate with that timeline.

### Correlated events

| Local time, September 5 | Supported event |
|---|---|
| `15:42:35` | Medium-integrity host PID 8492 starts; adjacent DLL open fails with `0xC0000906`, followed by the same exit status |
| `15:48:19` | Downloads host PID 1512 repeats the adjacent-DLL failure |
| `15:50:02.607` | Medium-integrity host PID 5952 successfully loads the adjacent DLL |
| `15:50:14.734` | Same host relaunches as high-integrity PID 2116; parent exits; child loads the companion DLL |
| `15:50:17.398` | PID 2116 creates high-integrity bare `SysWOW64\svchost.exe` PID 3696 |
| `15:50:17.413–.423` | Elevated host installs hidden ProgramData host/DLL copies, backdates LastWrite to July 15, writes HKCU Run/RunOnce and starts task creation |
| `15:50:17.535` | `schtasks` creates the highest-available `\NvSvc` logon task |
| `15:50:28.196` | Packet evidence begins recording quoted failed SYN attempts to port 443 |
| `16:22:41` | Another manual launch repeats persistence; its bare child PID 6716 survives about 0.33 seconds |
| `16:28:43` | Task Scheduler starts persisted host PID 5764; bare child PID 5748 survives about 0.12 seconds |
| `16:35:40` | Dump preserves the original long-lived PID 3696 |
| `16:51:55.711` | Last quoted SYN failure in the packet capture, extending beyond the Procmon interval |

The integrity transition corroborates the static `runas` path. PID 3696 and `schtasks` PID 4600 are siblings under PID 2116; `conhost` PID 8248 is a child of `schtasks`. Because PID reuse occurs in this session, process joins use timestamp, image, parent and Sysmon ProcessGuid where available.

### Persistence

The elevated host writes `NvSvc` under both HKCU `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, pointing to the ProgramData Tax Notice host. Task `\NvSvc` uses a logon trigger, `InteractiveToken`, `HighestAvailable`, `MultipleInstancesPolicy=IgnoreNew` and the same target.

The later Autoruns snapshot contains both an NvSvc logon entry and scheduled-task entry. Its NV Access label reflects the legitimate host signature, not the companion DLL. A later task-owned execution confirms the persisted path was launched, although the trace does not distinguish a fresh logon trigger from an on-demand task start.

This session also records the LastWrite backdating operations directly.

### Failed network observations

The packet capture contains **373 ICMP type/code `3/1` messages quoting TCP SYNs** to `154[.]36[.]188[.]201:443`: ACK clear, no payload, across 288 unique source ports. No SYN-ACK or established TCP/application session appears.

Process Explorer separately shows PID 3696 in `SYN_SENT` to the same endpoint at local source ports 54581 and 50275. This directly associates PID 3696 with those socket entries at those moments. The packet capture has no PID metadata, so attribution of every quoted SYN to PID 3696 remains correlation rather than direct packet-to-process linkage.

The capture does not establish why the connection attempts failed.

### Package and mapped B

The PID 3696 user-mode dump records process creation at `19:50:17Z` and snapshot time `20:35:40Z`, preserving the long-lived process and its private mappings.

| Object | Coordinates | Comparison |
|---|---|---|
| Package allocation | RX at `0x00680000`, size `0x66000` | A at `0x0068128D`, raw B at `0x00681CC1`; the first 415,071 bytes differ at eight bytes from the static package |
| Mapped B | Private image at `0x02F10000`, size `0x48000` | Matching headers, six sections, timestamp `0x6A3CB0B5`, entry RVA `0x12FAC` |

The eight changed package bytes occupy three inclusive record ranges: `0x5753–0x5756`, `0xDD8E–0xDD8F` and `0x3CDE7–0x3CDE8`, corresponding to B RVAs `0x4692`, `0xCCCD` and `0x3C326`.

After normalizing 4,023 expected HIGHLOW relocations and 188 IAT slots, `.rsrc` and `.reloc` match exactly; remaining differences are six `.text`, two `.rdata`, 608 `.data` and eight `.fptable` bytes.

The package comparison contains three changed ranges totaling eight bytes. Three straightforward little-endian 6666-to-443 substitutions explain six of them; the remaining two cannot be resolved without the original per-site before/after bytes. Port 443 is independently observed in the runtime network evidence.

No independently identifiable Core PE was found in this dump.

## Reproducibility

Some PID 3696 event counts and memory comparisons relied on analyst-created helpers whose source and exact invocations were not retained, limiting independent reproduction of those measurements.

See [limitations](limitations.md) and [evidence](evidence.md) for unresolved runtime boundaries.
