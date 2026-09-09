# Active-session handoff

This document describes the target-session selection, token handling, command-line construction, and session-drift behavior recovered from Launcher B. All RVAs are relative to the recovered Launcher B described in [architecture](architecture.md). The behavior was reconstructed statically; the reviewed runtime evidence does not show a successful active-session replacement.

## Session selection and entry gate

`WTSGetActiveConsoleSessionId` is the only target-session source. Current-process and enumerated-process session IDs are gates or filters. B does not enumerate candidate WTS sessions or select an existing PackClient process as its target.

Orchestrator `0x8349` first checks `-acsi` or `--active-session`. If a marker exists and current-process session equals a valid active-console session, it starts the drift-monitor path and performs no immediate handoff. All other immediate-handoff paths require the current token’s user SID to be `LocalSystem` (`S-1-5-18`). This checks identity, not administrator membership or elevation.

The SYSTEM branch requires a successful lookup of the current process’s session, a valid active-console ID, and a nonempty bootstrap path. It does not require current and active session IDs to differ. Shared helper `0x8F04` then samples the active console again; this second sample is authoritative. It sleeps 20 ms while the value is `0xFFFFFFFF`, with no static timeout. Session zero and other valid DWORDs have no separate exclusion.

## Two distinct token roles

| Role | Source and operations | Failure behavior |
|---|---|---|
| **Primary launch token** | Open current process token with `TOKEN_ALL_ACCESS`; `DuplicateTokenEx` requests `MAXIMUM_ALLOWED`, `SecurityImpersonation`, `TokenPrimary`; set `TokenSessionId` to selected active console | Open, duplicate or session-set failure aborts; no alternate primary-token source |
| **Optional environment token** | `WTSQueryUserToken(target)` first; otherwise first usable target-session `winlogon.exe` or `explorer.exe` token in process snapshot order | Missing token does not block launch |

The environment token never becomes the primary launch token. In the immediate SYSTEM path, the launch token is derived from the current LocalSystem token with a different session ID. Successful runtime execution of this handoff path was not observed.

Before target selection, B requests `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`, and `SeIncreaseQuotaPrivilege` in that order. Privilege adjustment is best effort: the caller neither gates execution on success nor checks for partial assignment through `GetLastError`.

The environment fallback enumerates processes in snapshot order, matches `winlogon.exe` or `explorer.exe`, and requires its session to equal the selected target. It tries `PROCESS_QUERY_LIMITED_INFORMATION`, then `PROCESS_QUERY_INFORMATION`, opens the token with duplicate/query access, and duplicates a primary token with `TOKEN_ALL_ACCESS`. A failure continues enumeration. Although the name table lists winlogon first, the selection is **first usable process in snapshot order**, not a global winlogon-first search.

When an environment token exists, `CreateEnvironmentBlock(&environment, token, FALSE)` receives a pointer initialized to null. Its Boolean result is ignored. The spawn call uses that pointer as left by the API and later destroys it when non-null; this does not establish its contents after API failure. B adds no handoff-specific environment variable.

## Bootstrap resolution

Resolver `0x8ABB` uses this order:

1. Current image path immediately, if its case-normalized basename is `PackClientLauncher.exe` or `PackClientConsole.exe`.
2. Launcher, then Console, beside an already-loaded `PackClientCore.dll` (cached module handle first, then `GetModuleHandleW`).
3. Launcher, then Console, beside the current process image.
4. Launcher, then Console, in each of these `LOCALAPPDATA` bases, in table order.
5. Original current image path even if its basename is neither recognized bootstrap name.

| Search order within LOCALAPPDATA | Relative base |
|---:|---|
| 1 | `PackMonitorClient\Plugins\x64\` |
| 2 | `PackMonitorClient\Plugins\Win32\` |
| 3 | `PackMonitorClient\Plugins\` |
| 4 | `PackMonitorClient\Launcher\x64\` |
| 5 | `PackMonitorClient\Launcher\Win32\` |

Candidate files must have valid attributes and not be directories. Current-image lookup failure/empty output yields an empty result. The fixed 260-WCHAR current-image buffer has no separate truncation check. Core's presence here supplies only a path candidate; this is separate from Core acquisition/mapping.

## Argument preservation and marker handling

`0x7ABB` preserves only the following arguments rather than copying the complete original command line:

| Recognized exact token | Preserved arguments |
|---|---|
| `-acsi`, `--active-session` | Marker |
| `--guard`, `--guarded-by`, `--pg-slot`, `--pg-core-guard`, `--pg-core-slot` | Flag plus one following argument when present |
| `/scr_cap_worker` | Flag plus endpoint and one optional following argument |

Selected values from the parsed wide command line come first. Narrow `argv` selections are converted as UTF-8 and appended only when the same individual wide string is not already present. Deduplication is per string, not per flag/argument tuple.

The merged vector omits exact active markers. A broader detector then looks for either marker as a substring in the raw wide command line, followed by exact narrow-argument tests. **Only when neither marker is detected is canonical `-acsi` appended.** Therefore an existing marker can be removed without replacement. `/acsi` is neither recognized nor inserted.

`QuoteArg` at `0x899A` turns empty input into `""`; strings without space, tab or quote are unchanged. Otherwise it wraps the value in quotes and doubles embedded quotes, without special treatment of backslashes. The constructed command line contains the quoted bootstrap path, preserved arguments, and conditional `-acsi`, separated by single spaces. A separate mutable wide vector receives an explicit trailing NUL.

Preserving the `/scr_cap_worker` arguments does not establish where the worker was originally launched or who created its endpoint. A valid [screenshot-worker invocation](screenshot-ipc.md) exits through the early dispatch before this normal handoff; no reachable initial worker launch or endpoint construction is established by the argument builder.

## Process creation

The sole `CreateProcessAsUserW` call is B RVA `0x916A`.

| API state | Recovered value |
|---|---|
| Token | Duplicated current-process primary token with retargeted session |
| `lpApplicationName` | Null |
| `lpCommandLine` | Mutable NUL-terminated wide vector |
| Process/thread security attributes | Null |
| `bInheritHandles` | False |
| Creation flags | `0x09000400`: break away from job, no window, Unicode environment |
| Environment | Optional environment-block pointer described above |
| Current directory | Bootstrap substring through its last slash/backslash, including separator; null if none |
| Startup desktop | `WinSta0\Default` |
| Startup flags/window | `STARTF_USESHOWWINDOW`, `SW_HIDE` |
| Output | Caller-supplied, initially zeroed 16-byte `PROCESS_INFORMATION` |

The 32-bit `STARTUPINFOW` is zeroed for `0x44` bytes, then only `cb`, desktop, flags and show-window are set. Standard handles and all other fields remain zero; `STARTF_USESTDHANDLES` is absent. No `CREATE_SUSPENDED` flag is supplied.

The helper makes up to 30 process-creation attempts without filtering by error code. Every failed attempt, including the thirtieth, is followed by a 1,000 ms sleep. A successful attempt returns immediately. Per-attempt errors are read immediately after failure; a later aggregate log occurs after cleanup and need not preserve the last creation error.

Cleanup destroys a non-null environment and closes environment/source/primary token handles. On success the helper leaves process/thread handles and IDs with its caller. The immediate handoff caller closes thread then process handles and calls `ExitProcess(0)` without waiting for a child handshake.

## Drift monitor

Starter `0x9261` rechecks the active marker and current-session/active-console equality. It atomically claims the initially zero per-process flag at `0x41BCC`, allocates `0x24` bytes of diagnostic context and creates a thread starting at `0x8E06`. The thread handle is immediately closed; there is no retained join/cancel handle.

Thread-creation failure frees context and resets the flag. A null context allocation returns **without** resetting the flag, preventing this starter from trying again in that process. Successful creation retains the flag; the monitor has no normal return or explicit context free before process exit.

| Sampled state after `Sleep(200)` | Action |
|---|---|
| Current-session lookup fails | Continue |
| Active console is `0xFFFFFFFF` | Continue |
| Current and active IDs equal | Continue |
| Valid unequal IDs | Resolve bootstrap and attempt replacement if nonempty |

There is no stored prior active ID, WTS lock-state query, debounce or session-notification registration. Lock/unlock cannot be distinguished when IDs remain equal. The nominal spacing is at least 200 ms; API and replacement work add time.

On session drift, the worker constructs exactly `-acsi` and calls `0x8F04` at `0x8EC3`; guardian, screenshot-worker, and other original arguments are not preserved. There is no LocalSystem gate in this caller. The helper resamples the active console, so its final token target can differ from the drift sample. If the console disappears, the helper's unbounded 20 ms wait suspends progress of the outer loop.

Success closes the returned thread/process handles and exits the old process. Failure destroys its temporary strings and resumes the 200 ms sampling loop; there is no fixed outer retry limit. This state machine never calls the exported mutex-closing function. Normal process teardown closes owned handles, but that does not identify an explicit caller of the export.

## Key RVAs

| B RVA | Role |
|---|---|
| `0x7914` | Best-effort privilege adjustment |
| `0x7FA7` | Exact LocalSystem identity gate |
| `0x8349` | Immediate handoff orchestrator |
| `0x87FF` | Environment-token acquisition |
| `0x899A` | Quoting |
| `0x8ABB` | Bootstrap path resolution |
| `0x8F04` | Shared token/environment/spawn helper |
| `0x916A` | Process creation |
| `0x9261` | Monitor starter |
| `0x8E06` | Drift worker |

Windows API behavior follows [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw). The token/process behavior maps most directly to [MITRE T1134.002](https://attack.mitre.org/techniques/T1134/002/). See [evidence](evidence.md) and [limitations](limitations.md) for more details.
