# The `1RCP` screenshot worker

The recovered launcher implements the worker half of a local screenshot interface. This section reconstructs its activation, message format, pixel layout and local dataflow. The external peer and initial worker launcher remain unrecovered.

## Activation and process context

The worker is selected with:

```text
PackClientLauncher.exe /scr_cap_worker <endpoint-utf8> [monitor-index]
```

Main calls the worker dispatcher at B RVA `0x45C3 -> 0xA38E` before the normal Core/session path. The body requires at least three arguments, exact `argv[1] == /scr_cap_worker`, and non-null `argv[2]`. Optional `argv[3]` supplies the monitor index; default is zero. The wrapper passes the worker result to `ExitProcess`.

The worker inherits its existing token, integrity level, session, environment and parent relationship. This branch does not create another process or change session context.

## Endpoint boundary

`argv[2]` is converted from UTF-8 into a 260-WCHAR buffer and passed to `CreateFileW` at `0xA4DE`:

| Argument | Recovered value |
|---|---|
| Filename | Direct UTF-16 conversion of supplied endpoint |
| Access | `0xC0000000`, read and write |
| Share mode | Zero |
| Security attributes | Null |
| Creation disposition | `OPEN_EXISTING` |
| Flags and template handle | Zero/null |

B opens the supplied path once with `OPEN_EXISTING`; endpoint creation and peer identity are external to the recovered worker.

Named-pipe use is strongly inferred from the duplex protocol and diagnostics. `CreateFileW` also accepts other path types, so this call alone does not prove a pipe namespace. [Microsoft's CreateFileW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) and [named-pipe client documentation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client) describe the relevant API behavior.

No worker-launch or peer-creation path was found outside B in the recovered components. Generic argument rebuilding preserves `/scr_cap_worker`, its endpoint and optional monitor index across relaunches, but does not create the initial worker invocation.

## Header and message semantics

Every message starts with five little-endian DWORDs, exactly 20 bytes. Magic is `0x50435231`, wire bytes `31 52 43 50` (`1RCP`).

| Offset | Field | READY, type 1 | Frame, type 2 | Recapture, type 3 | Exit, type 5 |
|---:|---|---|---|---|---|
| `0x00` | Magic | `1RCP` | `1RCP` | `1RCP` | `1RCP` |
| `0x04` | Type | 1 | 2 | 3 | 5 |
| `0x08` | Width | Width | Width | Ignored | Ignored |
| `0x0C` | Height | Height | Height | Ignored | Ignored |
| `0x10` | Payload size | Zero | Pixel-byte count | Ignored | Ignored |

The reconstructed exchange is:

1. Worker captures once, then sends type 1 READY with dimensions and no pixel body.
2. Peer sends type 3 to request recapture.
3. On successful capture, worker sends type 2 plus the pixel body.
4. Peer can repeat recapture or send type 5; exit has no reply.

The request tail DWORDs are ignored, not required to be zero. The worker reads no extra request body from the last DWORD; its next operation is another exact 20-byte header read. Unknown types with correct magic are ignored. Wrong magic, failed reads or zero-byte reads end the loop without a protocol error response.

Reads and writes loop until the requested byte count completes. These operations do not require message-mode pipe boundaries. Writer `0xA731` sends the header, then writes a payload only when both pointer and size are nonzero; `0xA6E6` performs exact writes.

## Desktop and pixel layout

The attachment path opens `winsta0`, temporarily selects the window station, attempts `OpenInputDesktop`, falls back to `Winlogon`, selects the desktop, and restores/closes handles after use. It depends on the inherited context having the required access.

Capture at `0x9EB0` enumerates monitor rectangles. A valid requested index wins; otherwise it selects index zero. Positive dimensions are calculated from the selected rectangle:

```text
width        = right - left
height       = bottom - top
row_stride   = width * 4
payload_size = width * height * 4
```

The DIB header is 40 bytes, with positive width, negative height, planes 1, bit count 32 and `BI_RGB`. Negative height selects top-down row order. `BitBlt` uses `SRCCOPY | CAPTUREBLT` (`0x40CC0020`). Each pixel is blue, green, red, unused/reserved: **BGRX**, with no meaningful alpha established and no extra row padding beyond `width * 4`.

IA-32 multiplication/shift calculates the allocation length; no separate overflow guard was observed.

Within B the framebuffer dataflow ends at `WriteFile` on the supplied handle. No B-local edge reaches Winsock, PLK1, the lower encrypted transport, JPEG or `PV10`. Any forwarding or encoding stage therefore belongs to an unrecovered external component.

## DIB lifetime hazard and observed failure

The recovered call order is `CreateDIBSection`, select bitmap, `BitBlt`, restore old selection, `DeleteObject`, DC cleanup, then copy from the saved bits pointer. This creates a plausible lifetime hazard because the saved bits pointer is used after the deletion call. Microsoft's [CreateDIBSection](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdibsection) contract ties the bits to the bitmap's lifetime, while [DeleteObject](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-deleteobject) can fail. A breakpoint before `DeleteObject` does not establish that deletion succeeded.

| Attempt | Captured observation |
|---|---|
| PID 8892 | Copy source `0x03260000`, length `0x510000`; source not resolved in the captured memory view |
| PID 8148 | Breakpoint before deletion, then later `rep movsb` from source `0x02830000`, length `0x510000` |
| PID 8040 | First-chance AV at RVA `0xA567`, `push [edi+8]`, with **EDI=`0x13C`, EAX=1**; peer received 0 of 20 READY-header bytes |

These were separate debugger sessions and included manual intervention, so they do not form a single controlled execution trace.

`0x510000` equals `1536 * 864 * 4`, matching the expected framebuffer size for 1536 × 864 but not establishing the lifetime of the source allocation. The final fault is separate from the earlier copy-source observations.

Relevant sites: `CreateDIBSection` at `0xA010`; deletion near `0xA066`; copy near `0xA0F9/0xA0FE`; final recorded fault `0xA567`.

The static call order exposes a plausible DIB lifetime defect. The runtime attempts show a later copy from a saved bits pointer and a separate worker fault, but do not establish a causal use-after-free chain.

The [synthetic validation appendix](screenshot-ipc-validation.md) reproduces the `1RCP` framing and BGRX serialization with a local peer and simulator. A complete exchange with the real worker was not captured. See [evidence](evidence.md) and [limitations](limitations.md) for the remaining boundaries.
