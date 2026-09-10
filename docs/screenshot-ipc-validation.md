# Synthetic screenshot IPC validation

This appendix exercises the reconstructed [`1RCP` worker contract](screenshot-ipc.md) using a local named-pipe peer and a simulator that sends a fixed 2 × 2 BGRX frame. It does not execute PackClient, contact a remote endpoint, or use captured malware data.

The kit targets **Windows PowerShell 5.1** and local synthetic inputs.

## Files and requirements

| File | Purpose |
|---|---|
| [`peer.ps1`](../tools/screenshot-ipc/peer.ps1) | Create a local pipe endpoint, validate READY and framebuffer messages, save output and send exit |
| [`simulator.ps1`](../tools/screenshot-ipc/simulator.ps1) | Send fixed 2 × 2 BGRX pixels or selected malformed messages |
| [`test_screenshot_ipc.ps1`](../tests/test_screenshot_ipc.ps1) | Run the documented protocol and validation cases |

Use `powershell.exe` from Windows PowerShell 5.1 / Desktop edition. PowerShell 7 and non-Windows platforms are not supported by this kit.

## Run the synthetic suite

From the repository root in Windows PowerShell:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tests\test_screenshot_ipc.ps1
```

A successful run prints **`RESULT: 15 tests passed`**. Each case uses a fresh pipe name and output directory, with finite waits and cleanup on failure.

To retain generated results:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tests\test_screenshot_ipc.ps1 -KeepArtifacts
```

The final `artifacts=` line identifies the output directory. `-ArtifactParent` can select an existing parent directory; otherwise the Windows temporary directory is used. The [validation workflow](../.github/workflows/validate.yml) runs the suite on Windows Server 2022 under Windows PowerShell 5.1 and retains the synthetic outputs as a workflow artifact.

## Inspect one exchange

In the first Windows PowerShell terminal, from the repository root:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tools\screenshot-ipc\peer.ps1 -PipeName '\\.\pipe\packclient-synthetic-demo' -EvidenceRoot .\ipc-output -RunId demo -ConnectTimeoutMs 60000
```

Within 60 seconds, run the simulator from a second terminal under the **same Windows account**:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tools\screenshot-ipc\simulator.ps1 -PipeName '\\.\pipe\packclient-synthetic-demo' -Scenario HappyPath
```

Use a different `-RunId` for later runs. The exchange follows one `1 -> 3 -> 2 -> 5` sequence. Exit code 0 indicates success; exit code 1 indicates failure.

| Successful output in `ipc-output/demo/` | Meaning |
|---|---|
| `framebuffer.bgrx` | 16 bytes: top row red/green, bottom row blue/white, zero reserved bytes |
| `framebuffer.bmp` | 70-byte BMP: 54-byte header, width 2, signed height −2, 32 bpp, BI_RGB |
| `transcript.json`, `transcript.txt` | Message fields, validations and state transitions |
| `run-summary.txt` | Status, reason, configured bounds and message sequence |
| `hashes.sha256` | SHA-256 of the other emitted files |

The fixed BGRX and BMP bytes are deterministic across successful runs. Timestamps, pipe names, run identifiers and transcript hashes vary.

| Fixed output | Expected SHA-256 |
|---|---|
| BGRX | `51E73B32547F29FA45D01B01CB92236AC641E1EA40F8E974AD9846E0954FB198` |
| BMP | `ADD262002A71D6F04080E52A8ED726BD962BF12313112EFA3E3FBB65F3AA4595` |

Malformed or incomplete frames fail without producing a framebuffer. If failure occurs after a valid frame has already been received, that frame may remain alongside the failure summary.

## Test coverage

| Cases | Count | Assertion |
|---|---:|---|
| Happy exchange, BMP reconstruction, repeatability | 3 | Exact sequence, fixed pixel bytes, top-down BMP fields and known hashes |
| Wrong magic, unexpected type, truncated header | 3 | Rejection without framebuffer output |
| Zero/absurd READY dimensions, nonzero READY payload | 3 | Rejection before framebuffer data is accepted |
| Truncated pixels, inconsistent payload length, absurd frame dimensions | 3 | Rejection of incomplete or invalid frame data |
| Peer without a worker; simulator without a peer | 2 | Finite connection timeouts |
| Existing output directory | 1 | Rejection preserves every prior output filename and byte |

The current suite contains **15 tests** covering protocol sequencing, image reconstruction, malformed input, timeout handling and output preservation.

The peer accepts only the local `\\.\pipe\` namespace and restricts the synthetic endpoint to the current user while denying the NETWORK SID (`S-1-5-2`).

## What the tests establish

The peer validates message order, dimensions, payload lengths, image serialization, and finite I/O behavior. Its defensive bounds are intentionally stricter than those recovered from the real worker.

These tests confirm the reconstructed `1RCP` framing and framebuffer format. They do not reproduce PackClient's GDI capture, session acquisition, worker lifetime, external peer, or any downstream forwarding of captured pixels. See [Screenshot IPC](screenshot-ipc.md) and [Scope and limitations](limitations.md).
