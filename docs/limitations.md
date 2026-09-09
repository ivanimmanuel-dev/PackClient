# Scope and limitations

This publication reconstructs one PackClient launcher build and its independently recovered Core, supported by local runtime evidence and historical public sandbox artifacts.

## Unresolved boundaries

| Boundary | Established | Not established |
|---|---|---|
| Core | Eight PLK1 transfers reconstruct the same 985,088-byte DLL; exports, major subsystems and mapped `.text` identity recovered | Server implementation, every internal function's semantic name, or a second Core build |
| Plugins | Modern ABI and legacy loader, request/cache grammar and feature bindings | Any delivered plugin binary or observed `CLIENTCOREUPD` transaction |
| Screenshot peer | Worker command grammar, endpoint open and five-DWORD `1RCP` contract | Endpoint creator, initial launcher, peer identity or downstream pixel consumer |
| Screenshot runtime | Real worker reached the capture/copy path; final attempt shows an AV and zero-byte READY timeout | Completed real exchange or causal failure diagnosis |
| DIB lifetime | Deletion call precedes the later bits-pointer copy | Successful deletion return or causal use-after-free proof |
| Envelope keys | Separate 32-byte AES and HMAC key globals gated by a ready byte | Key values, derivation, initializer/writer, activation time or successful encrypted receive |
| In-memory launcher state | Package/A/B private mappings, exact PE/section anchors, A-entry thread, section-backed remote mapping and primary-thread redirection | A second carrier build or complete runtime trace of every native call |
| Network | Local sessions show timeout/failed SYNs; historical July captures show full Launcher handshake, PLK1 and Core traffic | Server implementation, September response cause, or plugin delivery |
| Session continuity | Exact token, spawn and drift logic | Successful runtime active-session replacement |
| Mutex export | Exact close-and-clear effect | External caller or invocation |

## Reproduction gaps

1. **Some PID 3696 event counts and memory comparisons relied on analyst-created helpers whose source and exact invocations were not retained.** This limits independent reproduction of those measurements.
2. **The eight-byte package difference is not fully explained.** The recorded comparison contains three changed ranges totaling eight bytes. Three straightforward 6666-to-443 substitutions explain six of them; the remaining two require the original per-site before/after bytes to resolve.

## Runtime evidence limits

The PID 5812 Procmon capture spans 9.48 seconds and begins 44 minutes 45 seconds after the process started. It therefore does not cover the launch or the earlier connection attempt.

The PID 3696 session contains multiple interrupted launches and manual intervention, so its observations are treated as scoped events rather than one uninterrupted baseline. Its packet capture has no PID metadata; Process Explorer directly associates PID 3696 with specific `SYN_SENT` sockets, but that does not assign every captured packet to the process.

Each original local dump is a point-in-time user-mode capture and did not independently expose Core. The later historical Triage packet/memory audit recovers Core separately; that does not retroactively place Core into either original local dump.

## Tool and detection validation

Synthetic tests validate framing, cryptography, parsing, reassembly, rejected-input handling and detector mechanics against controlled fixtures. A filtered historical positive flow now validates Launcher dissector recognition, but does not measure production detection accuracy.

The [screenshot IPC kit](screenshot-ipc-validation.md) validates the reconstructed `1RCP` framing and synthetic image serialization. It does not reproduce GDI capture, the observed worker failure or a completed exchange with the real worker.

Established historical PackClient captures are available, but no representative benign/malicious corpus was measured, so sensitivity, specificity and false-positive rates remain unmeasured. Parsing and resource limits are documented in [tooling](tooling.md), with operational detection limits in [detection guidance](detection-guide.md).

## Generalization

No second carrier variant was acquired for byte-level comparison. These conclusions therefore apply to the [pinned build](architecture.md), not every PackClient deployment.
