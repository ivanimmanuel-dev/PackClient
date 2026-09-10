# Scope and limitations

This report covers one PackClient Launcher build and the Core DLL recovered directly from its historical PLK1 traffic. Other PackClient builds and deployments may use different components, configuration, infrastructure, or protocol behavior.

## Unresolved behavior

- **Carrier injection:** Runtime evidence shows remote package writes followed by primary-thread context hijacking in a suspended `SysWOW64\svchost.exe`. The carrier's exact write call site and the instruction-pointer value installed by `SetThreadContext` remain unknown.

- **Launcher encryption:** The Launcher's type-`0x16` envelope format and AES/HMAC key storage were recovered, but no code initializing those keys was found. The Core uses a separate, fully recovered key derivation based on `auth_psk`.

- **Plugins and Core updates:** The Core implements modern and legacy plugin loading, staged delivery, protected storage, activation, and update handling. No delivered plugin binary, paired plugin cache, activated plugin mapping, or completed Core-update transaction was recovered.

- **Screenshot paths:** The Launcher's `1RCP` message format and framebuffer layout were recovered, but no complete exchange with the real worker was captured. The external peer, endpoint creator, downstream framebuffer consumer, and any bridge between Launcher `1RCP` and Core `PV10` remain unknown. The observed bitmap-deletion order alone does not prove a causal use-after-free.

- **Active-session handoff:** Token selection, process creation, argument handling, and session-drift behavior were recovered from the Launcher. No successful replacement into another interactive session was observed.

- **Server behavior:** Historical July traffic contains successful authentication, Core delivery, and post-delivery commands. Later runs sent valid `PLH1` greetings but received no application response. The server implementation and the reason for that later non-response are unknown.

## Runtime and capture limits

The local runtime sessions provide point-in-time evidence rather than complete execution traces. One Procmon capture began well after process creation, while another session included interrupted and manually initiated launches.

The local packet capture does not contain process identifiers. Process Explorer associated specific `SYN_SENT` sockets with the PackClient surrogate, but this does not attribute every captured packet to that process.

Neither local process dump contained an independently identifiable Core image. The Core was recovered separately from historical Triage traffic and memory, so its presence must not be retroactively attributed to those local dumps.

## Detection and tooling limits

The synthetic tests exercise framing, cryptography, reassembly, malformed-input handling, screenshot-message serialization, and detection-rule mechanics. They do not reproduce the complete malware execution chain or establish production detection accuracy.

The included rules are experimental hunting candidates. Their sensitivity, specificity, and false-positive rates have not been measured against representative benign and unrelated-malware corpora. The Suricata rules recognize plaintext Launcher prefixes but do not validate the complete session or Core phase.

Additional technical context is available in [Evidence](evidence.md), [Runtime analysis](runtime-analysis.md), [Screenshot IPC](screenshot-ipc.md), [Launcher protocol](launcher-protocol.md), and the [Detection guide](detection-guide.md).
