# Prior work and contribution

Prior-art review cut-off: **9 September 2026 (UTC)**.

## Public reporting

Proofpoint's **27 August 2026** [Carry-On Compromise: TA4922 Packs PackClient](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) documents the TA4922 campaign context, Tax Notice lineage, PackClient's modular Launcher/Core architecture, representative `PLH1`, `PLC1`, `PLA1`, `PLK1` and `PV10` markers, and existing Emerging Threats coverage.

Deception.Pro's [*New PackClient & HOK (Aug 2026)*](https://blog.deception.pro/blog/new-packclient-hok-aug2026) provides later hands-on-keyboard and attacker-controlled ManageEngine context. That operator telemetry is prior public reporting; its private backend artifacts were not available to this research.

The [MalwareBazaar campaign ZIP](https://bazaar.abuse.ch/sample/7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a/) anchors the recovered `7108FF…F85A` lineage used in the [architecture](architecture.md).

## What this work contributes

| Contribution | Added detail | Evidence boundary |
|---|---|---|
| Launcher lower transport | Exact framing and type gates, fixed handshake fields, 42-byte HMAC transcript and authenticated CBC receive path | Recovered launcher build, now checked against successful historical captures. |
| Delivery/cache | Exact PLK1 sizes, sequence checks, optional raw LZ4, plaintext SHA-256 verification, cache-hit/fresh selection and required save/reload cycle | Eight transfers reconstruct the same Core; both active pull callers use slot 0. |
| Recovered Core | Byte-exact 985,088-byte DLL, all exports, Launcher ABI, six local keys, application envelope, plugin/update storage, ETCHOOK implementation, major subsystems and built-in PV10 producer | No plugin binary, deployed Core PSK or second Core build recovered. |
| Carrier and terminal loader | Signed-host `injection_initialize` call, call-return-address ABI, complete 11,647-byte Donut loader identity and parsed embedded instance | Runtime remote writes/thread hijacking are established; exact carrier write API/call site and instruction-pointer value remain unresolved. |
| Local screenshot IPC | Exact five-DWORD `1RCP` worker contract, BGRX layout, endpoint roles and process context | Worker half reconstructed. External peer and complete real exchange unrecovered. |
| Active-session continuity | Target selection, launch/environment token roles, bootstrap and argument semantics, spawn retries and drift replacement | Static contract. Successful runtime handoff was not observed. |
| Runtime corroboration | Memory/process evidence linking the package, A/B, persistence and local failed attempts, plus historical sandbox evidence of successful delivery | September reruns remained nonresponsive; no plugin delivery observed. |
| Defensive tooling | Passive parsers, metadata dissector, detections, synthetic regression tests and a real positive Launcher-flow check | Core phase handling and production accuracy remain unmeasured. |

Searches through the cut-off found no indexed detailed treatment of the recovered `1RCP` worker contract, `scr_cap_worker`, or the launcher's PLK1/HMAC behavior. These areas are therefore described here as **previously underdocumented**.
