# Prior work and contribution

Prior-art review cut-off: **5 September 2026 (UTC)**.

## Public reporting

Proofpoint's **27 August 2026** [Carry-On Compromise: TA4922 Packs PackClient](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) documents the TA4922 campaign context, Tax Notice lineage, PackClient's modular Launcher/Core architecture, representative `PLH1`, `PLC1`, `PLA1`, `PLK1` and `PV10` markers, and existing Emerging Threats coverage.

The [MalwareBazaar campaign ZIP](https://bazaar.abuse.ch/sample/7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a/) anchors the recovered `7108FF…F85A` lineage used in the [architecture](architecture.md).

## What this work contributes

| Contribution | Added detail | Evidence boundary |
|---|---|---|
| Launcher lower transport | Exact framing and type gates, fixed handshake fields, 42-byte HMAC transcript and authenticated CBC receive path | Recovered launcher build. No successful session captured. |
| Delivery/cache | Exact PLK1 sizes, sequence checks, optional raw LZ4, plaintext SHA-256 verification, cache-hit/fresh selection and required save/reload cycle | Core bytes were not recovered. Both active pull callers use slot 0. |
| Local screenshot IPC | Exact five-DWORD `1RCP` worker contract, BGRX layout, endpoint roles and process context | Worker half reconstructed. External peer and complete real exchange unrecovered. |
| Active-session continuity | Target selection, launch/environment token roles, bootstrap and argument semantics, spawn retries and drift replacement | Static contract. Successful runtime handoff was not observed. |
| Runtime corroboration | Memory and process evidence linking the transformed package, mapped A/B, A-entry thread, persistence and failed outbound attempts | Upstream placement/injection mechanism, Core and successful C2 remain unresolved. |
| Defensive tooling | Passive parsers, metadata dissector, detections and synthetic regression tests | Mechanics tested. Real-capture compatibility and production accuracy remain unmeasured. |

Searches through the cut-off found no indexed detailed treatment of the recovered `1RCP` worker contract, `scr_cap_worker`, or the launcher's PLK1/HMAC behavior. These areas are therefore described here as **previously underdocumented**.
