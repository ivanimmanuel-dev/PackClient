# Prior work and contributions

## Public reporting

Proofpoint's [*Carry-On Compromise: TA4922 Packs PackClient*](https://www.proofpoint.com/us/blog/threat-insight/carry-compromise-ta4922-packs-packclient) documented the campaign's Tax Notice lineage, PackClient's Launcher/Core architecture, representative `PLH1`, `PLC1`, `PLA1`, `PLK1`, and `PV10` markers, and the associated Emerging Threats coverage.

Deception.Pro's [*New PackClient & HOK (Aug 2026)*](https://blog.deception.pro/blog/new-packclient-hok-aug2026) documented later PackClient activity and the attacker's use of compromised ManageEngine infrastructure.

## Pre-existing public artifacts

The [MalwareBazaar campaign ZIP](https://bazaar.abuse.ch/sample/7108ff29916d064216aa2ece7fb395f1e3a73d12d19895bffc0bd46806cbf85a/) provides the public Tax Notice lineage examined in the [Launcher architecture](launcher-architecture.md).

Three public Triage analyses supplied historical runtime and network evidence:

- [`260715-wd77daas7l`](https://tria.ge/260715-wd77daas7l/behavioral3) contains successful Launcher authentication, Core delivery, post-delivery commands, and `PV10` screenshot traffic.
- [`260716-dhnz7aft6z`](https://tria.ge/260716-dhnz7aft6z) contains another successful session delivering the same Core build.
- [`260828-py7ysahr4y`](https://tria.ge/260828-py7ysahr4y) records the suspended `SysWOW64\svchost.exe`, remote package placement, and primary-thread context hijacking used to start the injected chain.

## What this research adds

| Area | Contribution |
| --- | --- |
| Launcher transport | Recovered the outer framing, message-type gates, complete `PLH1`/`PLC1`/`PLA1` handshake, 42-byte authentication transcript, authenticated AES-256-CBC receive order, and PLK1 delivery logic. |
| Core recovery | Reconstructed a 985,088-byte x86 `PackClientCore.dll` directly from historical PLK1 traffic and confirmed that all eight complete transfers produce the same DLL. The recovery includes the eleven ordered type-`0x15` chunks, raw-LZ4 decompression, and plaintext SHA-256 verification. |
| Execution chain | Connected the signed host's imported carrier entry point to a suspended `SysWOW64\svchost.exe`, the remotely placed Donut package, unmanaged executable A, Launcher B, and the delivered Core. The Donut loader, embedded instance, terminal glue, and A-to-B mapping contract were also recovered. |
| PackClient Core | Mapped all 11 exports, the Launcher-to-Core ABI, six local settings, Core-specific type-`0x16` encryption, staged plugin delivery and cache behavior, DPAPI-protected Core updates, ETCHOOK clipboard replacement, major command handlers, and the built-in `PV10` screenshot producer. |
| Screenshot paths | Reconstructed the worker-side `1RCP` interface, including its five-DWORD header and top-down BGRX framebuffer. Core's separate `PV10` JPEG producer was also recovered; no direct bridge between the two paths was established. |
| Session continuity | Recovered active-session selection, token handling, bootstrap construction, process-creation retries, and session-drift replacement logic. |
| Persistence | Two September sandbox runs distinguished the normal full-EXE scheduled-task path from the direct-DLL `rundll32.exe` behavior produced by sandbox execution. |
| Defensive tooling | Added passive Launcher/Core stream decoding, verified PLK1 and `PV10` extraction with provenance manifests, a phase-aware Wireshark Lua dissector, synthetic protocol fixtures, engine-backed regression tests, and separate Launcher/Core YARA rules. |

Artifact identities and supporting observations are collected in [Evidence](evidence.md). Remaining unknowns and limits are documented in [Scope and limitations](limitations.md).
