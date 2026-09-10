# Detection

Detection and hunting rules derived from the observed PackClient execution chain, recovered Launcher and reconstructed Core.

| Path | Purpose |
|---|---|
| `sigma/` | Process creation, scheduled-task persistence, and screenshot-worker behavior |
| `yara/` | Compiled marker constellations for the recovered Launcher and Core |
| `suricata/` | Reassembled-stream regression rules for Launcher markers, challenge-to-PLK1 progression, Core startup and startup-to-`PV10` correlation |

These are hunting candidates, not production-ready detections. Validate them against local telemetry before deployment. See the [detection guide](../docs/detection-guide.md) for supporting evidence, correlation guidance, and false-positive considerations.

CI compiles both YARA rules, converts and executes the Sigma rules through the pySigma SQLite backend, runs Suricata against positive and negative synthetic captures, and exercises the Lua dissector through TShark. The tests cover file renaming, argument boundaries, protocol versions, TCP segmentation and coalescing, Launcher delivery progression, Core startup and `PV10` correlation.

The compiled Launcher rule matched all 86 retained Launcher memory mappings and none of 383 other retained objects. The Core rule matched the recovered DLL and all 352 retained Core mappings, with no matches among 116 Launcher/control allocations. Both rules also produced zero matches across a preliminary local scan of more than 30,000 Windows and installed-application PE files. These results do not replace testing against representative enterprise software and unrelated malware.

The standalone Suricata markers intentionally reproduce existing Emerging Threats coverage for local regression. The correlated rules add case-specific Launcher/Core state, but they are not complete protocol validators. All included rules remain experimental and should be tuned against local telemetry.
