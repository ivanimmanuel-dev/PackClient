# Detection

Detection and hunting rules derived from the observed PackClient execution chain, recovered Launcher and reconstructed Core.

| Path | Purpose |
|---|---|
| `sigma/` | Process creation, scheduled-task persistence, and screenshot-worker behavior |
| `yara/` | Compiled marker constellations for the recovered Launcher and Core |
| `suricata/` | Reassembled-stream regression rules for Launcher markers, challenge-to-PLK1 progression, Core startup and startup-to-`PV10` correlation |

These are hunting candidates, not production-ready detections. Validate them against local telemetry before deployment. See the [detection guide](../docs/detection-guide.md) for supporting evidence, correlation guidance, and false-positive considerations.

CI compiles both YARA rules, converts and executes the Sigma rules through the pySigma SQLite backend, runs Suricata against positive and negative synthetic captures, and exercises the Lua dissector through TShark. The tests cover file renaming, argument boundaries, protocol versions, TCP segmentation and coalescing, Launcher delivery progression, Core startup and `PV10` correlation.

Against the available case material, the Launcher rule matched all 86 Launcher memory mappings and none of the other 383 artifacts. The Core rule matched the recovered DLL and all 352 Core memory mappings, with no matches among 116 Launcher and control allocations. Both rules also returned zero matches across more than 30,000 Windows and installed-application PE files. This provides a useful initial false-positive check, but does not replace testing against representative enterprise software and unrelated malware.

The standalone Suricata rules mirror existing Emerging Threats marker coverage for regression testing. Additional rules correlate observed Launcher delivery and Core traffic, but do not validate an entire PackClient session. All included rules remain experimental and should be tuned for the environment in which they are deployed.
