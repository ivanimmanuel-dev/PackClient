# Detection

Detection and hunting rules derived from the PackClient Launcher behavior.

| Path | Purpose |
|---|---|
| `sigma/` | Process creation, scheduled-task persistence, and screenshot-worker behavior |
| `yara/` | Static marker constellation for the recovered Launcher |
| `suricata/` | Regression checks for plaintext Launcher handshake markers in reassembled TCP traffic |

These are hunting candidates, not production-ready detections. Validate them against local telemetry before deployment. See the [detection guide](../docs/detection-guide.md) for supporting evidence, correlation guidance, and false-positive considerations.

CI compiles the Launcher YARA rule, converts and executes the Sigma rules with a SQLite backend, and runs Suricata against synthetic captures. Positive and negative tests cover file renaming, argument boundaries, TCP segmentation and coalescing, and incorrect protocol versions. These tests verify rule behavior; they do not measure production accuracy.

The Suricata rules intentionally reproduce existing handshake-marker coverage for local regression testing. They are not presented as new detections or complete protocol validators.
