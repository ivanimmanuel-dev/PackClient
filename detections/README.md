# Detection content

These rules turn the documented PackClientLauncher findings into detection and hunting candidates.

| Path | Purpose |
|---|---|
| `sigma/` | Windows process and task behavior |
| `yara/` | Recovered-launcher marker constellation |
| `suricata/` | Candidate plaintext handshake prefixes, including version bytes, at any offset in reassembled TCP data |

The rules are experimental and should be tuned to local telemetry. See [`docs/detection-guide.md`](../docs/detection-guide.md) for evidence, correlation guidance, and false-positive boundaries.

The CI engine job compiles YARA, converts and executes Sigma with a SQLite backend, and runs Suricata against synthetic captures. Positive and negative cases cover renaming, token boundaries, segmentation, coalescing, and wrong versions. These tests validate rule mechanics rather than production sensitivity or specificity. Suricata signatures are candidate selectors, not complete protocol validators.
