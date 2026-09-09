# Transport, authentication, and delivery

This is a byte-level reference for the recovered `PackClientLauncher.exe` build identified in [architecture](architecture.md). It documents the reconstructed wire contract. All multi-byte fields are little-endian unless explicitly marked otherwise.

## Outer framing

| Wire offset | Size | Field | Rule |
|---:|---:|---|---|
| `0x00` | 4 | `frame_word` | `0x5A400000` bitwise OR `body_length` |
| `0x04` | 4 | `type` | First DWORD of body |
| `0x08` | variable | Payload | `body_length - 4` bytes |

Receive requires `(frame_word >> 22) == 0x169`, a nonzero low-22-bit body length no larger than `0x3FFFFF`, the complete declared body, and at least four body bytes before reading the type. Send produces type `0x15`; its application payload ceiling is `0x3FFFFB`. Exact I/O loops fail when Winsock `send` or `recv` returns zero or a negative value.

The bytes `24 00 40 5A` are only a length word declaring a 36-byte body, hence a 40-byte total frame. They are not a complete message. TCP packet boundaries do not define protocol objects.

The shared syntactic validator accepts decimal `1–3` and `10–23`. Its two receive callers apply a stricter semantic gate: direct type `0x15`, or outer type `0x16` decrypting to inner type `0x15`. Other syntactically accepted values have no constructed or dispatched meaning in B. Type `0x16` is inbound-only in this build.

Relevant B RVAs: exact receive `0x54D1`; framed receive `0x550A`; exact send `0x56BC`; framed send `0x56F5`; generic type validator `0x3039`.

## Handshake

The reconstructed order is client PLH1, server PLC1, then client PLA1. B sends PLH1 and PLA1 inside outer type `0x15`. It accepts PLC1 directly inside type `0x15`, or inside an authenticated outer `0x16` envelope whose decrypted inner type is `0x15`. That first receive occurs at `0x34F6`, before Core loading; the encrypted branch requires initialized envelope-key state. B checks no separate post-PLA1 acknowledgement in handshake function `0x344A–0x37AF`.

### PLH1: client hello, 32 bytes

| Offset | Size | Value/source |
|---:|---:|---|
| `0x00` | 4 | ASCII `PLH1` |
| `0x04` | 2 | Version 1 |
| `0x06` | 2 | `0x20`; semantic name unresolved |
| `0x08` | 4 | Zero; semantic name unresolved |
| `0x0C` | 4 | One; semantic name unresolved |
| `0x10` | 8 | `GetTickCount64()` |
| `0x18` | 4 | `GetCurrentProcessId()` |
| `0x1C` | 4 | Zero |

### PLC1: server challenge, 24 bytes

| Offset | Size | Value/use |
|---:|---:|---|
| `0x00` | 4 | ASCII `PLC1`, checked |
| `0x04` | 2 | Version 1, checked |
| `0x06` | 2 | Unknown; received but not validated or authenticated |
| `0x08` | 16 | Server-supplied challenge |

The recovered client does not generate the server challenge.

### PLA1: client authentication, 40 bytes

| Offset | Size | Value |
|---:|---:|---|
| `0x00` | 4 | ASCII `PLA1` |
| `0x04` | 2 | Version 1 |
| `0x06` | 2 | Zero |
| `0x08` | 32 | HMAC-SHA-256 result |

`BCryptOpenAlgorithmProvider` with `SHA256` and HMAC flag `0x8` establishes the MAC construction. The transcript is exactly 42 bytes:

```text
HMAC-SHA-256(
    key = selected_psk_bytes,
    data = PLH1[0x10:0x20]
         || PLC1[0x08:0x18]
         || PLH1[0x0C:0x10]
         || PLH1[0x06:0x08]
         || ASCII "PLK1"
)
```

Its source lengths are 16 + 16 + 4 + 2 + 4. The handshake magic/version fields and PLC1's unknown word are not included. PLA1 is not plain SHA-256.

The PSK is the nonempty narrow environment value `PACK_LAUNCH_PSK`; missing, null, empty or failed lookup selects the 19-byte ASCII fallback `pack-launch-dev-psk`. Bytes are used verbatim up to `strlen`: no trimming, hex decoding or terminating NUL is included. A whitespace-only value is nonempty.

## Authenticated receive envelope

Outer type `0x16` carries this payload:

| Envelope offset | Size | Field |
|---:|---:|---|
| `0x00` | 1 | Version, must be 1 |
| `0x01` | 16 | Wire-provided IV |
| `0x11` | 4 | Unsigned **big-endian** ciphertext length `C` |
| `0x15` | `C` | AES-256-CBC ciphertext |
| `0x15 + C` | 32 | HMAC-SHA-256 tag |

The exact envelope length is `C + 0x35`. HMAC covers `envelope[0:0x15+C]`: version, IV, encoded length and ciphertext. It excludes the outer frame word, outer type DWORD and trailing tag. B compares the tag as eight DWORDs with early exit, then decrypts only after a match. This comparison is not constant time.

The AES helper uses a separate 32-byte key, `ChainingModeCBC`, a mutable copy of the wire IV, and `BCryptDecrypt` with `BCRYPT_BLOCK_PADDING`. The output must contain at least four bytes and begin with inner LE32 type `0x15`; bytes following that type return to the handshake or PLK1 caller. Successful CBC/padding acceptance is delegated to BCrypt.

### Key-state boundary

| B RVA | Size | Purpose |
|---:|---:|---|
| `0x41C44` | 1 | Nonzero readiness gate |
| `0x41C48` | 32 | AES key |
| `0x41C68` | 32 | Envelope HMAC key |

These lie beyond the `.data` file-backed end at RVA `0x41C00` and begin zero-filled. The parser locks a separate state object, checks readiness, copies the keys into two local buffers, then unlocks before authentication/decryption. Zero readiness causes generic framed-receive failure. The code does not test the key arrays themselves for all-zero content.

No initializer or writer for these globals was found in A, B, or the recovered outer components. A's mapper leaves the region zero-initialized, and the handshake PSK does not flow into this key state; no KDF was recovered.

Key initialization therefore remains unresolved. The earliest encrypted read occurs after PLH1 and before Core loading, so later Core acquisition cannot account for the initial key state.

Relevant B RVAs: parser `0xF30E`; AES helper `0xF028`; readiness read `0xF34F`; key source reads `0xF373` and `0xF380`; sole parser call `0x55CC`.

## PLK1 delivery and cache

The header is exactly `0x38` (56) application bytes after lower framing/type removal.

| Offset | Size | Field | Recovered interpretation |
|---:|---:|---|---|
| `0x00` | 4 | Magic | ASCII `PLK1` |
| `0x04` | 2 | Wire version | 1 or 2 |
| `0x06` | 1 | LZ4 flag | Nonzero enables decompression only for version 2 |
| `0x07` | 1 | Reserved | No use established |
| `0x08` | 8 | `total_size` | Transferred byte count |
| `0x10` | 8 | `orig_size` | Original plaintext size for version 2 |
| `0x18` | 32 | SHA-256 | Expected final plaintext digest |

Effective transferred and plaintext sizes must be nonzero, fit a DWORD and not exceed `0x08000000` (128 MiB). Version 1 disables LZ4 and uses `total_size` as plaintext size. Version 2 uses `orig_size`.

The first `TryLoad(slot, expected_digest, out)` is evaluated against this header. A hit sends LE32 control 2 and returns verified cached plaintext without receiving chunks. A miss sends LE32 control 1 and allocates the validated wire-size vector.

Each fresh chunk is a separate lower-framed application object:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | 4 | Sequence, initially zero |
| `0x04` | 4 | Nonzero data length |
| `0x08` | variable | Exactly that many bytes |

The received object must be exactly `8 + length`; sequence must match; the 64-bit cursor plus length must not exceed `total_size`. B copies the chunk, sends the accepted sequence as a four-byte acknowledgement, increments the expected sequence, and finishes only at exact total-size equality.

With LZ4 enabled, an explicitly sized raw-block decode produces exactly `orig_size` bytes. This is not an LZ4-frame stream. After optional decompression, SHA-256 of the final plaintext must match the header digest.

### Mandatory cache round trip

Fresh verified plaintext is not returned directly. Save must succeed, then immediate TryLoad must succeed with a nonempty vector, and that reload becomes the caller's result. Save failure, reload failure, malformed framing, sequence errors or hash failure returns no successful vector.

| Cache object | Relative layout |
|---|---|
| Protected blob | `<base>\pluginsdata\x86\blobs\<slot filename>.pblob` |
| Metadata | `<base>\pluginsdata\x86\meta\<slot filename>.json` |

The absolute base is unresolved. Slot 1 names `PackClientCore.secondary.dll`, while all other selector values name `PackClientCore.primary.dll`. Both reachable pull calls use slot 0; no failover, promotion or cross-slot path was found.

Save uses description `PackMonitorClient.PluginStore`, optional-entropy identifier `PackMonitorClient.PluginStore.v1`, and metadata encoding label `dpapi_current_user_v1`. The resolved CryptProtect/Unprotect capabilities and dataflow strongly support current-user DPAPI protection. Its metadata template is:

```json
{"version":1,"file":"%s","sha256":"%s","enc":"dpapi_current_user_v1","blob":"%s","root":"%s"}
```

TryLoad recomputes paths from the slot; it does not trust the metadata's `file`, `enc`, `blob` or `root` fields for selection. It requires a 64-character matching metadata digest, unprotects the blob, and independently hashes the plaintext before returning it. Blob/metadata writers use a `.tmp` file then `MoveFileExW(..., 9)`, meaning same-target replace plus write-through; failure cleanup deletes the temporary file.

Relevant B RVAs: pull `0x37AF`; transfer body `0x3A49`; header receive `0x3AB8`; initial TryLoad `0x3C46`; chunk receive `0x3DE1`; LZ4 boundary `0x3FAC`; plaintext hash verification `0x418C`; Save `0x4200 -> 0xD899`; reload `0x4263 -> 0xDCE3`; vector-to-PE handoff `0x4938 -> 0x10591 -> 0x10136`.

## Historical positive-flow validation

Triage runs `260715-wd77daas7l` and `260716-dhnz7aft6z` each preserve four complete PLK1 transfers. The sender-declared values are version 2, raw LZ4, transferred size 669,717, original size 985,088 and plaintext SHA-256 `4DE6EF8647FB4B599966A233740CB0514D1E71B8019A1A1792ED7E1E514EDF1C`.

Each transfer uses eleven ordered type-`0x15` chunk records: sequences 0–9 carry 65,536 bytes and sequence 10 carries 14,357 bytes. Concatenation produces a 669,717-byte compressed derivative with SHA-256 `502A7D2D72BEFA9114417936A1B3C2DD8EC84FCD4AE9EF9A09FFF3604FC05CCE`; raw-LZ4 decompression produces the declared 985,088-byte Core and exact plaintext digest.

The captures also validate the ordered plaintext handshake `PLH1 -> PLC1 -> PLA1 -> PLK1` and then carry bidirectional Core traffic. The filtered PCAPNG used to validate the Wireshark Lua dissector is a derivative of `260715-wd77daas7l/behavioral1`, 762,668 bytes, SHA-256 `AB437D0EAE5E3C93764B89A3ECC5F6940D3CBEE0C2BE8D80D34CD7CB4CA38875`.

### Type-0x16 is phase-dependent

The recovered Core has its own authenticated type-`0x16` format with a little-endian ciphertext length and key material derived from local `auth_psk` using PBKDF2-HMAC-SHA-256 (100,000 iterations; salt `PackClientCore.AppAuth`; 64 derived bytes split into AES/HMAC material). This differs from the Launcher's pre-Core type-`0x16` envelope above, whose ciphertext length is big-endian and whose key-state writer remains unresolved.

Parsers must therefore select the type-`0x16` layout by Launcher/Core phase; the common outer type number is not a sufficient discriminator. Full Core behavior and validation boundaries are in the [Core and artifact audit](core-and-artifact-audit.md).

## Validation

The [tooling reference](tooling.md) provides offline parsers and synthetic fixtures for the structures documented above. The historical capture now provides independent positive-flow validation for the Launcher dissector. Runtime coverage and unresolved boundaries are summarized in [evidence](evidence.md) and [limitations](limitations.md).
