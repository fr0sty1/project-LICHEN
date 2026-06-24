# Hello Handshake

Connection initialization and capability negotiation.

## Sequence

```
Host                          Device
  |                              |
  |-------- hello (0x01) ------->|
  |                              |
  |<------- hello (0x01) --------|
  |                              |
  |  (connection established)    |
```

Both sides send hello. No strict ordering — either can send first.

## CDDL

```cddl
hello = {
  0: 0x01,                    ; message type
  1: protocol_version,        ; sender's protocol version
  2: [* message_type],        ; supported message types
  3: tstr,                    ; firmware/software version string
  ? 4: iid,                   ; device IID (device→host only)
  ? 5: tstr,                  ; device name (user-assigned)
  ? 6: uint,                  ; max message size supported
  ? 7: features,              ; feature flags
}

protocol_version = uint       ; starts at 1

features = {
  ? 1: bool,                  ; supports OTA
  ? 2: bool,                  ; supports raw frames
  ? 3: bool,                  ; supports log streaming
  ? 4: bool,                  ; has GPS
  ? 5: bool,                  ; has battery monitor
}
```

## Fields

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x01 | Message type = hello |
| 1 | version | uint | Protocol version (current: 1) |
| 2 | supported | [uint] | List of message type codes this endpoint handles |
| 3 | firmware | tstr | Version string, e.g. "lichen-0.1.0" or "lichen-tui-0.1.0" |
| 4 | iid | bstr | Device's 8-byte IID (device only) |
| 5 | name | tstr | User-assigned device name |
| 6 | max_size | uint | Max CBOR payload size (default 4096) |
| 7 | features | map | Optional capability flags |

## Version Negotiation

Use minimum of both sides' protocol version. If versions are incompatible (e.g., device requires features host doesn't support), device MAY close connection.

## Example

Device hello:
```cbor-diag
{
  0: 1,                           / type = hello /
  1: 1,                           / protocol version /
  2: [1, 16, 17, 18, 32, 33, 48, 49],  / supported types /
  3: "lichen-fw-0.1.0",           / firmware /
  4: h'0123456789abcdef',         / IID /
  5: "sensor-north",              / name /
  7: {1: true, 4: true}           / OTA + GPS /
}
```
