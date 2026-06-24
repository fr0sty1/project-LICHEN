# OTA Firmware Updates

Over-the-air firmware update protocol.

## Message Flow

```
Host                          Device
  |                              |
  |------ ota_begin (0x50) ----->|
  |<----- ota_status (0x53) -----|  (ready or error)
  |                              |
  |------ ota_chunk (0x51) ----->|
  |<----- ota_status (0x53) -----|  (progress)
  |------ ota_chunk (0x51) ----->|
  |<----- ota_status (0x53) -----|
  |           ...                |
  |                              |
  |----- ota_finish (0x52) ----->|
  |<----- ota_status (0x53) -----|  (verifying)
  |<----- ota_status (0x53) -----|  (complete or failed)
  |                              |
  |      (device reboots)        |
```

## CDDL

```cddl
ota_begin = {
  0: 0x50,                    ; message type
  1: uint,                    ; total size (bytes)
  2: bstr .size 32,           ; SHA-256 hash of firmware
  ? 3: tstr,                  ; firmware version string
  ? 4: uint,                  ; chunk size (default 512)
  ? 5: tstr,                  ; hardware compatibility tag
}

ota_chunk = {
  0: 0x51,                    ; message type
  1: uint,                    ; offset (bytes from start)
  2: bstr,                    ; chunk data
}

ota_finish = {
  0: 0x52,                    ; message type
  ? 1: bool,                  ; auto-reboot (default true)
}

ota_status = {
  0: 0x53,                    ; message type
  1: ota_state,               ; current state
  ? 2: uint,                  ; bytes received
  ? 3: uint,                  ; total bytes
  ? 4: result_code,           ; error code (if failed)
  ? 5: tstr,                  ; error message
}

ota_state = &(
  idle: 0,
  receiving: 1,
  verifying: 2,
  complete: 3,
  failed: 4,
  rebooting: 5,
)
```

## Fields

### ota_begin

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x50 | Message type |
| 1 | size | uint | Total firmware size in bytes |
| 2 | hash | bstr | SHA-256 of complete firmware |
| 3 | version | tstr | Target version string |
| 4 | chunk_size | uint | Suggested chunk size (default 512) |
| 5 | hw_compat | tstr | Hardware compatibility string |

### ota_chunk

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x51 | Message type |
| 1 | offset | uint | Byte offset from start |
| 2 | data | bstr | Chunk payload |

### ota_status

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x53 | Message type |
| 1 | state | uint | Current OTA state |
| 2 | received | uint | Bytes received so far |
| 3 | total | uint | Total expected bytes |
| 4 | error | uint | Error code if failed |
| 5 | error_msg | tstr | Human-readable error |

## Chunk Delivery

- Chunks can arrive out of order (device tracks bitmap)
- Host should wait for ota_status after each chunk (flow control)
- On timeout, host can resend chunk
- Device responds with current received count

## Verification

After ota_finish:
1. Device computes SHA-256 of received data
2. Compares to hash from ota_begin
3. If match: marks update as pending, sends complete status
4. If mismatch: sends failed status, discards data

## Example

Begin 128KB update:
```cbor-diag
{
  0: 80,                      / ota_begin /
  1: 131072,                  / 128 KB /
  2: h'abc123...',            / SHA-256 /
  3: "lichen-0.2.0",
  4: 512
}
```

Send chunk:
```cbor-diag
{0: 81, 1: 0, 2: h'...512 bytes...'}
{0: 81, 1: 512, 2: h'...512 bytes...'}
```

Status during transfer:
```cbor-diag
{0: 83, 1: 1, 2: 1024, 3: 131072}  / receiving, 1KB of 128KB /
```

Complete:
```cbor-diag
{0: 83, 1: 3}  / complete /
```
