# Common Types

Shared CDDL definitions used across message types.

## CDDL

```cddl
; All messages are CBOR maps with integer keys
; Key 0 is always the message type

message = {
  0: message_type,
  * int => any,
}

message_type = &(
  hello: 0x01,
  config_get: 0x10,
  config_set: 0x11,
  config_result: 0x12,
  send_message: 0x20,
  message_received: 0x21,
  mesh_state: 0x30,
  node_info: 0x31,
  log_entry: 0x40,
  log_subscribe: 0x41,
  ota_begin: 0x50,
  ota_chunk: 0x51,
  ota_finish: 0x52,
  ota_status: 0x53,
  raw_tx: 0x60,
  raw_rx: 0x61,
)

; 8-byte Interface Identifier (from public key)
iid = bstr .size 8

; Full IPv6 address
ipv6 = bstr .size 16

; Address can be IID (link-local assumed) or full IPv6
address = iid / ipv6

; Milliseconds since device boot
uptime_ms = uint

; Unix timestamp (seconds since 1970)
timestamp = uint

; RSSI in dBm (negative)
rssi = int

; SNR in dB (can be negative)
snr = int

; Sequence number for state sync
seq = uint

; Result codes
result_code = &(
  ok: 0,
  error: 1,
  invalid_param: 2,
  not_found: 3,
  busy: 4,
  not_supported: 5,
)
```

## Key Numbering Convention

To avoid collisions and aid debugging:

| Range | Purpose |
|-------|---------|
| 0 | Message type (always present) |
| 1-15 | Primary fields for this message type |
| 16-31 | Secondary/optional fields |
| 32+ | Reserved for extensions |

## Extensibility

- Receivers MUST ignore unknown keys
- Receivers MUST ignore unknown message types (log warning)
- Senders SHOULD NOT send keys the receiver doesn't support (via hello negotiation)
