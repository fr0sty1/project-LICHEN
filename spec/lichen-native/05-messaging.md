# Application Messaging

Send and receive application-layer messages through the mesh.

## Message Flow

```
Host                          Device                        Mesh
  |                              |                            |
  |---- send_message (0x20) ---->|                            |
  |                              |--------- transmit -------->|
  |                              |                            |
  |                              |<-------- receive ----------|
  |<-- message_received (0x21) --|                            |
```

## CDDL

```cddl
send_message = {
  0: 0x20,                    ; message type
  1: address,                 ; destination (IID or IPv6)
  2: bstr,                    ; payload
  ? 3: uint,                  ; destination port (default 5683 = CoAP)
  ? 4: uint,                  ; source port (default ephemeral)
  ? 5: bool,                  ; request acknowledgment
  ? 6: uint,                  ; message ID (for correlation)
  ? 7: uint,                  ; TTL / hop limit (default 64)
}

message_received = {
  0: 0x21,                    ; message type
  1: address,                 ; source address
  2: bstr,                    ; payload
  ? 3: uint,                  ; source port
  ? 4: uint,                  ; destination port
  ? 5: rssi,                  ; receive RSSI
  ? 6: snr,                   ; receive SNR
  ? 7: uint,                  ; hop count (from IPv6 hop limit delta)
  ? 8: uint,                  ; message ID (if this is an ACK)
}

; For ACK requests, device sends message_received back to host
; with key 8 set to the original message ID when ACK arrives

send_ack = {
  0: 0x22,                    ; message type
  1: uint,                    ; message ID being acknowledged
  2: result_code,             ; delivery result
  ? 3: uint,                  ; round-trip time (ms)
}
```

## Fields

### send_message

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x20 | Message type |
| 1 | dest | address | Destination IID (8 bytes) or IPv6 (16 bytes) |
| 2 | payload | bstr | Application payload |
| 3 | dest_port | uint | UDP destination port (default 5683) |
| 4 | src_port | uint | UDP source port (default ephemeral) |
| 5 | ack | bool | Request delivery acknowledgment |
| 6 | msg_id | uint | Correlation ID for ACK |
| 7 | ttl | uint | Hop limit (default 64) |

### message_received

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x21 | Message type |
| 1 | src | address | Source address |
| 2 | payload | bstr | Application payload |
| 3 | src_port | uint | UDP source port |
| 4 | dest_port | uint | UDP destination port |
| 5 | rssi | int | RSSI of final hop (dBm) |
| 6 | snr | int | SNR of final hop (dB) |
| 7 | hops | uint | Estimated hop count |
| 8 | msg_id | uint | If ACK, the original message ID |

## Example

Send a CoAP request:
```cbor-diag
{
  0: 32,                      / send_message /
  1: h'0123456789abcdef',     / dest IID /
  2: h'500100...',            / CoAP GET /
  5: true,                    / request ACK /
  6: 42                       / msg_id for correlation /
}
```

Receive a message:
```cbor-diag
{
  0: 33,                      / message_received /
  1: h'fedcba9876543210',     / source IID /
  2: h'600245...',            / CoAP response /
  3: 5683,                    / src port /
  5: -85,                     / RSSI /
  6: 8                        / SNR /
}
```
