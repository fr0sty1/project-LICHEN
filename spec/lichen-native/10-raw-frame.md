# Raw Frame Access

Send and receive raw link-layer frames for debugging and protocol development.

## Use Cases

- Protocol debugging (inspect actual on-air frames)
- Custom experiments (bypass normal stack)
- Packet capture / injection
- Testing link-layer features

## Message Flow

```
Host                          Device
  |                              |
  |------- raw_tx (0x60) ------->|  (transmit raw frame)
  |                              |
  |<------ raw_rx (0x61) --------|  (received raw frame)
```

Raw frames bypass the normal IPv6/UDP stack. Device transmits exactly what host provides (after adding PHY preamble/sync).

## CDDL

```cddl
raw_tx = {
  0: 0x60,                    ; message type
  1: bstr,                    ; raw frame bytes
  ? 2: int,                   ; TX power override (dBm)
  ? 3: uint,                  ; frequency override (Hz)
  ? 4: bool,                  ; wait for TX complete before responding
}

raw_rx = {
  0: 0x61,                    ; message type
  1: bstr,                    ; raw frame bytes
  2: rssi,                    ; receive RSSI
  ? 3: snr,                   ; receive SNR
  ? 4: uptime_ms,             ; receive timestamp
  ? 5: uint,                  ; frequency (Hz)
  ? 6: bool,                  ; CRC valid
}
```

## Fields

### raw_tx

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x60 | Message type |
| 1 | frame | bstr | Raw bytes to transmit |
| 2 | power | int | TX power (dBm), omit for default |
| 3 | freq | uint | Frequency (Hz), omit for default |
| 4 | wait | bool | Wait for TX complete (default false) |

### raw_rx

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x61 | Message type |
| 1 | frame | bstr | Received raw bytes |
| 2 | rssi | int | RSSI (dBm) |
| 3 | snr | int | SNR (dB) |
| 4 | time | uint | Uptime when received |
| 5 | freq | uint | Receive frequency |
| 6 | crc_ok | bool | CRC validation result |

## Enabling Raw Mode

Raw frame reception is off by default. Enable via config:

```cbor-diag
{0: 17, 1: {64: true}}  / config_set raw_rx_enable=true /
```

Config key 64 = `raw_rx_enable`.

When enabled:
- Device sends raw_rx for ALL received frames
- Normal stack processing continues (frames are copied, not diverted)

## Security Note

Raw mode enables:
- Transmitting arbitrary frames (could violate regulations)
- Observing all traffic (including encrypted payloads)

Implementations MAY:
- Require PIN/confirmation to enable
- Rate-limit raw TX
- Disable in production builds

## Example

Transmit a raw frame:
```cbor-diag
{
  0: 96,                      / raw_tx /
  1: h'c1020304...',          / LICHEN frame bytes /
  4: true                     / wait for complete /
}
```

Received raw frame:
```cbor-diag
{
  0: 97,                      / raw_rx /
  1: h'c1020304...',          / frame bytes /
  2: -85,                     / RSSI /
  3: 9,                       / SNR /
  4: 3662000,                 / timestamp /
  6: true                     / CRC valid /
}
```
