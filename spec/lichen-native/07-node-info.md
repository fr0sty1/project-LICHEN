# Node Info

Device status, hardware info, and telemetry.

## Message Flow

```
Host                          Device
  |                              |
  |<------ node_info (0x31) -----|  (on connect)
  |                              |
  |<------ node_info (0x31) -----|  (periodic or on change)
```

Device sends node_info:
- After hello handshake
- Periodically (e.g., every 60s)
- When significant state changes (battery low, GPS fix acquired)

## CDDL

```cddl
node_info = {
  0: 0x31,                    ; message type
  1: iid,                     ; device IID
  ? 2: tstr,                  ; device name
  ? 3: tstr,                  ; firmware version
  ? 4: tstr,                  ; hardware model
  ? 5: uptime_ms,             ; uptime since boot
  ? 6: battery_info,          ; battery status
  ? 7: gps_info,              ; GPS position
  ? 8: radio_stats,           ; radio statistics
  ? 9: memory_info,           ; memory usage
}

battery_info = {
  1: uint,                    ; percentage (0-100)
  ? 2: uint,                  ; voltage (mV)
  ? 3: bool,                  ; charging
  ? 4: int,                   ; current (mA, negative = discharging)
}

gps_info = {
  1: int,                     ; latitude (microdegrees, divide by 1e6)
  2: int,                     ; longitude (microdegrees)
  ? 3: int,                   ; altitude (cm above sea level)
  ? 4: uint,                  ; horizontal accuracy (cm)
  ? 5: uint,                  ; satellites in view
  ? 6: timestamp,             ; fix timestamp (Unix seconds)
  ? 7: uint,                  ; speed (cm/s)
  ? 8: uint,                  ; heading (degrees, 0-359)
}

radio_stats = {
  1: uint,                    ; packets transmitted
  2: uint,                    ; packets received
  ? 3: uint,                  ; TX errors (no ACK, channel busy)
  ? 4: uint,                  ; RX errors (CRC fail, etc)
  ? 5: uint,                  ; channel busy detections
  ? 6: uint,                  ; duty cycle (permille, 0-1000)
}

memory_info = {
  1: uint,                    ; free heap bytes
  2: uint,                    ; total heap bytes
  ? 3: uint,                  ; stack high water mark
}
```

## Fields

### node_info

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x31 | Message type |
| 1 | iid | iid | Device IID |
| 2 | name | tstr | User-assigned name |
| 3 | firmware | tstr | Firmware version string |
| 4 | hardware | tstr | Hardware model (e.g., "rak4631", "nucleo_wl55jc") |
| 5 | uptime | uint | Milliseconds since boot |
| 6 | battery | map | Battery status |
| 7 | gps | map | GPS fix |
| 8 | radio | map | Radio statistics |
| 9 | memory | map | Memory usage |

## Example

```cbor-diag
{
  0: 49,                      / node_info /
  1: h'0123456789abcdef',     / IID /
  2: "sensor-north",          / name /
  3: "lichen-0.1.0",          / firmware /
  4: "rak4631",               / hardware /
  5: 3661000,                 / ~1 hour uptime /
  6: {1: 78, 2: 3950, 3: false},  / 78%, 3.95V, not charging /
  7: {1: 47606000, 2: -122332000, 3: 12500, 5: 8},  / Portland, 8 sats /
  8: {1: 1523, 2: 892, 6: 15}  / 1523 TX, 892 RX, 1.5% duty /
}
```
