# Mesh State

Device pushes mesh topology state to host for visualization and routing decisions.

## Message Flow

```
Host                          Device
  |                              |
  |<----- mesh_state (0x30) -----|  (on connect, full state)
  |                              |
  |<----- mesh_state (0x30) -----|  (periodic or on change)
```

Device sends mesh_state:
- Immediately after hello handshake (full state)
- When topology changes (neighbor added/removed, route changed)
- Periodically (configurable, e.g., every 30s)

## CDDL

```cddl
mesh_state = {
  0: 0x30,                    ; message type
  1: [* gradient_entry],      ; gradient/routing table
  2: [* neighbor_entry],      ; direct neighbors
  ? 3: seq,                   ; state sequence number
  ? 4: bool,                  ; true = full state, false = delta
  ? 5: uptime_ms,             ; device uptime when captured
}

gradient_entry = {
  1: iid,                     ; destination IID
  2: iid,                     ; next-hop IID
  3: uint,                    ; hop count to destination
  4: seq,                     ; route sequence number
  5: uint,                    ; expires in (ms from now)
  ? 6: rssi,                  ; last-heard RSSI (of next hop)
  ? 7: uint,                  ; route flags
}

neighbor_entry = {
  1: iid,                     ; neighbor IID
  2: rssi,                    ; last RSSI
  ? 3: snr,                   ; last SNR
  ? 4: uptime_ms,             ; last heard (ms ago)
  ? 5: uint,                  ; packets received from this neighbor
  ? 6: uint,                  ; packets sent to this neighbor
  ? 7: uint,                  ; link quality estimate (0-100)
}

; Route flags (bitmask)
; 0x01 = default route
; 0x02 = border router path
; 0x04 = bidirectional confirmed
```

## Fields

### gradient_entry

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 1 | dest | iid | Destination node IID |
| 2 | next_hop | iid | Next hop toward destination |
| 3 | hops | uint | Total hop count to destination |
| 4 | seq | uint | Route sequence (higher = fresher) |
| 5 | expires | uint | Time until route expires (ms) |
| 6 | rssi | int | RSSI of next-hop link |
| 7 | flags | uint | Route flags bitmap |

### neighbor_entry

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 1 | iid | iid | Neighbor's IID |
| 2 | rssi | int | Most recent RSSI (dBm) |
| 3 | snr | int | Most recent SNR (dB) |
| 4 | last_heard | uint | Milliseconds since last packet |
| 5 | rx_count | uint | Packets received |
| 6 | tx_count | uint | Packets transmitted |
| 7 | lqi | uint | Link quality index (0-100) |

## Delta Updates

When key 4 (delta) is true:
- `gradient_entry` with `expires: 0` means route removed
- `neighbor_entry` with `rssi: 0` means neighbor removed
- Only changed entries included

## Example

Full state on connect:
```cbor-diag
{
  0: 48,                      / mesh_state /
  1: [
    {1: h'1111111111111111', 2: h'2222222222222222', 3: 2, 4: 100, 5: 25000},
    {1: h'3333333333333333', 2: h'2222222222222222', 3: 3, 4: 98, 5: 18000}
  ],
  2: [
    {1: h'2222222222222222', 2: -72, 3: 10, 4: 1500, 7: 95}
  ],
  3: 1,                       / seq /
  4: false,                   / full state /
  5: 3600000                  / 1 hour uptime /
}
```
