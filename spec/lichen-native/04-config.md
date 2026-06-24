# Configuration Messages

Read and write device configuration.

## Message Flow

```
Host                          Device
  |                              |
  |------ config_get (0x10) ---->|
  |<---- config_result (0x12) ---|
  |                              |
  |------ config_set (0x11) ---->|
  |<---- config_result (0x12) ---|
```

## CDDL

```cddl
config_get = {
  0: 0x10,                    ; message type
  ? 1: [* config_key],        ; specific keys to get (omit = all)
}

config_set = {
  0: 0x11,                    ; message type
  1: config_map,              ; key-value pairs to set
  ? 2: bool,                  ; persist to flash (default true)
}

config_result = {
  0: 0x12,                    ; message type
  1: result_code,             ; success/failure
  ? 2: config_map,            ; current values (on success)
  ? 3: tstr,                  ; error message (on failure)
  ? 4: [* config_key],        ; keys that failed (partial success)
}

config_key = &(
  ; Radio
  tx_power: 1,                ; int, dBm
  frequency: 2,               ; uint, Hz
  spreading_factor: 3,        ; uint, 7-12
  bandwidth: 4,               ; uint, Hz (125000, 250000, 500000)
  coding_rate: 5,             ; uint, 5-8 (4/5 to 4/8)
  sync_word: 6,               ; uint, 0x12 or 0x34

  ; Timing
  announce_interval: 16,      ; uint, ms
  receive_timeout: 17,        ; uint, ms
  tx_jitter_max: 18,          ; uint, ms

  ; Identity
  device_name: 32,            ; tstr

  ; Network
  network_key: 48,            ; bstr .size 32 (write-only, read returns empty)
)

config_map = {
  * config_key => config_value,
}

config_value = int / uint / tstr / bstr / bool
```

## Config Keys

| Key | Name | Type | Default | Description |
|-----|------|------|---------|-------------|
| 1 | tx_power | int | 22 | Transmit power in dBm |
| 2 | frequency | uint | 915000000 | Center frequency in Hz |
| 3 | spreading_factor | uint | 10 | LoRa SF (7-12) |
| 4 | bandwidth | uint | 125000 | Bandwidth in Hz |
| 5 | coding_rate | uint | 5 | CR 4/x where x is this value |
| 6 | sync_word | uint | 0x12 | LoRa sync word |
| 16 | announce_interval | uint | 30000 | Announce beacon interval (ms) |
| 17 | receive_timeout | uint | 5000 | RX window timeout (ms) |
| 18 | tx_jitter_max | uint | 1000 | Max random TX delay (ms) |
| 32 | device_name | tstr | "" | User-assigned name |
| 48 | network_key | bstr | - | 32-byte network key (write-only) |

## Security

- `network_key` is write-only; reads return empty bytes
- Config changes MAY require confirmation (PIN entry via separate message)
- Sensitive configs MAY be locked after initial setup

## Example

Get all config:
```cbor-diag
{0: 16}  / config_get, no filter = get all /
```

Response:
```cbor-diag
{
  0: 18,                      / config_result /
  1: 0,                       / ok /
  2: {
    1: 22,                    / tx_power = 22 dBm /
    2: 915000000,             / frequency /
    3: 10,                    / SF10 /
    16: 30000,                / announce every 30s /
    32: "sensor-north"        / device name /
  }
}
```

Set TX power:
```cbor-diag
{0: 17, 1: {1: 14}}  / config_set tx_power=14 /
```
