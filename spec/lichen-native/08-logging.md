# Debug Logging

Stream device logs to host for debugging.

## Message Flow

```
Host                          Device
  |                              |
  |--- log_subscribe (0x41) ---->|  (enable streaming)
  |                              |
  |<---- log_entry (0x40) -------|
  |<---- log_entry (0x40) -------|
  |<---- log_entry (0x40) -------|
  |                              |
  |--- log_subscribe (0x41) ---->|  (disable)
```

## CDDL

```cddl
log_subscribe = {
  0: 0x41,                    ; message type
  1: bool,                    ; enable (true) or disable (false)
  ? 2: log_level,             ; minimum level to stream
  ? 3: [* tstr],              ; module filter (empty = all)
}

log_entry = {
  0: 0x40,                    ; message type
  1: log_level,               ; severity
  2: tstr,                    ; message text
  ? 3: tstr,                  ; module/tag
  ? 4: uptime_ms,             ; timestamp (uptime)
  ? 5: tstr,                  ; file:line (debug builds)
}

log_level = &(
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
  trace: 5,
)
```

## Fields

### log_subscribe

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x41 | Message type |
| 1 | enable | bool | Enable or disable streaming |
| 2 | level | uint | Minimum severity (1=error, 5=trace) |
| 3 | modules | [tstr] | Only these modules (empty = all) |

### log_entry

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 0 | type | 0x40 | Message type |
| 1 | level | uint | Log severity |
| 2 | msg | tstr | Log message |
| 3 | module | tstr | Source module/tag |
| 4 | time | uint | Uptime when logged |
| 5 | loc | tstr | Source location (debug) |

## Notes

- Log streaming is disabled by default (bandwidth concern)
- Device MAY rate-limit log output
- Device MAY buffer logs and batch-send
- Host can filter client-side for display

## Example

Enable debug logging for radio module:
```cbor-diag
{0: 65, 1: true, 2: 4, 3: ["radio", "lora"]}
```

Log entry:
```cbor-diag
{
  0: 64,                      / log_entry /
  1: 3,                       / info /
  2: "TX complete, 23 bytes", / message /
  3: "radio",                 / module /
  4: 3661500                  / uptime /
}
```
