# LICHEN Logging Style Guide

## Log Levels

| Level | Use For | Examples |
|-------|---------|----------|
| `LOG_ERR` | Unrecoverable failures, resource exhaustion, invariant violations | Init failed, malloc failed, impossible state |
| `LOG_WRN` | Recoverable issues, dropped packets, degraded operation | Auth failed (drop packet), timeout (retry), config fallback |
| `LOG_INF` | State transitions, startup/shutdown, configuration summary | Module started, peer added, interface enabled |
| `LOG_DBG` | Per-packet tracing, internal state, debugging details | RX 45 bytes, TX queued, mutex acquired |

**Rules:**
- Never put severity words in the message (`CRITICAL:`, `ERROR:`, `WARNING:`)
- Never use `k_panic()` -- see "No Panic Policy" below
- `LOG_DBG` is compiled out in release builds -- use freely for tracing

## Message Format

```
<subsystem>: <subject> <verb> [details]
```

**Components:**
- `<subsystem>`: Module name, lowercase, matches LOG_MODULE name
- `<subject>`: What failed/succeeded (noun or noun phrase)
- `<verb>`: Past tense action (started, failed, dropped, added)
- `[details]`: Context in parentheses or after dash

**Examples:**
```c
LOG_INF("lora_l2: RX thread started");
LOG_ERR("lora_l2: device init failed (%d)", ret);
LOG_WRN("lichen_l2: frame dropped (too short: %zu < %d)", len, MIN_LEN);
LOG_DBG("lichen_l2: TX %zu bytes", len);
```

## Error Codes

Use `(%d)` suffix for raw errno, `(%s)` for strerror when available:

```c
// Preferred: symbolic when meaningful
LOG_ERR("lora_l2: config failed (%d)", ret);

// With context
LOG_ERR("lichen_l2: peer_add failed (%s)", lichen_link_strerror(ret));

// Multiple values: use labeled format
LOG_ERR("lora_l2: RX overflow (got=%d, max=%d)", ret, MAX_FRAME);
```

**Don't:**
```c
LOG_ERR("Error: failed with error code %d", ret);  // Redundant "error"
LOG_ERR("ret=%d", ret);                            // No context
LOG_ERR("failed: %d", ret);                        // No subsystem
```

## Addresses and Identifiers

**EUI-64 / MAC addresses:**
```c
LOG_INF("lichen_l2: peer added %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
        eui[0], eui[1], eui[2], eui[3], eui[4], eui[5], eui[6], eui[7]);
```

**IPv6 addresses:** Use `lichen_ipv6_addr_to_str()` helper:
```c
char addr_str[LICHEN_IPV6_ADDR_STR_LEN];
lichen_ipv6_addr_to_str(addr, addr_str, sizeof(addr_str));
LOG_INF("lichen_l2: link-local %s", addr_str);
```

**Abbreviated form** (first/last 2 bytes) for high-frequency logs:
```c
LOG_DBG("lichen_l2: RX from ..%02x:%02x", eui[6], eui[7]);
```

## Units

Always include units. Use consistent abbreviations:

| Quantity | Unit | Format |
|----------|------|--------|
| Size | bytes | `%zu bytes` |
| Time | ms, us | `%d ms`, `%lld us` |
| Frequency | MHz, kHz | `%u MHz` (space before unit) |
| Power | dBm | `%d dBm` |
| SNR | dB | `%d dB` |
| Temperature | C | `%d C` |

**Examples:**
```c
LOG_INF("lora_l2: started (915 MHz, 14 dBm, SF10)");
LOG_DBG("lora_l2: RX %d bytes (RSSI %d dBm, SNR %d dB)", len, rssi, snr);
```

## State Transitions

Log state changes at `LOG_INF` with old→new:
```c
LOG_INF("lora_l2: state STOPPED -> RUNNING");
```

Or use a helper that logs automatically:
```c
LOG_DBG("lora_l2: state %s -> %s", state_names[old], state_names[new]);
```

## Security-Sensitive Data

**Never log:**
- Private keys, shared secrets, session keys
- Full packet contents (use hex dump at LOG_DBG only, truncated)
- Passwords, tokens, credentials

**Redact in production:**
- Peer public keys (log first/last 4 bytes only)
- Full EUI-64 of non-local nodes (abbreviate)

```c
// OK: local node identity at startup
LOG_INF("lichen_l2: local EUI-64 %02x:...:%02x", eui[0], eui[7]);

// OK: abbreviated peer in debug
LOG_DBG("lichen_l2: auth from ..%02x:%02x", peer_eui[6], peer_eui[7]);

// BAD: full peer EUI-64 at LOG_INF (enables tracking)
LOG_INF("lichen_l2: peer %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x joined", ...);
```

## Function Entry/Exit

Generally don't log function entry/exit. Exception: long-running operations:
```c
LOG_INF("lora_l2: deinit starting");
// ... lengthy cleanup ...
LOG_INF("lora_l2: deinit complete");
```

## No Panic Policy

**Never use `k_panic()` or `__ASSERT()` in production firmware.**

Panic/assert stops the CPU, making the device unresponsive until power cycle.
This is unacceptable for:
- Remote deployments (no physical access)
- Battery-powered devices (drain until watchdog or battery death)
- Safety-critical systems (must degrade gracefully)

### Error Handling Strategy

| Condition | Action |
|-----------|--------|
| Invalid external input | `LOG_WRN` + drop/ignore + continue |
| Resource exhausted | `LOG_ERR` + return error code |
| Init failure | `LOG_ERR` + return error + caller decides |
| Impossible state (bug) | `LOG_ERR` + set `needs_reinit` flag + return error |
| Corrupted state | `LOG_ERR` + store crash reason + let watchdog reset |

### Pattern: Impossible States

Instead of panic, force reinitialization:
```c
if (state >= LORA_STATE_COUNT) {
    LOG_ERR("lora_l2: invalid state (%d), forcing reinit", state);
    atomic_set(&lora_needs_reinit, 1);
    return -EINVAL;
}
```

### Pattern: Corrupted Memory / Stack Overflow

For truly unrecoverable corruption, store diagnostic info and let watchdog reset:
```c
// In retained RAM (survives reset)
__retained static struct {
    uint32_t reason;
    uint32_t location;
    uint32_t extra;
} crash_info;

static void fatal_error(uint32_t reason, uint32_t location, uint32_t extra)
{
    crash_info.reason = reason;
    crash_info.location = location;
    crash_info.extra = extra;
    
    LOG_ERR("main: fatal error (reason=%u, loc=%u)", reason, location);
    
    // Don't spin -- let watchdog reset us
    // On reboot, check crash_info and log it
}
```

### Pattern: Defensive Checks

Replace assertions with runtime checks that return errors:
```c
// BAD: stops the device
__ASSERT(ctx != NULL, "ctx cannot be NULL");

// GOOD: logs and returns
if (ctx == NULL) {
    LOG_ERR("lora_l2: ctx is NULL (caller bug)");
    return -EINVAL;
}
```

### Debug Builds

For development, `__ASSERT()` can be enabled via `CONFIG_ASSERT=y` to catch
bugs early. But release builds MUST have `CONFIG_ASSERT=n` (the default).

```kconfig
# prj.conf for debug builds only
CONFIG_ASSERT=y
CONFIG_ASSERT_LEVEL=2
```

### Watchdog Integration

Always enable watchdog in production:
```c
// main.c init
const struct device *wdt = DEVICE_DT_GET(DT_ALIAS(watchdog0));
wdt_setup(wdt, ...);

// main loop
while (1) {
    wdt_feed(wdt, channel_id);
    // ... normal operation ...
}
```

If the system hangs due to a bug we didn't anticipate, watchdog resets it.
Crash info in retained RAM survives the reset for post-mortem analysis.

## Module Registration

Each file registers its own module with appropriate default level:
```c
LOG_MODULE_REGISTER(lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);
```

Kconfig provides per-module control:
```kconfig
config LICHEN_LORA_L2_LOG_LEVEL
    int "LoRa L2 log level"
    default 3  # LOG_LEVEL_INF
    depends on LOG
```
