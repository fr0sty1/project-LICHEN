# Framing (Historical)

> **Status: FROZEN / PROTOTYPE-ONLY**
>
> This 0xC1 CBOR frame envelope is deprecated. Current LCI uses SLIP-framed
> IPv6 packets. See [../11-lci.md](../11-lci.md) for the authoritative spec.

This document describes the **deprecated** framing used by early prototypes.

## Wire Format

```
+--------+--------+--------+----------------+
| START  | LEN_HI | LEN_LO | CBOR payload   |
| 0xC1   |   (big-endian)  | (LEN bytes)    |
+--------+--------+--------+----------------+
```

| Field | Size | Description |
|-------|------|-------------|
| START | 1 | Magic byte `0xC1` (distinguishes from KISS `0xC0`) |
| LEN | 2 | Payload length, big-endian, max 65535 |
| payload | LEN | CBOR-encoded message |

No trailing CRC — transport layer (BLE, TCP, HDLC) handles integrity.

## CDDL

```cddl
; Frame wrapper (not CBOR itself, but documents the envelope)
frame = (
  start: 0xC1,
  length: uint16,
  payload: bstr,  ; contains CBOR message
)

uint16 = uint .size 2
```

## Transport Notes

### TCP / Serial (stream)

Read START byte, then 2-byte length, then payload. Repeat.

### BLE (GATT)

- **Write characteristic**: Host sends frames, may span multiple writes
- **Notify characteristic**: Device sends frames, may span multiple notifications
- Fragment at MTU boundary, reassemble using length prefix
- Reassembly buffer per connection

### USB CDC

Same as serial — byte stream, no packet boundaries.

## Sync Recovery

If framing is lost (bad length, partial frame):

1. Discard bytes until next `0xC1`
2. Validate length is reasonable (≤ MTU or buffer size)
3. If payload CBOR decode fails, discard and resync

For BLE: disconnect and reconnect if sync cannot be recovered.
