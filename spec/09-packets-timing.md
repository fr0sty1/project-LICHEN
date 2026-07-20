<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Packets and Timing

## 13. Packet Formats

### 13.1. Complete Packet Example

**Scenario:** Leaf node sends CoAP temperature reading to border router.

The byte count below is the non-OSCORE case. Enabling OSCORE adds approximately
10 bytes for this example and changes the compressed payload length.

**Application payload (CoAP):**
```
Ver=1, T=NON, TKL=1, Code=2.05 (Content)
Token: 0x42
Options: Content-Format=60 (CBOR)
Payload: {temperature: 23.5} -> A1 6B 74656D7065726174757265 F9 4BC0
         (16 bytes)
```

**After OSCORE:** (if enabled)
```
OSCORE option + encrypted payload + tag
(adds ~10 bytes)
```

**After SCHC compression (Rule 1):**
```
Rule ID: 0x01 (1 byte)
Residue: HopLimit + SrcAddr[119:0] + DstAddr[119:0] + ports (32 bytes)
CoAP header, token, option, and payload marker: 8 bytes
Payload: (16 bytes)
Total: 57 bytes
```

**With authenticated L2 payload dispatch:**
```
SCHC dispatch: 0x14 (1 byte)
SCHC packet: (57 bytes)
Total: 58 bytes
```

**Link-layer frame:**
```
Length: 114 (0x72, body bytes after Length)
LLSec: 0xA1 (sender ID, signature, no encryption, short addr) (1 byte)
Epoch: 0x01 (1 byte)
SeqNum: 0x0042 (2 bytes)
DstAddr: 0x0001 (border router short) (2 bytes)
SenderID: immediate sender short address (2 bytes)
Payload: dispatch 0x14 + SCHC packet (58 bytes)
Signature: (48 bytes, Schnorr e₁₂₈+s)
Total: 115 bytes (Length byte plus 114-byte body)
```

**LoRa PHY:**
```
Preamble: 8 symbols
Header: explicit mode
Payload: 115 bytes
CRC: 2 bytes
```

The complete link frame is the PHY payload. Airtime MUST be calculated from the
actual payload length and configured SF, bandwidth, coding rate, preamble,
header mode, CRC, and low-data-rate optimization. Implementations MUST NOT use
the former 76-byte approximation for this example.

### 13.2. Packet Size Summary

| Component | Bytes in example |
|-----------|------------------|
| Application payload | 16 |
| IPv6/UDP SCHC residue and CoAP overhead | 41 |
| L2 dispatch | 1 |
| Destination address | 2 |
| Link security and framing | 55 |
| **Total without OSCORE** | **115** |
| **Approximate total with OSCORE** | **125** |

Link security breakdown: Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) + SenderID(2) + Signature(48) = 55 bytes
(DstAddr counted separately in addressing mode). Unsigned frames carry no MIC bytes.

### 13.3. RPL DIO Packet

```
Link-layer:
  [Len] [LLSec] [Epoch] [SeqNum] [SenderID] [Payload] [Sig]
  (broadcast AddrMode; no link-layer destination bytes)

IPv6 (compressed):
  [RPL multicast SCHC rule] [source IID] [ICMPv6 code]

ICMPv6:
  Type=155, Code=1 (DIO)

DIO payload:
  [RPLInstanceID] [Version] [Rank] [Flags] [DODAGID]

Options:
  [DODAG Configuration] [SCHC Rule Version] [Root Authorization]
```

---

## 14. Timing and Duty Cycle

### 14.1. Trickle Timer (DIO)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Imin | 4 seconds | Allow network stabilization |
| Imax | 17 minutes | Reduce steady-state overhead |
| k | 10 | Suppress redundant DIOs |

### 14.2. DAO Timing

| Event | Delay |
|-------|-------|
| Initial DAO | Random 0-2 seconds after joining |
| DAO retry | 4, 8, 16 seconds (exponential backoff) |
| DAO refresh | 30 minutes (soft state lifetime / 2) |

### 14.3. Data Traffic

| Traffic Type | Recommended Interval |
|--------------|---------------------|
| Periodic telemetry | 5-60 minutes |
| Event-driven | As needed |
| Heartbeat/keepalive | 30 minutes |

### 14.4. Duty Cycle Compliance

Regulatory limits are properties of the configured regional plan and equipment
authorization, not a single percentage per continent. Implementations MUST
account complete RF airtime, including routing, synchronization, rendezvous,
retries, and acknowledgments, against every applicable per-channel, sub-band,
and aggregate budget. A slot or channel assignment never overrides duty-cycle,
dwell-time, occupancy, power, or listen-before-talk requirements.

### 14.5. CSMA/CA Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CAD timeout | 3 symbols | Channel activity detection |
| Backoff unit | 10 ms | Slot time |
| Backoff max | 5 | CW = 2^backoff - 1 |
| Retry limit | 3 | Before reporting failure |

### 14.6. Time Synchronization

Accurate time is needed for message TTL, SenML timestamps, and scheduled
operations. Replay protection uses counters and does not require synchronized
time. LICHEN firmware uses a unified time provider that
separates monotonic uptime from wall-clock time and validates all time sources
against epoch floors. See `docs/firmware-time-provider.md` for the full design.

Scheduled MAC operation additionally requires a high-resolution monotonic slot
clock with bounded drift and timestamp uncertainty. Unix wall clock and the DIO
Time Option MUST NOT be used as the slot clock. See the
[Coordinated Capacity Profile](02a-coordinated-capacity.md) for synchronization,
guard, holdover, and fallback rules.

**Time Provider Architecture:**

The firmware-wide time provider tracks:

- **Monotonic uptime:** Always available, used for age calculations and replay
  protection within a power cycle. Never synthesized into Unix time.
- **Wall-clock time:** Unix seconds, only valid after a trusted source provides
  a timestamp at or above the effective epoch floor.

**Source Classes (by trust/precedence):**

| Class | Examples | Can Establish Wall Clock? |
|-------|----------|---------------------------|
| GNSS | On-device GNSS, external GNSS | Yes, if timestamp >= epoch floor |
| Network | NTS (RFC 8915), Roughtime, SNTP, mesh peer DIO | Yes, if authenticated or policy-accepted and >= floor |
| Local-client | Phone/app via LCI, gpsd | Yes, if policy permits and >= floor |
| Manual/static | Provisioning tool, configuration | Yes, if policy permits and >= floor |
| Internal RTC | Retained RTC, external RTC chip | Yes, if >= floor (accuracy degrades with age) |
| Monotonic | Uptime, cycle counter | No (ordering and age only) |

**Epoch Floor Validation:**

The effective epoch floor prevents stale or bogus timestamps from establishing
wall-clock time:

```
effective_epoch_floor = max(firmware_build_epoch, board_provision_epoch_if_valid)
```

Time samples below this floor are rejected for wall-clock establishment.
This guards against common failures: GNSS modules reporting their default
epoch (1980 or 1999), apps sending zero timestamps, or RTCs booting with
uninitialized values.

**Time Stratum (propagated in DIO Time Option):**

| Value | Meaning | Source Class |
|-------|---------|--------------|
| 0 | No sync | Monotonic counters only |
| 1 | Mesh-derived | Network (peer DIO) |
| 2 | Roughtime | Network (BR) |
| 3 | NTS | Network (BR) |
| 4 | GNSS/gpsd | GNSS or Local-client |

**DIO Time Option (Type TBD):**

```
+--------+--------+--------+--------+--------+--------+
| Type   | Length | Stratum| Reserved| Timestamp (4B)  |
+--------+--------+--------+--------+--------+--------+
   1B       1B       1B       1B          4B (Unix epoch)
```

Nodes receiving DIO with higher stratum than their own MAY adopt that time,
subject to epoch floor validation. Nodes MUST NOT adopt time from lower
stratum sources. Nodes MUST NOT accept DIO timestamps below their effective
epoch floor.

**Constrained Node Behavior:**

Nodes without a valid wall-clock source:
- Use sequence numbers for replay protection independently of wall clock
- MUST persist the replay epoch while retaining the long-term key and increment
  it on boot
- MAY omit absolute timestamps from SenML (use relative `t` offsets only)
- MUST NOT originate time-sensitive operations (scheduled check-in, message
  TTL that requires wall-clock comparison)
- Report `wall_clock_valid=false` via LCI status until a valid source appears

**Border Router Responsibilities:**

Border routers with internet connectivity SHOULD:
- Run NTS client (preferred) or Roughtime client
- Validate obtained time against the epoch floor before advertising
- Advertise time in DIO with appropriate stratum
- Provide NTS/Roughtime proxy for LCI clients
- Expose time provider state (source class, validity, age) via CoAP status

---

[← Previous: Node Types](08-nodes.md) | [Index](README.md) | [Next: Implementation →](10-implementation.md)
