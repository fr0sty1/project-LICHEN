<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Packets and Timing

## 13. Packet Formats

### 13.1. Complete Packet Example

**Scenario:** Leaf node sends CoAP temperature reading to border router.

**Application payload (CoAP):**
```
Ver=1, T=NON, TKL=1, Code=2.05 (Content)
Token: 0x42
Options: Content-Format=60 (CBOR)
Payload: {temperature: 23.5} -> A1 6B 74656D7065726174757265 F9 4BC0
         (17 bytes)
```

**After OSCORE:** (if enabled)
```
OSCORE option + encrypted payload + tag
(adds ~10 bytes)
```

**After SCHC compression (Rule 0):**
```
Rule ID: 0x00 (1 byte)
Residue: SrcPort[3:0], DstPort[3:0] (1 byte)
Compressed CoAP header: 0x42 0x45 (2 bytes)
Payload: (17 bytes)
Total: 21 bytes
```

**With authenticated L2 payload dispatch:**
```
SCHC dispatch: 0x14 (1 byte)
SCHC packet: (21 bytes)
Total: 22 bytes
```

**Link-layer frame:**
```
Length: 76 (0x4C, body bytes after Length)
LLSec: 0x21 (signature, no encryption, short addr) (1 byte)
Epoch: 0x01 (1 byte)
SeqNum: 0x0042 (2 bytes)
DstAddr: 0x0001 (border router short) (2 bytes)
Payload: dispatch 0x14 + SCHC packet (22 bytes)
Signature: (48 bytes, Schnorr e₁₂₈+s)
Total: 77 bytes (Length byte plus 76-byte body)
```

**LoRa PHY:**
```
Preamble: 8 symbols
Header: 3 bytes (implicit mode)
Payload: 60 bytes
CRC: 2 bytes
```

### 13.2. Packet Size Summary

| Layer | This Protocol | Meshtastic | MeshCore |
|-------|---------------|------------|----------|
| App payload | 17 | 17 | 17 |
| Security (E2E) | 10 | 0* | 2 |
| Transport + Network | 2 | 16 | - |
| Routing overhead | 0-6 | 0-7 | 0-64 |
| Link security | 53 | 0 | 4 |
| **Total** | **82-88** | **33-40** | **23-87** |

*Meshtastic AES-CTR has no auth overhead; this is a weakness.

Link security breakdown: Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) + Signature(48) = 53 bytes
(DstAddr counted separately in addressing mode). Unsigned frames carry no MIC bytes.

### 13.3. RPL DIO Packet

```
Link-layer:
  [Len] [LLSec] [Epoch] [SeqNum] [DstAddr=ff02::1a] [Payload] [Sig]

IPv6 (compressed):
  [SCHC Rule 2] [HopLimit] [Multicast flag]

ICMPv6:
  Type=155, Code=1 (DIO)

DIO payload:
  [RPLInstanceID] [Version] [Rank] [Flags] [DODAGID]

Options:
  [DODAG Configuration] [Prefix Information]
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
| DAO refresh | 15 minutes (30-minute soft state lifetime / 2) |

Each new logical DAO, including a refresh or parent change, MUST advance its
64-bit DAO Origin Sequence, construct the complete signed DAO, and crash-safely
commit both the sequence and complete signed bytes before transmission. State
is keyed by the public key, not the full IPv6 address. Storage MUST provide
atomic commit or two independently validated slots with generation numbers.
The TX API MUST expose the retained complete bytes after reboot so a retry can
reuse the sequence only by retransmitting those bytes exactly; rebuilding or
re-signing an equal-sequence DAO is forbidden. The sequence starts above zero
and MUST NOT wrap; at `0xffffffffffffffff`, no new logical DAO may be sent.
Missing, corrupt, unavailable, or uncommitted state MUST stop DAO origination
until valid state above every value previously used with that key is restored.
A node MUST NOT fall back to a clock, random value, or link replay counter.

### 14.3. Data Traffic

| Traffic Type | Recommended Interval |
|--------------|---------------------|
| Periodic telemetry | 5-60 minutes |
| Event-driven | As needed |
| Heartbeat/keepalive | 30 minutes |

### 14.4. Duty Cycle Compliance

**EU 868 MHz (10% duty cycle):**

At SF9/125kHz, airtime per 60-byte packet ~ 200ms.

Max packets per hour: `3600s * 0.1 / 0.2s = 1800 packets`

Per node, accounting for routing: ~100-300 packets/hour comfortable.

### 14.5. CSMA/CA Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| CAD timeout | 3 symbols | Channel activity detection |
| Backoff unit | 10 ms | Slot time |
| Backoff max | 5 | CW = 2^backoff - 1 |
| Retry limit | 3 | Before reporting failure |

### 14.6. Time Synchronization

Accurate time is needed for replay protection, message TTL, SenML timestamps,
and scheduled operations. LICHEN firmware uses a unified time provider that
separates monotonic uptime from wall-clock time and validates all time sources
against epoch floors. See `docs/firmware-time-provider.md` for the full design.

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
- Use link sequence numbers for replay protection within a power cycle; the
  DAO Origin Sequence in Section 14.2 remains persistent across power cycles
- SHOULD persist replay epoch counter across reboots (increment on boot)
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
