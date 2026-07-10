# KISS Framing for LICHEN

LICHEN implements the KISS TNC protocol for compatibility with legacy amateur radio
applications (APRSDroid, aprs.fi, Direwolf, Xastir, Linux AX.25 stack).

## 1. KISS Protocol Overview

KISS (Keep It Simple, Stupid) is a TNC interface standard created by Mike Chepponis
(K3MC) and Phil Karn (KA9Q) in 1986. It provides a simple byte-stuffing protocol
for framing packets over serial links.

Reference: http://www.ka9q.net/papers/kiss.html

### 1.1 Frame Format

```
FEND | CMD | DATA... | FEND
0xC0 | 1B  | 0-N     | 0xC0
```

- **FEND (0xC0)**: Frame delimiter, marks start and end of frame
- **CMD**: Command byte (high nibble = port, low nibble = command type)
- **DATA**: Payload with escape sequences applied

Multiple consecutive FENDs between frames are valid (inter-frame fill).

### 1.2 Special Bytes

| Byte | Name  | Purpose                    |
|------|-------|----------------------------|
| 0xC0 | FEND  | Frame delimiter            |
| 0xDB | FESC  | Escape prefix              |
| 0xDC | TFEND | Escaped FEND (after FESC)  |
| 0xDD | TFESC | Escaped FESC (after FESC)  |

### 1.3 Escape Sequences

Data bytes 0xC0 and 0xDB cannot appear literally in the payload:

| Original | Escaped      |
|----------|--------------|
| 0xC0     | 0xDB 0xDC    |
| 0xDB     | 0xDB 0xDD    |

### 1.4 Command Byte Structure

```
7  6  5  4  3  2  1  0
├──────────┼──────────┤
│  Port    │ Command  │
│  (0-15)  │  (0-15)  │
└──────────┴──────────┘
```

Example: Port 1, Data command = `0x10`

### 1.5 Standard Commands

| Cmd | Name        | Direction    | Payload    | Purpose                           |
|-----|-------------|--------------|------------|-----------------------------------|
| 0   | Data        | Bidirectional| AX.25 frame| Raw packet data                   |
| 1   | TxDelay     | Host->TNC    | 1 byte     | TX key-up delay (10ms units)      |
| 2   | Persistence | Host->TNC    | 1 byte     | CSMA p-value (0-255 -> 0.0-1.0)   |
| 3   | SlotTime    | Host->TNC    | 1 byte     | CSMA slot interval (10ms units)   |
| 4   | TxTail      | Host->TNC    | 1 byte     | TX tail time (obsolete but used)  |
| 5   | FullDuplex  | Host->TNC    | 1 byte     | 0=half, 1=full duplex             |
| 6   | SetHardware | Host->TNC    | varies     | TNC-specific commands             |
| 15  | Return      | Host->TNC    | none       | Exit KISS mode                    |

Note: Commands 7-14 are undefined in the standard.

## 2. Real-World Usage Patterns

Survey of how existing tools actually use KISS.

### 2.1 Traffic Distribution

| Command     | Usage    | Notes                              |
|-------------|----------|------------------------------------|
| Data (0)    | 99%+     | Nearly all traffic                 |
| TxDelay (1) | rare     | Set once at startup via kissparms  |
| P (2)       | rare     | Set once at startup                |
| SlotTime (3)| rare     | Set once at startup                |
| TxTail (4)  | rare     | Still used despite being "obsolete"|
| FullDuplex  | rare     | Typically left at default (half)   |
| SetHardware | vendor   | Mobilinkd queries, Direwolf TNC:   |
| Return      | rare     | Most TNCs ignore or stay in KISS   |

### 2.2 Typical Payload Sizes

| Application   | Typical Size    | Max Size    |
|---------------|-----------------|-------------|
| APRS          | 100-200 bytes   | ~214 bytes  |
| General AX.25 | 128-256 bytes   | 256 bytes   |
| KISS buffer   | -               | 1024+ bytes |

## 3. LICHEN KISS Port Assignments

LICHEN uses KISS port numbers to multiplex different payload types:

| Port | Content              | Use Case                              |
|------|----------------------|---------------------------------------|
| 0    | AX.25/APRS frames    | Legacy TNC apps (APRSDroid, Xastir)   |
| 1    | Raw LICHEN frames    | Debugging, native apps, packet inject |
| 2-15 | Reserved             | Future use                            |

### 3.1 Rationale

**Option A: Raw IPv6 packets** - Rejected. IPv6 packets are 40+ bytes of header
before payload. Most TNC apps expect AX.25 and would display garbage.

**Option B: Raw LICHEN link frames** - Partial. Useful for debugging and packet
injection but not for TNC app compatibility.

**Option C: Both via port numbers** - Selected. Port 0 carries AX.25-wrapped
LICHEN payloads for TNC app compatibility. Port 1 exposes raw LICHEN frames for
debugging, packet injection, and native applications.

### 3.2 Port 0: AX.25/APRS Mode

```
KISS Frame (Port 0)
├─ FEND
├─ CMD (0x00)
├─ AX.25 UI Frame (escaped)
│  ├─ Dest Callsign (7 bytes)
│  ├─ Src Callsign (7 bytes)
│  ├─ Control (0x03 = UI)
│  ├─ PID (0xF0 = no L3)
│  └─ Info Field (APRS data / LICHEN payload formatted)
└─ FEND
```

Callsigns are synthesized from LICHEN IIDs using `L` prefix + base36 encoding.
See `docs/kiss-aprs-bridge.md` for callsign mapping details.

### 3.3 Port 1: Raw LICHEN Mode

```
KISS Frame (Port 1)
├─ FEND
├─ CMD (0x10)
├─ LICHEN Link Frame (escaped)
│  ├─ Length
│  ├─ LLSec
│  ├─ Epoch
│  ├─ SeqNum
│  ├─ [Dest Addr]
│  ├─ Payload
│  ├─ MIC
│  └─ [Signature]
└─ FEND
```

Raw LICHEN frames include all link-layer fields (epoch, seqnum, MIC, etc.).
Useful for:
- Packet sniffing and protocol debugging
- Test packet injection
- Native applications that understand LICHEN framing

## 4. LICHEN Command Support

Which KISS commands LICHEN firmware should implement.

### 4.1 Required

| Cmd | Name | Implementation |
|-----|------|----------------|
| 0   | Data | Full bidirectional support |

### 4.2 Optional (Accept and Store)

| Cmd | Name        | Implementation                         |
|-----|-------------|----------------------------------------|
| 1   | TxDelay     | Store value, apply to LoRa TX timing   |
| 2   | Persistence | Store value, use for channel access    |
| 3   | SlotTime    | Store value, use for CSMA backoff      |

These parameters map to LICHEN's channel access mechanism:
- TxDelay: Post-preamble settling time (LoRa uses CAD, not carrier detect)
- Persistence: Probability of transmitting when channel is clear
- SlotTime: Backoff slot duration

### 4.3 Accept but Ignore

| Cmd | Name       | Rationale                               |
|-----|------------|-----------------------------------------|
| 4   | TxTail     | LoRa handles TX tail automatically      |
| 5   | FullDuplex | LoRa is always half-duplex              |
| 15  | Return     | LICHEN stays in KISS mode permanently   |

Accept these silently to avoid confusing host software, but take no action.

### 4.4 Vendor-Specific (SetHardware)

| Cmd | Name        | Implementation                         |
|-----|-------------|----------------------------------------|
| 6   | SetHardware | Optional vendor extensions             |

If implemented, consider Mobilinkd-style sub-commands for:
- Battery/power status query
- RF parameters (SF, BW, CR)
- Firmware version query
- Link statistics

Response format: echo command byte with MSB set (`cmd | 0x80`).

## 5. Use Cases

### 5.1 Gateway to IP Network

```
Internet ←→ Border Router ←→ LICHEN Mesh
                  ↑
            KISS/Serial to
            LoRa transceiver
```

KISS provides the host-to-radio interface for border routers connecting LICHEN
meshes to IP networks. The border router speaks KISS to the radio and tunnels
packets over IPv6/UDP.

### 5.2 Debugging and Packet Sniffing

```
Developer Laptop ←KISS/USB→ LICHEN Node
                              ↓
                         LoRa Sniffer
```

Port 1 (raw LICHEN) enables:
- Wireshark-style packet capture (via `kissutil` or custom tool)
- Protocol debugging with full frame visibility
- Timing analysis (epoch/seqnum inspection)

### 5.3 Packet Injection for Testing

```
Test Script ←KISS/USB→ LICHEN Node → LoRa TX
```

Inject arbitrary LICHEN frames via Port 1 for:
- Fuzzing and security testing
- Replay attack simulation
- Protocol conformance testing

### 5.4 APRS Bridge

```
APRSDroid ←BLE/KISS→ LICHEN Node ←LoRa→ LICHEN Mesh
                                          ↓
                                     APRS-IS Gateway
                                          ↓
                                       aprs.fi
```

Port 0 (AX.25/APRS) enables APRS applications to send position reports, messages,
and telemetry over LICHEN networks. The bridge synthesizes proper APRS packet
types from structured LICHEN payloads (position, weather, telemetry).

### 5.5 BLE KISS for Mobile Apps

LICHEN exposes a BLE GATT service for KISS connectivity:

| Characteristic | UUID | Properties |
|----------------|------|------------|
| Service        | `00000001-ba2a-46c9-ae49-01b0961f68bb` | - |
| TX (to device) | `00000002-ba2a-46c9-ae49-01b0961f68bb` | Write |
| RX (from device)| `00000003-ba2a-46c9-ae49-01b0961f68bb` | Notify, Read |

This enables iOS/Android apps (APRSDroid, aprs.fi) to communicate with LICHEN
nodes via Bluetooth.

## 6. Implementation Status

**Rust** (`rust/lichen-kiss/`): Core framing and bridge complete. APRS/BLE stubs.

**Python** (`python/src/lichen/interface/kiss/`): Complete implementation with
AX.25, APRS synthesis, callsign mapping, serial transport. 313 tests.

See `docs/kiss-aprs-bridge.md` for module-level details.

## 7. References

- [KISS Specification (KA9Q)](http://www.ka9q.net/papers/kiss.html)
- [BLE-KISS-API (aprs.fi)](https://github.com/hessu/aprs-specs/blob/master/BLE-KISS-API.md)
- [AX.25 v2.2 Specification](http://www.ax25.net/AX25.2.2-Jul%2098-2.pdf)
- [APRS Protocol Reference v1.01](http://www.aprs.org/doc/APRS101.PDF)
- [Direwolf Documentation](https://github.com/nwdigitalradio/direwolf)
- [Linux AX.25 HOWTO](https://tldp.org/HOWTO/AX25-HOWTO/)
- [LICHEN KISS/APRS Bridge](../docs/kiss-aprs-bridge.md)
