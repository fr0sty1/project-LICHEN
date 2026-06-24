# Amateur Radio Standards

Protocols and standards from the amateur radio community.

## KISS Protocol

**Keep It Simple, Stupid** — TNC interface standard (1986)

| Document | Description |
|----------|-------------|
| [KISS Specification](http://www.ax25.net/kiss.aspx) | Original Phil Karn (KA9Q) spec |
| [BLE-KISS-API](https://github.com/hessu/aprs-specs/blob/master/BLE-KISS-API.md) | BLE KISS for iOS (aprs.fi) |

### Frame Format

```
FEND (0xC0) | CMD | DATA... | FEND (0xC0)
```

### Special Bytes

| Byte | Name | Purpose |
|------|------|---------|
| 0xC0 | FEND | Frame delimiter |
| 0xDB | FESC | Escape marker |
| 0xDC | TFEND | Escaped FEND |
| 0xDD | TFESC | Escaped FESC |

### Commands

| Cmd | Name | Direction | Purpose |
|-----|------|-----------|---------|
| 0 | Data Frame | Bidirectional | Raw packet data |
| 1 | TXDELAY | Host→TNC | TX key-up delay |
| 2 | Persistence | Host→TNC | CSMA parameter |
| 3 | SlotTime | Host→TNC | CSMA slot interval |
| 4 | TxTail | Host→TNC | TX tail time |
| 5 | FullDuplex | Host→TNC | Half/full duplex |
| 15 | Return | Host→TNC | Exit KISS mode |

### LICHEN Integration

LICHEN implements KISS for compatibility with:
- aprs.fi iOS app
- APRSDroid
- Xastir
- direwolf

## AX.25

**Amateur X.25** — Layer 2 packet radio protocol

| Document | Description |
|----------|-------------|
| [AX.25 2.2](http://www.ax25.net/AX25.2.2-Jul%2098-2.pdf) | Current specification |

### Frame Format

```
Flag | Dest | Src | Digis | Ctrl | PID | Info | FCS | Flag
7E   | 7B   | 7B  | 0-56B | 1-2B | 1B  | var  | 2B  | 7E
```

LICHEN does **not** implement full AX.25, but KISS carries AX.25 frames.

## APRS

**Automatic Packet Reporting System**

| Document | Description |
|----------|-------------|
| [APRS 1.01](http://www.aprs.org/doc/APRS101.PDF) | Protocol specification |
| [APRS 1.1](http://www.aprs.org/aprs11.html) | Extensions |

### Position Format

```
!DDMM.mmN/DDDMM.mmW$
```

LICHEN uses standard lat/lon (not APRS format) but can bridge.

## Packet Radio History

| Year | Development |
|------|-------------|
| 1978 | First amateur packet (Montreal) |
| 1982 | AX.25 standardized |
| 1986 | KISS protocol (KA9Q) |
| 1992 | APRS (WB4APR) |
| 2000s | APRS-IS internet gateway |
| 2020s | LoRa packet radio |

## LICHEN vs Traditional Packet

| Feature | Traditional | LICHEN |
|---------|-------------|--------|
| Modulation | AFSK 1200 baud | LoRa CSS |
| Addressing | Callsigns | IPv6 + Ed25519 |
| Routing | Manual digipeaters | Automatic mesh |
| Security | None | Per-packet signatures |
| Interop | KISS compatibility | KISS bridge mode |
