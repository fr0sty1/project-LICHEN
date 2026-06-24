# Other Standards

IEEE, OASIS, ISO, ITU, and other standards organizations.

## IEEE

| Standard | Title | LICHEN Use |
|----------|-------|------------|
| [IEEE 802.15.4](https://standards.ieee.org/standard/802_15_4-2020.html) | LR-WPAN | Referenced (NOT used) |
| [IEEE 754](https://standards.ieee.org/standard/754-2019.html) | Floating-Point | Numeric representation |
| [IEEE 802.11](https://standards.ieee.org/standard/802_11-2020.html) | WiFi | Border router uplink |

### Why Not IEEE 802.15.4?

LICHEN uses LoRa instead of 802.15.4 because:
- LoRa has 10-100x range
- Lower data rate acceptable for IoT
- Better penetration (sub-GHz)
- CSS more robust than O-QPSK

## OASIS

| Standard | Title | LICHEN Use |
|----------|-------|------------|
| [MQTT-SN](https://www.oasis-open.org/committees/mqtt/) | MQTT for Sensor Networks | Alternative to CoAP |
| [CAP](https://docs.oasis-open.org/emergency/cap/v1.2/CAP-v1.2.html) | Common Alerting Protocol | Emergency message format |

### MQTT-SN

Lightweight publish/subscribe over UDP:
- Port: 10883
- QoS: 0, 1, 2
- Topics: Short topic IDs
- Security: DTLS (optional)

## ISO/IEC

| Standard | Title | LICHEN Use |
|----------|-------|------------|
| [ISO 3309](https://www.iso.org/standard/8618.html) | HDLC | CRC-32 algorithm |
| [ISO 8601](https://www.iso.org/standard/70907.html) | Date/Time | Timestamp format |

## ITU

| Standard | Title | LICHEN Use |
|----------|-------|------------|
| [ITU-R SM.329](https://www.itu.int/rec/R-REC-SM.329/en) | Spurious Emissions | RF compliance |
| [ITU-R P.525](https://www.itu.int/rec/R-REC-P.525/en) | Free-Space Path Loss | Link budget |
| [ITU-R P.1238](https://www.itu.int/rec/R-REC-P.1238/en) | Indoor Propagation | Range estimation |

## Regulatory

| Region | Authority | Band | Notes |
|--------|-----------|------|-------|
| US | FCC Part 15 | 902-928 MHz | 1W EIRP, FHSS or DSS |
| EU | ETSI EN 300 220 | 863-870 MHz | 25mW, 1% duty |
| AU | ACMA | 915-928 MHz | 1W EIRP |
| JP | MIC | 920-928 MHz | 20mW |

## BLE Standards

| Document | Title | LICHEN Use |
|----------|-------|------------|
| [Bluetooth Core 5.x](https://www.bluetooth.com/specifications/specs/core-specification-5-4/) | Bluetooth Specification | Local client interface |
| [GATT](https://www.bluetooth.com/specifications/specs/core-specification-5-4/) | Generic Attribute Profile | BLE services |
| [NUS](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/libraries/bluetooth_services/services/nus.html) | Nordic UART Service | Serial over BLE |

### LICHEN BLE Services

| Service | UUID | Purpose |
|---------|------|---------|
| LICHEN Native | TBD | Full protocol access |
| KISS | 00000001-ba2a-46c9-ae49-01b0961f68bb | TNC compatibility |
| Meshtastic | (Meshtastic UUIDs) | App compatibility |

## JSON Schema

| Document | Title | LICHEN Use |
|----------|-------|------------|
| [JSON Schema Draft-07](https://json-schema.org/specification-links.html#draft-7) | Validation | Test vector schemas |

## PCAP

| Document | Title | LICHEN Use |
|----------|-------|------------|
| [PCAP](https://www.tcpdump.org/manpages/pcap-savefile.5.txt) | Packet Capture | Wireshark analysis |
| [PCAP-NG](https://pcapng.github.io/pcapng/) | Next Generation | Extended captures |

### LICHEN DLT (Data Link Type)

Custom DLT for LICHEN frames:
- DLT_USER0 (147) or registered DLT
- Wireshark dissector in `tools/wireshark/`
