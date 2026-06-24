# LoRa Specifications

Physical layer and radio specifications from Semtech and LoRa Alliance.

## Semtech LoRa

### Chipset Datasheets

| Document | Description |
|----------|-------------|
| [SX1262 Datasheet](https://www.semtech.com/products/wireless-rf/lora-connect/sx1262) | Sub-GHz transceiver (primary) |
| [SX1276 Datasheet](https://www.semtech.com/products/wireless-rf/lora-connect/sx1276) | Legacy 868/915 MHz transceiver |
| [SX1278 Datasheet](https://www.semtech.com/products/wireless-rf/lora-connect/sx1278) | Legacy 433/470 MHz transceiver |

### LoRa Modulation

LICHEN uses LoRa CSS (Chirp Spread Spectrum) with these defaults:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Spreading Factor | SF10 | Adjustable per-link via ADR |
| Bandwidth | 125 kHz | Fixed |
| Coding Rate | 4/5 | Minimal FEC overhead |
| Preamble | 8 symbols | Standard |
| Sync Word | 0x34 | Distinct from Meshtastic (0x2B) |
| CRC | Enabled | Hardware CRC |

### Regional Parameters

| Region | Frequency | Channels | Duty Cycle |
|--------|-----------|----------|------------|
| US/CA (FCC) | 902-928 MHz | 64 @ 200 kHz | None (FHSS) |
| EU (ETSI) | 863-870 MHz | 3 @ 125 kHz | 1% or 0.1% |
| AU/NZ | 915-928 MHz | 64 @ 200 kHz | None |
| AS923 | 923 MHz | Variable | LBT required |

## LoRa Alliance

### LoRaWAN Specification

LICHEN does **NOT** implement LoRaWAN, but references it for:
- Regional frequency plans
- Duty cycle regulations
- Channel definitions

| Document | Version | Notes |
|----------|---------|-------|
| [LoRaWAN Specification](https://lora-alliance.org/resource_hub/lorawan-specification-v1-0-4/) | 1.0.4 | Star topology (not used) |
| [Regional Parameters](https://lora-alliance.org/resource_hub/rp2-1-0-4-regional-parameters/) | RP2-1.0.4 | Frequency plans (referenced) |

### Why Not LoRaWAN?

| LoRaWAN | LICHEN |
|---------|--------|
| Star topology | Mesh topology |
| Gateway-centric | Peer-to-peer |
| Class A/B/C devices | All nodes equivalent |
| Proprietary join | Ed25519 TOFU |

## Physical Layer Calculations

### Airtime Formula

```
T_symbol = 2^SF / BW
T_preamble = (n_preamble + 4.25) × T_symbol
payload_symbols = 8 + max(ceil((8*PL - 4*SF + 28 + 16) / (4*SF)) * CR, 0)
T_payload = payload_symbols × T_symbol
T_total = T_preamble + T_payload
```

### Example (SF10, 125kHz, 50 bytes)

```
T_symbol = 2^10 / 125000 = 8.192 ms
T_preamble = 12.25 × 8.192 = 100.4 ms
payload_symbols ≈ 33
T_payload = 33 × 8.192 = 270.3 ms
T_total ≈ 371 ms
```

### Link Budget

| Parameter | Typical Value |
|-----------|---------------|
| TX Power | +14 to +22 dBm |
| Antenna Gain | 0 to +3 dBi |
| Path Loss (1km) | ~110 dB @ 915 MHz |
| Receiver Sensitivity | -137 dBm @ SF10 |
| Link Margin | 10-20 dB |
| Max Range (LOS) | 5-15 km |
