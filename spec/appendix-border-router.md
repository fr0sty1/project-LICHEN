<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Border Router Hardware Options

A border router bridges the LICHEN LoRa mesh to IP infrastructure (home network, internet, or cloud). It runs the full IPv6 stack, terminates RPL as DODAG root, and forwards packets between the constrained mesh and conventional networks.

## Hardware Recommendations

Selecting a border router involves tradeoffs among cost, power, throughput, and deployment environment.

### Tier 1: Home / Development (WiFi + LoRa)

**Heltec WiFi LoRa 32 V3** — Best for prototyping, lab testing, and low-traffic home gateways.

| Spec | Value |
|------|-------|
| SoC | ESP32-S3FN8 (240 MHz dual-core, 8 MB flash) |
| LoRa | SX1262 (built-in) |
| Backhaul | WiFi 2.4 GHz (802.11 b/g/n) |
| Power | ~250 mA RX, ~500 mA TX (20 dBm), USB-C |
| Cost | ~$25 |
| Antenna | u.FL to SMA pigtail (868/915 MHz whip included) |

**Pros:** Cheap, integrated, Zephyr-native (no Linux needed as 6LBR runs on-ESP32). **Cons:** WiFi backhaul limits throughput to ~3 Mbps; no Ethernet; single-LoRa-channel reduces capacity.

**Seeed T-Deck** — ESP32-S3 with keyboard, display, and SX1262. Useful for portable/field border router with local UI.

### Tier 2: Serious Deployment (Linux + LoRa Hat)

**Raspberry Pi 4/5 + RAK2287 Concentrator** — Full Linux stack for production gateways, multi-channel LoRa, and rich monitoring.

| Spec | Value |
|------|-------|
| Compute | RPi 4 (4 GB) or RPi 5 (8 GB) |
| LoRa | RAK2287 (SX1302, 8-channel concentrator) |
| Backhaul | Gigabit Ethernet or WiFi 5 |
| Storage | 32 GB+ SD card or USB SSD |
| Power | ~3 W RPi + ~1 W HAT = ~4 W idle, ~6 W TX |
| Cost | ~$235 (RPi 5 $60 + RAK2287 $120 + antenna/GPS/case) |
| Antenna | External SMA, 5–8 dBi omnidirectional or directional yagi |

**Pros:** 8 simultaneous LoRa channels (throughput ~8× single-channel), full Linux for advanced routing (RPL root, 6LBR, CoAP proxy, Prometheus metrics, Grafana), GPS time sync for accurate TDMA. **Cons:** Higher power, larger physical footprint, needs SD/USB SSD reliability management.

**RAK5146 USB variant** offers same SX1302 over USB instead of SPI, for easier physical mounting.

### Tier 3: Remote / Solar Sites (Cellular Backhaul)

Custom SBC + LoRa concentrator + cellular modem for off-grid deployments where no WiFi or Ethernet exists.

| Component | Example |
|-----------|---------|
| SBC | Raspberry Pi 5 (low power) or Jetson Nano (edge AI) |
| LoRa | RAK2287 (8-channel) or RAK5146 (USB) |
| Cellular | Quectel EG25-G (4G LTE, ~$40), Sixfab Shield (~$80) |
| Power | Solar panel 100 W + 12 V battery + MPPT controller |
| Enclosure | IP66 weatherproof NEMA 4X |
| Antenna | LoRa: 8 dBi yagi; Cellular: 5 dBi omni (LTE); GPS: active patch |
| Cost | ~$600–$1,000 (SBC + LoRa + Cell + Solar + Enclosure) |

**Pros:** True off-grid operation, multi-channel LoRa + reliable backhaul. **Cons:** High cost, cellular data plan needed, weather exposure.

### Power Budget Comparison

| Tier | Idle | Active | Peak TX | Source |
|------|------|--------|---------|--------|
| Heltec V3 | ~0.8 W | ~1.2 W | ~2.5 W | USB-C (5 V / 0.5 A) |
| RPi 4 + RAK2287 | ~4 W | ~5 W | ~7 W | PoE (802.3af) or 5 V / 3 A |
| Solar cellular | ~6 W | ~8 W | ~12 W | 100 W solar + 12 V / 20 Ah battery |
| ThinkNode M7 | ~3 W (PoE) | ~4 W | ~6 W | PoE (802.3af) |

### Backhaul Options

| Backhaul | Latency | Bandwidth | Power | Cost |
|----------|---------|-----------|-------|------|
| Ethernet | <1 ms | 1 Gbps | ~0 W (PoE) | $0 (existing) |
| WiFi | 2–10 ms | 100–300 Mbps | ~0.5 W | $0 (existing) |
| Cellular LTE | 20–50 ms | 10–50 Mbps | ~2 W | $10–50/mo plan |
| Satellite (Starlink) | 25–50 ms | 25–100 Mbps | ~50 W | $120/mo + $600 HW |
| Satellite (Iridium) | 1–2 s | 2.4 kbps | ~5 W | $100–500/mo |

For most deployments: Ethernet when available > WiFi > Cellular > Satellite. LoRa mesh throughput itself (~250 bps–22 kbps) means WiFi backhaul is rarely the bottleneck.

### Antenna Considerations

- **Frequency band:** Match antenna to regulatory region (US 902–928 MHz, EU 863–870 MHz, AU 915–928 MHz).
- **Gain:** 5–8 dBi omnidirectional for general coverage; directional yagi (10–12 dBi) for point-to-point between gateways.
- **Polarization:** Vertical (standard for LoRa handheld nodes). Circular (RHCP) for mobile/rotary installations.
- **Lightning protection:** Gas discharge tube + ground for outdoor installations.
- **Mounting:** Mast-top preferred; avoid metal roofs, chimney flues, and ground-level placement.
- **Cable:** LMR-400 or equivalent for runs over 3 m; minimize connector losses (SMA → N-type preferred outside).

[Index](README.md)
