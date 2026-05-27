<!-- Part of LICHEN Protocol Specification -->

# Implementation Notes

## 16. Implementation Notes

### 16.1. Recommended Platforms

| Platform | OS | Notes |
|----------|-----|-------|
| nRF52840 | Zephyr, RIOT | BLE + LoRa (via SPI radio) |
| ESP32-S3 | ESP-IDF, Zephyr | WiFi gateway + LoRa |
| STM32WL | Zephyr, bare metal | Integrated LoRa SoC |
| STM32L4 + SX126x | Contiki-NG | Mature 6LoWPAN stack |

### 16.2. Software Stack

| Component | Recommended |
|-----------|-------------|
| 6LoWPAN/RPL | Contiki-NG, RIOT GNRC |
| SCHC | libschc, OpenSCHC |
| CoAP | libcoap, microcoap |
| OSCORE | RISE OSCORE, aiocoap |
| MQTT-SN | Eclipse Paho MQTT-SN |
| Crypto | TweetNaCl, mbedTLS |

### 16.3. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| IPv6 stack | 8-16 KB | 20-40 KB |
| RPL | 4-8 KB | 15-25 KB |
| CoAP | 2-4 KB | 10-20 KB |
| OSCORE | 2-4 KB | 10-15 KB |
| Crypto | 1-2 KB | 10-20 KB |
| **Total** | **20-40 KB** | **65-120 KB** |

Feasible on nRF52840 (256KB RAM, 1MB Flash) or ESP32.

---

[← Previous: Packets and Timing](09-packets-timing.md) | [Index](README.md) | [Next: Local Client Interface →](11-lci.md)
