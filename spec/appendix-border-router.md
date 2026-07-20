<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Border Router Hardware Options

A border router terminates RPL as a DODAG root and connects a LICHEN mesh to
backhaul infrastructure. Native node `/128`s may enter Yggdrasil only through
an identity-preserving transport for the owning node; a gateway-owned
Yggdrasil daemon MUST NOT spoof node source addresses. Conventional Internet
and cloud integration therefore uses explicit application proxies unless a
separate routed service is configured.

| Hardware | Connectivity | Notes |
|----------|--------------|-------|
| Heltec V3 | WiFi | ESP32-S3, built-in LoRa, good dev board |
| Raspberry Pi + LoRa HAT | Ethernet/WiFi | Most flexible, full Linux |
| ThinkNode M7 | PoE + WiFi | Industrial, outdoor rated |

---

[Index](README.md)
