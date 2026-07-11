<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Border Router Hardware Options

A border router bridges the LICHEN LoRa mesh to IP infrastructure (home network, internet, or cloud). It runs the full IPv6 stack, terminates RPL as DODAG root, and forwards packets between the constrained mesh and conventional networks.

| Hardware | Connectivity | Notes |
|----------|--------------|-------|
| Heltec V3 | WiFi | ESP32-S3, built-in LoRa, good dev board |
| Raspberry Pi + LoRa HAT | Ethernet/WiFi | Most flexible, full Linux |
| ThinkNode M7 | PoE + WiFi | Industrial, outdoor rated |

---

[Index](README.md)
