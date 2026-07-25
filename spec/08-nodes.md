<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Node Types and Roles

## 11. Node Types and Roles

### 11.1. Role Definitions

| Role | IPv6 | RPL | Forwards | Description |
|------|------|-----|----------|-------------|
| Leaf | Host | Leaf | No | Endpoint device, joins RPL but does not forward |
| Router | Router | Full | Yes | Mesh router, participates in DODAG |
| Border Router | Router | Root | Yes | DODAG root, identity-preserving backhaul |
| Gateway | Host | None | L7 only | Protocol translator (MQTT-SN->MQTT) |

### 11.2. Leaf Node (Endpoint)

- Minimal resources (constrained MCU)
- Joins through one preferred RPL parent
- Sends DAO for its native `/128` but does not relay RPL or data traffic
- Sends all traffic via default parent

### 11.3. Router

- Full RPL participation
- Maintains neighbor table and routing state
- Forwards packets for children
- Sends DIOs, processes DAOs

### 11.4. Border Router (6LBR)

- DODAG root
- Installs native `/128` host routes from DAOs
- Provides application gateways and optional separately specified backhauls
- Runs Resource Directory, NTP, etc.
- May aggregate multiple DODAGs

---

[← Previous: Transport and Application](07-transport-app.md) | [Index](README.md) | [Next: Packets and Timing →](09-packets-timing.md)
