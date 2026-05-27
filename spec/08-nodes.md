<!-- Part of LICHEN Protocol Specification -->

# Node Types and Roles

## 11. Node Types and Roles

### 11.1. Role Definitions

| Role | IPv6 | RPL | Forwards | Description |
|------|------|-----|----------|-------------|
| Leaf | Host | None | No | Endpoint device, no routing |
| Router | Router | Full | Yes | Mesh router, participates in DODAG |
| Border Router | Router | Root | Yes | DODAG root, internet gateway |
| Gateway | Host | None | L7 only | Protocol translator (MQTT-SN->MQTT) |

### 11.2. Leaf Node (Endpoint)

- Minimal resources (constrained MCU)
- Associates with one parent router
- Does not participate in RPL
- Sends all traffic via default parent

### 11.3. Router

- Full RPL participation
- Maintains neighbor table and routing state
- Forwards packets for children
- Sends DIOs, processes DAOs

### 11.4. Border Router (6LBR)

- DODAG root
- Assigns global prefix to mesh
- Routes between mesh and external IPv6
- Runs Resource Directory, NTP, etc.
- May aggregate multiple DODAGs

---

[← Previous: Transport and Application](07-transport-app.md) | [Index](README.md) | [Next: Packets and Timing →](09-packets-timing.md)
