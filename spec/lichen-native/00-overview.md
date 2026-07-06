# LICHEN Native Protocol (Historical)

> **Status: FROZEN / PROTOTYPE-ONLY**
>
> This CBOR integer-key protocol is a historical draft from early prototyping.
> It is **not** the Local Client Interface contract. Do not implement this
> protocol for new clients, firmware, or simulators.
>
> **Current LCI:** IPv6 + CoAP over SLIP or native transport.
> See [../11-lci.md](../11-lci.md) for the authoritative specification.
>
> This directory is retained solely as a reference for legacy prototype code.
> No new features will be added. No compatibility is guaranteed.

This document describes a **deprecated** transport-agnostic device interface
that was explored during early LICHEN prototyping.

## Purpose

This directory is retained to document an earlier native-device draft and to
support legacy prototype code. It is not the application contract for new
clients, firmware, BLE services, or simulators.

Expose full mesh state and control to host applications over BLE, USB, serial, or TCP/IP with identical framing and semantics.

## Design Principles

1. **Transport-agnostic** — Same wire format everywhere
2. **CBOR encoding** — Compact, schema-evolvable, consistent with CoAP
3. **Integer keys** — Minimize overhead (not string keys)
4. **Extensible** — Unknown fields ignored, version negotiation on connect

## Message Types

| Type | Code | Direction | Description |
|------|------|-----------|-------------|
| hello | 0x01 | bidir | Version/capability negotiation |
| config_get | 0x10 | host→device | Request configuration |
| config_set | 0x11 | host→device | Update configuration |
| config_result | 0x12 | device→host | Configuration response |
| send_message | 0x20 | host→device | Send application message |
| message_received | 0x21 | device→host | Received application message |
| mesh_state | 0x30 | device→host | Gradient table + neighbors |
| node_info | 0x31 | device→host | Status, battery, GPS, uptime |
| log_entry | 0x40 | device→host | Debug log line |
| log_subscribe | 0x41 | host→device | Enable/disable log streaming |
| ota_begin | 0x50 | host→device | Start firmware update |
| ota_chunk | 0x51 | host→device | Firmware chunk |
| ota_finish | 0x52 | host→device | Finalize update |
| ota_status | 0x53 | device→host | Update progress/result |
| raw_tx | 0x60 | host→device | Transmit raw frame |
| raw_rx | 0x61 | device→host | Received raw frame |

## Files

- [01-framing.md](01-framing.md) — Wire framing
- [02-common.md](02-common.md) — Shared CDDL types
- [03-hello.md](03-hello.md) — Connection handshake
- [04-config.md](04-config.md) — Configuration messages
- [05-messaging.md](05-messaging.md) — Application messaging
- [06-mesh-state.md](06-mesh-state.md) — Mesh topology
- [07-node-info.md](07-node-info.md) — Device status
- [08-logging.md](08-logging.md) — Debug log streaming
- [09-ota.md](09-ota.md) — Firmware updates
- [10-raw-frame.md](10-raw-frame.md) — Raw link-layer access
