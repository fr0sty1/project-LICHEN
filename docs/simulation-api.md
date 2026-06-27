# Simulation Space API Reference

This document describes the APIs for interacting with the LICHEN network simulator.

## Overview

The simulator provides three interfaces:

1. **TCP Node Protocol** - Binary protocol for simulated radio nodes
2. **REST API** - HTTP endpoints for managing simulations
3. **WebSocket API** - Real-time event streaming

### Quick Start

```bash
# Start the simulator
lichen-sim --node-port 4444 --api-port 4445
```

## TCP Node Protocol

Binary protocol over TCP for SimRadio clients. Each connection represents one simulated node.

### Connection Flow

1. Connect to `127.0.0.1:4444` (default)
2. Send `REGISTER` message with sim_id, node_id, position
3. Receive `OK` on success
4. Exchange TX/RX/TIME/CAD messages
5. Close connection when done

### Message Framing

All messages use a 4-byte little-endian length prefix:

```
[length: uint32_le][payload: bytes]
```

### Message Types

| Type | Code | Direction | Description |
|------|------|-----------|-------------|
| OK | 0x00 | Server | Success response |
| REGISTER | 0x01 | Client | Register node with position |
| TX | 0x10 | Client | Transmit payload |
| TX_DONE | 0x11 | Server | Transmit complete with airtime |
| TX_FAIL | 0x12 | Server | Transmit failed (duty cycle) |
| RX | 0x20 | Client | Start receive with timeout |
| RX_OK | 0x21 | Server | Receive success with payload/RSSI/SNR |
| RX_TIMEOUT | 0x22 | Server | Receive timeout |
| TIME | 0x30 | Client | Query simulation time |
| TIME_OK | 0x31 | Server | Time response |
| CAD | 0x40 | Client | Channel activity detection |
| CAD_RESULT | 0x41 | Server | CAD result |
| ERR | 0xFF | Server | Error with code and message |

### Message Formats

**REGISTER (0x01)**
```
[type: 0x01]
[sim_id_len: uint8][sim_id: utf8]
[node_id_len: uint8][node_id: utf8]
[x: float64_le][y: float64_le][z: float64_le]
```

**TX (0x10)**
```
[type: 0x10]
[payload_len: uint16_le][payload: bytes]
```

**TX_DONE (0x11)**
```
[type: 0x11]
[airtime_us: uint32_le]
```

**RX (0x20)**
```
[type: 0x20]
[timeout_ms: uint32_le]
```

**RX_OK (0x21)**
```
[type: 0x21]
[payload_len: uint16_le][payload: bytes]
[rssi: int16_le][snr: int16_le]
```

**TIME_OK (0x31)**
```
[type: 0x31]
[time_us: uint64_le]
```

**CAD (0x40)**
```
[type: 0x40]
[timeout_ms: uint32_le]
```

**CAD_RESULT (0x41)**
```
[type: 0x41]
[detected: uint8]  # 0 = no activity, 1 = activity detected
```

**ERR (0xFF)**
```
[type: 0xFF]
[code: uint8][msg_len: uint8][msg: utf8]
```

## REST API

HTTP endpoints for simulation management. Default port: 4445.

### Create Simulation

```
POST /sim
```

**Request:**
```json
{"id": "sim1", "time_mode": "barrier_sync"}
```

`time_mode`: `"barrier_sync"` (default) or `"realtime"`

**Response:**
```json
{"id": "sim1", "status": "created"}
```

### Get Simulation

```
GET /sim/{sim_id}
```

**Response:**
```json
{
  "id": "sim1",
  "time_us": 1000000,
  "node_count": 5,
  "time_mode": "barrier_sync"
}
```

### Delete Simulation

```
DELETE /sim/{sim_id}
```

**Response:**
```json
{"status": "deleted"}
```

### Add Node

```
POST /sim/{sim_id}/node
```

**Request:**
```json
{"id": "node1", "x": 0, "y": 0, "z": 0}
```

**Response:**
```json
{"id": "node1", "position": [0, 0, 0]}
```

### Remove Node

```
DELETE /sim/{sim_id}/node/{node_id}
```

**Response:**
```json
{"status": "removed"}
```

### Move Node

```
PATCH /sim/{sim_id}/node/{node_id}
```

**Request:**
```json
{"x": 100, "y": 200, "z": 0}
```

**Response:**
```json
{"id": "node1", "position": [100, 200, 0]}
```

### Advance Time

```
POST /sim/{sim_id}/tick
```

**Request:**
```json
{"time_us": 1000000}
```

**Response:**
```json
{"time_us": 1000000, "events_processed": 42}
```

### Get Metrics

```
GET /sim/{sim_id}/metrics
```

**Response:**
```json
{
  "transmissions": 100,
  "receptions": 85,
  "collisions": 10,
  "delivery_rate": 0.85,
  "collision_rate": 0.10,
  "latency_us": {"min": 1000, "max": 5000, "avg": 2500}
}
```

### Get Topology

```
GET /sim/{sim_id}/topology
```

**Response:**
```json
{
  "nodes": [
    {"id": "node1", "x": 0, "y": 0, "z": 0, "connected": true},
    {"id": "node2", "x": 100, "y": 0, "z": 0, "connected": true}
  ]
}
```

### Chaos Rules

**Add Drop Rule**
```
POST /sim/{sim_id}/chaos/drop
{"node_id": "node1", "direction": "both"}
```
Direction: `"tx"`, `"rx"`, or `"both"`

**Add Partition Rule**
```
POST /sim/{sim_id}/chaos/partition
{"groups": [["node1", "node2"], ["node3", "node4"]]}
```

**Add Degrade Rule**
```
POST /sim/{sim_id}/chaos/degrade
{"node_id": "node1", "rssi_penalty_db": 10}
```

**Add Jammer Rule**
```
POST /sim/{sim_id}/chaos/jam
{"x": 50, "y": 50, "z": 0, "radius_m": 100}
```

**Add Latency Rule**
```
POST /sim/{sim_id}/chaos/latency
{"node_id": "node1", "added_us": 5000}
```

**List Rules**
```
GET /sim/{sim_id}/chaos
```

**Clear Rules**
```
DELETE /sim/{sim_id}/chaos
```

## WebSocket API

Real-time event streaming. Connect to `/sim/{sim_id}/ws`.

### Connection

```javascript
const ws = new WebSocket('ws://localhost:4445/sim/sim1/ws');
```

On connect, server sends:
```json
{"event": "connected", "client_id": "abc123", "sim_id": "sim1"}
```

### Commands

**Subscribe to events:**
```json
{"cmd": "subscribe", "events": ["tx_start", "rx_success"]}
```

**Unsubscribe:**
```json
{"cmd": "unsubscribe", "events": ["collision"]}
```

**Clear subscriptions (receive all):**
```json
{"cmd": "clear_subscriptions"}
```

**Ping:**
```json
{"cmd": "ping"}
```

### Event Types

| Event | Fields |
|-------|--------|
| tx_start | node_id, tx_id, payload_len, time_us |
| tx_end | node_id, tx_id, time_us |
| rx_success | node_id, tx_id, from_node_id, payload_len, rssi, snr, time_us |
| rx_timeout | node_id, time_us |
| collision | node_id, tx_ids, time_us |
| node_added | node_id, x, y, z |
| node_removed | node_id |

## Examples

See `python/examples/` for complete examples:

- `basic_two_node.py` - Simple two-node communication
- `mesh_topology.py` - Multi-node mesh network
- `chaos_testing.py` - Chaos engineering tests
- `pcap_capture.py` - Packet capture to pcapng
