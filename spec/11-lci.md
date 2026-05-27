<!-- Part of LICHEN Protocol Specification -->

# Local Client Interface

## 17. Local Client Interface

### 17.1. Overview

The Local Client Interface (LCI) connects external applications (phone apps,
desktop clients, RTOS tasks) to the mesh node. Unlike Meshtastic's proprietary
protobuf-over-GATT approach, LCI treats the local connection as another IPv6
interface, using the same CoAP protocol stack as mesh traffic.

**Design Principles:**

1. **Unified protocol:** CoAP everywhere, no separate local API
2. **Transport-agnostic:** Same framing works over BLE, serial, USB, IPC
3. **Client is a neighbor:** Gets link-local IPv6 address, routes through node
4. **Standard tools work:** Any CoAP client can control the node
5. **Push via Observe:** Notifications use CoAP Observe (RFC 7641)

### 17.2. Architecture

```
+------------------------------------------------------------------+
|                         Client Device                             |
|  (Phone, Laptop, RTOS Task)                                       |
|                                                                   |
|  +---------------+  +---------------+  +-----------------------+  |
|  | Mesh App      |  | Config Tool   |  | Other CoAP Clients    |  |
|  +-------+-------+  +-------+-------+  +-----------+-----------+  |
|          |                  |                      |              |
|          +------------------+----------------------+              |
|                             |                                     |
|                      +------+-------+                             |
|                      | CoAP Client  |                             |
|                      | fe80::client |                             |
|                      +------+-------+                             |
+----------------------------|--------------------------------------+
                             | SLIP / BLE / IPC
+----------------------------|--------------------------------------+
|                      +------+-------+          Mesh Node          |
|                      | Local I/F    |                             |
|                      | fe80::1      |                             |
|                      +------+-------+                             |
|                             |                                     |
|                      +------+-------+                             |
|                      |  IPv6 Stack  |                             |
|                      |  CoAP Server |                             |
|                      |  fe80::node  |                             |
|                      +------+-------+                             |
|                             |                                     |
|                      +------+-------+                             |
|                      | LoRa Radio   |                             |
|                      | Interface    |                             |
|                      +--------------+                             |
+-------------------------------------------------------------------+
```

The client and node communicate via link-local IPv6. The node acts as a
router: traffic to mesh addresses is forwarded over LoRa.

### 17.3. Transport Bindings

All transports carry IPv6 packets. Framing adapts to the transport.

#### 17.3.1. Serial / USB (SLIP)

SLIP (RFC 1055) framing over UART or USB CDC-ACM:

```
+------+---------------------+------+
| 0xC0 |  IPv6 Packet        | 0xC0 |
| END  |  (escaped)          | END  |
+------+---------------------+------+
```

Escaping:
- 0xC0 (END) in data -> 0xDB 0xDC
- 0xDB (ESC) in data -> 0xDB 0xDD

Recommended baud: 115200 or higher.

#### 17.3.2. Bluetooth Low Energy

**Option A: SLIP over BLE UART (Nordic UART Service or similar)**

- UUID: vendor-specific or 6E400001-B5A3-F393-E0A9-E50E24DCCA9E (NUS)
- TX/RX characteristics carry SLIP-framed IPv6
- Simple, works with existing BLE serial libraries

**Option B: 6LoWPAN over BLE (RFC 7668)**

- Standard IPSP (Internet Protocol Support Profile)
- L2CAP connection-oriented channels
- More overhead, but fully standard
- Header compression via 6LoWPAN IPHC

Implementations SHOULD support Option A. Option B is OPTIONAL.

#### 17.3.3. Bluetooth Classic (SPP)

SLIP framing over RFCOMM/SPP. Same as serial.

#### 17.3.4. RTOS IPC (Same-Device)

For applications running on the same MCU as the network stack:

```c
// Send IPv6 packet to network stack
void lci_send(const uint8_t *ipv6_pkt, size_t len);

// Receive IPv6 packet from network stack
size_t lci_recv(uint8_t *buf, size_t max_len, uint32_t timeout_ms);
```

Implementation may use:
- FreeRTOS queues / stream buffers
- Zephyr message queues / pipes
- Direct function calls (if same thread context)

No framing needed; packets are discrete.

### 17.4. Client IPv6 Address

The client obtains a link-local address for the local interface:

**Static (simple):**
```
Client: fe80::2
Node:   fe80::1
```

**EUI-64 derived:**
```
Client: fe80::<IID from device MAC>
Node:   fe80::<IID from node EUI-64>
```

The node acts as default router for the client. Client's routing table:

```
fe80::/10       -> local interface (direct)
::/0            -> fe80::1 (node)
```

### 17.5. CoAP Resources

The node exposes a CoAP server on UDP port 5683. All resources below are
relative to the node's link-local address.

#### 17.5.1. Discovery

```
GET coap://[fe80::1]/.well-known/core

Response:
</config>;rt="config",
</config/radio>;rt="config",
</config/identity>;rt="config",
</status>;rt="status";obs,
</status/neighbors>;rt="status";obs,
</status/routes>;rt="status",
</keys>;rt="keystore",
</mesh>;rt="proxy"
```

#### 17.5.2. Configuration Resources

**Node Configuration**

```
GET /config
Content-Format: application/cbor

{
  "name": "my-node",
  "role": "router",         // "leaf", "router", "border-router"
  "radio": "/config/radio",
  "identity": "/config/identity"
}
```

```
PUT /config
Content-Format: application/cbor

{
  "name": "new-name",
  "role": "router"
}

Response: 2.04 Changed
```

**Radio Configuration**

```
GET /config/radio
Content-Format: application/cbor

{
  "freq_mhz": 906.875,
  "bw_khz": 125,
  "sf": 9,
  "cr": "4/5",
  "tx_power_dbm": 20,
  "sync_word": "0x34"
}
```

```
PUT /config/radio
Content-Format: application/cbor

{
  "sf": 10,
  "tx_power_dbm": 17
}

Response: 2.04 Changed
```

**Identity (Read-Only)**

```
GET /config/identity
Content-Format: application/cbor

{
  "eui64": "0x0011223344556677",
  "pubkey": "<base64 Ed25519 public key>",
  "pubkey_fingerprint": "SHA256:xY7...",
  "addrs": {
    "link_local": "fe80::0211:22ff:fe33:4455",
    "ula": "fd12:3456:789a:1::0211:22ff:fe33:4455",
    "gua": null
  }
}
```

#### 17.5.3. Status Resources

**Node Status (Observable)**

```
GET /status
Observe: 0
Content-Format: application/cbor

{
  "uptime_s": 3600,
  "battery_pct": 87,
  "battery_mv": 3950,
  "mem_free_kb": 42,
  "dodag": {
    "joined": true,
    "rank": 512,
    "parent": "fe80::1234:5678:9abc:def0",
    "root": "fd12:3456:789a:1::1"
  },
  "radio": {
    "rx_packets": 1234,
    "tx_packets": 567,
    "rx_errors": 12,
    "duty_cycle_pct": 2.3
  }
}
```

Status updates pushed via Observe on significant changes.

**Neighbor Table (Observable)**

```
GET /status/neighbors
Content-Format: application/cbor

{
  "neighbors": [
    {
      "addr": "fe80::aaaa:bbbb:cccc:dddd",
      "rssi_dbm": -85,
      "snr_db": 7.5,
      "etx": 1.2,
      "last_seen_s": 30,
      "trust": "tofu"
    },
    {
      "addr": "fe80::1111:2222:3333:4444",
      "rssi_dbm": -72,
      "snr_db": 12.0,
      "etx": 1.0,
      "last_seen_s": 5,
      "trust": "dane"
    }
  ]
}
```

**Routing Table**

```
GET /status/routes
Content-Format: application/cbor

{
  "routes": [
    {
      "prefix": "fd12:3456:789a:1::/64",
      "via": "fe80::1234:5678:9abc:def0",
      "metric": 512,
      "lifetime_s": 1800
    }
  ],
  "default_route": "fe80::1234:5678:9abc:def0"
}
```

#### 17.5.4. Key Store

**List Keys**

```
GET /keys
Content-Format: application/cbor

{
  "keys": [
    {
      "iid": "1234:5678:9abc:def0",
      "pubkey_fp": "SHA256:xY7...",
      "trust": "tofu",
      "first_seen": "2026-05-26T12:00:00Z",
      "last_seen": "2026-05-26T14:30:00Z"
    }
  ]
}
```

**Get Single Key**

```
GET /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "iid": "1234:5678:9abc:def0",
  "pubkey": "<base64>",
  "trust": "tofu",
  "first_seen": "2026-05-26T12:00:00Z",
  "last_seen": "2026-05-26T14:30:00Z"
}
```

**Add/Update Key (Manual Trust)**

```
PUT /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "pubkey": "<base64>",
  "trust": "verified"
}

Response: 2.04 Changed
```

**Delete Key**

```
DELETE /keys/1234:5678:9abc:def0

Response: 2.02 Deleted
```

#### 17.5.5. Mesh Proxy

The client can reach any mesh node by addressing it directly. The local
node routes the traffic. No special proxy resource is required.

```
# Client sends directly to mesh node
GET coap://[fd12:3456:789a:1::aaaa:bbbb:cccc:dddd]/sensors/temp

# Node routes via LoRa mesh, returns response to client
Response: 2.05 Content
{temperature: 23.5}
```

For discovery, the client can query the Resource Directory (if available):

```
GET coap://[fd12:3456:789a:1::1]/rd-lookup/res?rt=temperature
```

#### 17.5.6. Messaging (Application-Level)

For human messaging (chat-like), nodes MAY implement:

```
# Send message
POST /msg
Content-Format: application/cbor

{
  "to": "fd12:3456:789a:1::aaaa:bbbb:cccc:dddd",
  "body": "Hello from the mesh!",
  "ack": true
}

Response: 2.01 Created
Location-Path: /msg/outbox/42
```

```
# Receive messages (Observable)
GET /msg/inbox
Observe: 0
Content-Format: application/cbor

{
  "messages": [
    {
      "id": 17,
      "from": "fd12:3456:789a:1::1111:2222:3333:4444",
      "body": "Hi there!",
      "received": "2026-05-26T14:35:00Z"
    }
  ]
}
```

This is OPTIONAL. Applications MAY instead use CoAP directly to mesh nodes.

### 17.6. Security

#### 17.6.1. Transport Security

The local link may be unencrypted (trusted physical access) or encrypted:

| Transport | Encryption |
|-----------|------------|
| USB/Serial | None (physical security) |
| BLE | BLE pairing (LE Secure Connections) |
| WiFi | WPA2/3 |
| RTOS IPC | None (same device) |

#### 17.6.2. Application Security

For sensitive operations, use OSCORE over the local link:

- OSCORE context established via pairing
- Protects against compromised transport
- Same mechanism as mesh traffic

#### 17.6.3. Access Control

Implementations SHOULD support restricting local client access:

| Level | Allowed Operations |
|-------|-------------------|
| Read-only | GET on all resources |
| Standard | GET, Observe, mesh proxy |
| Admin | All operations including PUT /config, DELETE /keys |

Access level determined by transport (e.g., USB = admin, BLE = standard).

### 17.7. Implementation Notes

**Minimal Implementation:**

A constrained node MUST implement:
- SLIP framing (serial)
- /.well-known/core
- /config (read-only acceptable)
- /status

**Full Implementation:**

A capable node (border router, gateway) SHOULD implement:
- All transports (SLIP, BLE, WiFi if available)
- All resources
- Observe on status resources
- OSCORE for local link

**Memory Impact:**

| Component | Additional RAM | Additional Flash |
|-----------|----------------|------------------|
| SLIP framing | 256 B | 512 B |
| LCI CoAP resources | 1-2 KB | 4-8 KB |
| BLE UART service | 512 B | 2 KB |

---

[← Previous: Implementation](10-implementation.md) | [Index](README.md) | [Next: Applications →](12-apps.md)
