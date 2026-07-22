# LCI Client Guide

How to connect to a LICHEN mesh node using the Local Client Interface (LCI).

## Overview

LCI treats the local connection as an IPv6 interface. Your client gets a
link-local address and talks CoAP to the node at `fe80::1`. Standard CoAP
tools work out of the box.

## Transport Setup

### Serial / USB (SLIP)

1. Connect USB cable
2. Find the serial port: `/dev/ttyACM0` (Linux), `/dev/cu.usbmodem*` (macOS)
3. Run SLIP daemon:

```bash
# Linux
sudo slattach -v -L -p slip /dev/ttyACM0

# Or use socat for raw access
socat -d -d pty,raw,echo=0 file:/dev/ttyACM0,b115200,raw,echo=0
```

4. Configure the interface:

```bash
sudo ip link set sl0 up
sudo ip -6 addr add fe80::2/64 dev sl0
sudo ip -6 route add default via fe80::1 dev sl0
```

### BLE (Nordic UART Service)

1. Scan for the node's BLE advertisement
2. Connect to NUS UUID: `6E400001-B5A3-F393-E0A9-E50E24DCCA9E`
3. SLIP frames go over the TX/RX characteristics
4. Same IPv6 setup as serial, but over the BLE channel

## CoAP Client Examples

Using [aiocoap](https://aiocoap.readthedocs.io/) or `coap-client` (libcoap).

### Discovery

```bash
# List available resources
coap-client -m get coap://[fe80::1%sl0]/.well-known/core

# Output:
# </config>;rt="config",</status>;rt="status";obs,...
```

### Read Node Status

```bash
coap-client -m get coap://[fe80::1%sl0]/status

# Returns CBOR with uptime, battery, radio stats, DODAG info
```

Decode CBOR with `cbor2`:

```bash
coap-client -m get coap://[fe80::1%sl0]/status | python3 -m cbor2.tool
```

### Read Configuration

```bash
# Node config
coap-client -m get coap://[fe80::1%sl0]/config

# Radio config
coap-client -m get coap://[fe80::1%sl0]/config/radio

# Identity (EUI-64, public key, addresses)
coap-client -m get coap://[fe80::1%sl0]/config/identity
```

### Update Configuration

```bash
# Change node name
echo '{"name": "my-node"}' | python3 -c "import sys,cbor2; cbor2.dump(cbor2.load(sys.stdin), sys.stdout.buffer)" | \
  coap-client -m put -f - coap://[fe80::1%sl0]/config

# Change radio SF
echo '{"sf": 10}' | python3 -c "import sys,json,cbor2; cbor2.dump(json.load(sys.stdin), sys.stdout.buffer)" | \
  coap-client -m put -f - coap://[fe80::1%sl0]/config/radio
```

### Observe Status Changes

```bash
# Subscribe to status updates
coap-client -m get -s coap://[fe80::1%sl0]/status

# Subscribe to neighbor table changes
coap-client -m get -s coap://[fe80::1%sl0]/status/neighbors
```

### Key Management

```bash
# List known peers
coap-client -m get coap://[fe80::1%sl0]/keys

# Get specific peer's key
coap-client -m get coap://[fe80::1%sl0]/keys/1234:5678:9abc:def0

# Delete a peer
coap-client -m delete coap://[fe80::1%sl0]/keys/1234:5678:9abc:def0
```

### Send Message to Mesh

```bash
# Direct to mesh node (node routes via LoRa)
coap-client -m get coap://[0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd]/sensors/temp
```

## Python aiocoap Examples

```python
import asyncio
import cbor2
from aiocoap import Context, Message, GET, PUT, OBSERVE

async def main():
    ctx = await Context.create_client_context()

    # GET /status
    req = Message(code=GET, uri="coap://[fe80::1%sl0]/status")
    resp = await ctx.request(req).response
    status = cbor2.loads(resp.payload)
    print(f"Uptime: {status['uptime_s']}s, Battery: {status['battery_pct']}%")

    # PUT /config/radio
    new_config = {"sf": 10, "tx_power_dbm": 17}
    req = Message(code=PUT, uri="coap://[fe80::1%sl0]/config/radio",
                  payload=cbor2.dumps(new_config))
    req.opt.content_format = 60  # application/cbor
    resp = await ctx.request(req).response
    print(f"Config update: {resp.code}")

    # Observe /status/neighbors
    req = Message(code=GET, uri="coap://[fe80::1%sl0]/status/neighbors",
                  observe=0)
    obs = ctx.request(req)
    async for resp in obs.observation:
        neighbors = cbor2.loads(resp.payload)
        print(f"Neighbors: {len(neighbors['neighbors'])}")

asyncio.run(main())
```

## CBOR Payload Reference

All payloads use CBOR (RFC 8949) with string keys.

### /status Response

```json
{
  "uptime_s": 3600,
  "battery_pct": 87,
  "battery_mv": 3950,
  "mem_free_kb": 42,
  "time": {
    "wall_clock_valid": true,
    "unix_time": 1716742800,
    "source_class": "gnss",
    "age_s": 120
  },
  "dodag": {
    "joined": true,
    "rank": 512,
    "parent": "fe80::1234:5678:9abc:def0"
  },
  "radio": {
    "rx_packets": 1234,
    "tx_packets": 567,
    "duty_cycle_pct": 2.3
  }
}
```

### /config/radio

```json
{
  "freq_mhz": 906.875,
  "bw_khz": 125,
  "sf": 9,
  "cr": "4/5",
  "tx_power_dbm": 20,
  "sync_word": "0x34"
}
```

### /keys/{iid}

```json
{
  "iid": "1234:5678:9abc:def0",
  "pubkey": "<base64 Ed25519>",
  "trust": "tofu",
  "first_seen": "2026-05-26T12:00:00Z",
  "last_seen": "2026-05-26T14:30:00Z"
}
```

## Troubleshooting

### No response from node

1. Check serial connection: `screen /dev/ttyACM0 115200`
2. Verify SLIP daemon is running
3. Check IPv6 address: `ip -6 addr show sl0`
4. Ping the node: `ping6 fe80::1%sl0`

### CBOR decode errors

Content-Format must be 60 (application/cbor). Check with:

```bash
coap-client -m get -v coap://[fe80::1%sl0]/status 2>&1 | grep Content-Format
```

### BLE connection drops

- Ensure BLE pairing completed (LE Secure Connections)
- Check MTU negotiation (needs 247+ for full packets)
- Verify NUS characteristics are subscribed

### Cannot reach mesh nodes

- Check routing table: `ip -6 route show`
- Verify node has joined DODAG: `GET /status` → `dodag.joined`
- Ensure destination address is reachable (check `/status/routes`)

## Reference

- Full LCI specification: `spec/11-lci.md`
- Transport bindings: §17.3
- Resource definitions: §17.5
- Security considerations: §17.6
