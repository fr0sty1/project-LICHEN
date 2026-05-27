<!-- Part of LICHEN Protocol Specification -->

# Adaptation Layer

## 5. Adaptation Layer

### 5.1. SCHC Overview (RFC 8724)

Static Context Header Compression uses pre-shared "rules" to compress
headers. Both sender and receiver store identical rule sets; packets
carry only a Rule ID and residue (changed fields).

### 5.2. Compression Gains

| Headers | Uncompressed | SCHC Compressed |
|---------|--------------|-----------------|
| IPv6 | 40 bytes | 1-2 bytes (link-local) |
| IPv6 + UDP | 48 bytes | 3-6 bytes |
| IPv6 + UDP + CoAP | 60+ bytes | 6-12 bytes |

### 5.3. Rule Structure

Each rule specifies, for each header field:
- **TV (Target Value):** Expected value
- **MO (Matching Operator):** equal, ignore, MSB(n), etc.
- **CDA (Compression/Decompression Action):** not-sent, value-sent, LSB(n), etc.

### 5.4. Default Rules

**Rule 0: Link-local IPv6 + UDP (most common)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (from L2) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (from L2) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 2 bytes** (Rule ID + 2x 4-bit port residue)

**Rule 1: Global IPv6 + UDP (internet-routable)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.SrcPrefix | mesh_prefix/64 | equal | not-sent |
| IPv6.DstPrefix | 0 | ignore | value-sent (64 bits) |
| (other fields as Rule 0) | | | |

**Compressed size: 10 bytes** (includes full destination prefix)

### 5.5. Fragmentation

Packets exceeding L2 MTU are fragmented per RFC 8724 Section 8:

**Fragment Header:**
```
+--------+--------+--------+
| RuleID | W | FCN | (MIC) |
+--------+--------+--------+
```

- **W (Window):** 1-bit window indicator
- **FCN (Fragment Counter):** 6 bits, counts down from N to 0
- **MIC:** Message Integrity Check on final fragment

**ACK-on-Error mode** recommended for LoRa: receiver only sends NACK
for missing fragments.

---

[← Previous: Physical and Link Layers](02-physical-link.md) | [Index](README.md) | [Next: Network Layer →](04-network.md)
