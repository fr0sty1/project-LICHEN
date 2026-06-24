# IETF Internet-Drafts

Work-in-progress standards and LICHEN-specific protocol documents.

## LICHEN Protocol Drafts

These are designed for eventual IETF submission:

| Draft | Title | Status |
|-------|-------|--------|
| draft-lichen-schnorr-00 | Schnorr Signatures with Truncated Challenge | Local spec |
| draft-lichen-schc-lora-00 | SCHC Profile for LoRa Mesh Networks | Local spec |
| draft-lichen-rpl-lora-00 | RPL Configuration for LoRa Mesh Networks | Local spec |
| draft-lichen-link-01 | LICHEN Link Layer Frame Format | Local spec |
| draft-lichen-ota-00 | LICHEN Over-The-Air Firmware Updates | Local spec |

See `spec/drafts/` for full documents.

## Referenced External Drafts

| Draft | Title | LICHEN Use |
|-------|-------|------------|
| [draft-ietf-roll-aodv-rpl](https://datatracker.ietf.org/doc/draft-ietf-roll-aodv-rpl/) | AODV-RPL (LOADng) | Reactive route discovery |
| [draft-tuexen-opsawg-pcapng](https://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng/) | PCAP-NG Format | Packet capture format |

## Draft Lifecycle

```
Local Spec (spec/drafts/)
    ↓
Individual I-D Submission
    ↓
Working Group Adoption (ROLL, CORE, LAKE)
    ↓
RFC Publication
```

## LICHEN Draft Summaries

### draft-lichen-schnorr-00

48-byte Schnorr signatures for constrained networks:
- Curve: Ed25519
- Challenge: SHA-512 truncated to 128 bits (16 bytes)
- Format: e[0:16] || s (16 + 32 = 48 bytes)
- Security: 128-bit (same as Ed25519, 25% smaller)

### draft-lichen-schc-lora-00

SCHC compression rules optimized for LoRa mesh:
- Rule 0: Link-local IPv6+UDP (2 bytes)
- Rule 1: Global IPv6+UDP (10 bytes)
- Fragmentation: ACK-on-Error mode

### draft-lichen-rpl-lora-00

RPL parameters tuned for LoRa latency:
- Trickle Imin: 60s (vs 1s default)
- Trickle Imax: 18 doublings (~3 days)
- DIO interval: Longer for duty-cycle compliance
- Non-storing mode: Border router holds routes

### draft-lichen-link-01

Link layer frame format:
- Length (1B) + LLSec (1B) + Epoch (1B) + SeqNum (2B)
- Variable addressing (none/short/extended/elided)
- 48-byte Schnorr signature
- Optional AES-128-CCM encryption
