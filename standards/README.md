# Standards Reference

This directory contains references to all standards, specifications, and technical
documents that LICHEN depends on or implements.

## Organization

| File | Contents |
|------|----------|
| [ietf-rfcs.md](ietf-rfcs.md) | IETF RFCs (IPv6, CoAP, SCHC, RPL, OSCORE, etc.) |
| [ietf-drafts.md](ietf-drafts.md) | IETF Internet-Drafts (including LICHEN drafts) |
| [lora.md](lora.md) | LoRa Alliance and Semtech specifications |
| [crypto.md](crypto.md) | Cryptographic standards (NIST, CFRG) |
| [ham-radio.md](ham-radio.md) | Amateur radio protocols (KISS, AX.25, APRS) |
| [other.md](other.md) | IEEE, OASIS, ISO, ITU standards |

## Protocol Stack Summary

```
┌─────────────────────────────────────────────────────┐
│  Application    CoAP (RFC 7252), SenML (RFC 8428)   │
│                 CBOR (RFC 8949), MQTT-SN            │
├─────────────────────────────────────────────────────┤
│  Security       OSCORE (RFC 8613), EDHOC (RFC 9528) │
│                 Schnorr-48 (draft-lichen-schnorr)   │
├─────────────────────────────────────────────────────┤
│  Transport      UDP (RFC 768)                       │
├─────────────────────────────────────────────────────┤
│  Routing        RPL (RFC 6550), LOADng, Announce    │
├─────────────────────────────────────────────────────┤
│  Network        IPv6 (RFC 8200), ICMPv6 (RFC 4443)  │
├─────────────────────────────────────────────────────┤
│  Adaptation     SCHC (RFC 8724)                     │
├─────────────────────────────────────────────────────┤
│  Link           LICHEN frame format + Schnorr sigs  │
├─────────────────────────────────────────────────────┤
│  Physical       LoRa CSS (SF10/125kHz/CR4-5)        │
└─────────────────────────────────────────────────────┘
```

## Key Design Choices

| Choice | Standard Used | Why |
|--------|---------------|-----|
| Compression | SCHC (RFC 8724) | Designed for LPWAN, not 802.15.4 |
| Routing | RPL + LOADng | Tree for gateway, reactive for peers |
| Signatures | Schnorr-48 | 25% smaller than Ed25519, same security |
| E2E Security | OSCORE | CoAP-native, proven |
| Key Exchange | EDHOC | Lightweight, 3-message, offline-capable |
