<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# LICHEN Protocol Specification

**LoRa IPv6 CoAP Hybrid Extended Network**

**Document Status:** Proposed Design
**Version:** Draft 0.1
**Date:** 2026-05-26
**License:** CC-BY-4.0 (documentation)

## Abstract

LICHEN (LoRa IPv6 CoAP Hybrid Extended Network) is a LoRa-based mesh networking
protocol built entirely on IETF standards: IPv6 with SCHC header compression,
hybrid RPL+LOADng mesh routing, and CoAP application protocols. The design
prioritizes interoperability with existing IP infrastructure, efficient use of
constrained bandwidth, and cryptographic authentication of all packets.

LICHEN uses a three-tier routing architecture: RPL for border router traffic
(efficient tree routing), announce-based gradient routing for peer-to-peer
between active nodes (zero discovery latency), and LOADng as fallback for
unknown destinations (reactive discovery).

Unlike Meshtastic and MeshCore, LICHEN uses real IPv6 addressing, enabling
direct communication with internet hosts via border routers and compatibility
with the broader IoT ecosystem. LICHEN runs on existing Meshtastic-compatible
hardware as a reflash -- same radios, new protocol.

## Table of Contents

### Core Specification

1. [Architecture](01-architecture.md) - Design Principles and Protocol Stack
2. [Physical and Link Layers](02-physical-link.md) - LoRa PHY and Frame Format
2a. [Coordinated Capacity Planning (CCP)](02a-coordinated-capacity.md) - CCP-14 test vectors, abstract/title/scope cross-refs, SFN, TDMA frame structure & slot assignment (project-LICHEN-i9r0.1), interference mitigation, robustness (serves as draft-lichen-ccp)
3. [Adaptation Layer](03-adaptation.md) - SCHC/6LoWPAN Compression
4. [Network Layer](04-network.md) - IPv6 Addressing
5. [Addressing](03-addressing.md) - Human-Readable Node Addresses and IID Derivation from Ed25519
6. [Routing](05-routing.md) - Three-Tier Routing (RPL + Announce + LOADng)
7. [Security](06-security.md) - Security Architecture
8. [Transport and Application](07-transport-app.md) - UDP, CoAP, MQTT-SN
9. [Node Types](08-nodes.md) - Roles and Responsibilities
10. [Gateway Coordination](08-gateway-coordination.md) - Multi-gateway TDMA slot allocation, federation modes (closed PSK + open Ed25519/TOFU), node handoff, CoAP coordination (project-LICHEN-mugl.1)
11. [Packets and Timing](09-packets-timing.md) - Formats and Duty Cycle
12. [Implementation](10-implementation.md) - Platform and Software Notes
13. [Local Client Interface](11-lci.md) - Phone/Desktop Connectivity
14. [Applications](12-apps.md) - Messaging, Position, Emergency

### Appendices

- [Appendix A: SCHC Rules](appendix-schc.md) - Compression Rule Definitions
- [Appendix B: RPL Configuration](appendix-rpl.md) - RPL Routing Parameters
- [Appendix B2: LOADng Configuration](appendix-loadng.md) - LOADng Routing Parameters
- [Appendix C-E: Miscellaneous](appendix-misc.md) - Resource Directory, Comparison, Example
- [Appendix F: SenML Profile](appendix-senml.md) - Sensor Data Format
- [Appendix G: Design Rationale](appendix-design-rationale.md) - Inspirations and Constraints
- [Appendix H: Bufferbloat Avoidance](appendix-bufferbloat.md) - Queue Management and Latency
- [Appendix I: Border Router Hardware](appendix-border-router.md) - Hardware Options
- [Appendix J: C Code Safety](appendix-c-safety.md) - Compiler Hardening and Coding Rules

### Acknowledgments

- [Acknowledgments](99-acknowledgments.md) - In memoriam: Dave Täht

### Historical / Deprecated

- [lichen-native/](lichen-native/) - **Deprecated** early prototype protocol (CBOR
  integer-key framing). Retained for reference only; see
  [Local Client Interface](11-lci.md) for the current native app contract.

### Internet-Drafts (Preliminary)

Standalone documents for novel or reusable components:

- [draft-lichen-schnorr-00](drafts/draft-lichen-schnorr-00.md) - 48-byte Schnorr signatures
- [draft-lichen-schc-lora-00](drafts/draft-lichen-schc-lora-00.md) - SCHC profile for LoRa
- [draft-lichen-rpl-lora-00](drafts/draft-lichen-rpl-lora-00.md) - RPL tuning for LoRa

See [drafts/README.md](drafts/README.md) for status and contributing info.

---

*This document is a design sketch, not a finalized specification. Implementation
will require detailed engineering of timing, buffer management, and edge cases
not covered here.*
