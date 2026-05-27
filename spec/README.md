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
RPL mesh routing, and CoAP application protocols. The design prioritizes
interoperability with existing IP infrastructure, efficient use of constrained
bandwidth, and cryptographic authentication of all packets.

Unlike Meshtastic and MeshCore, LICHEN uses real IPv6 addressing, enabling
direct communication with internet hosts via border routers and compatibility
with the broader IoT ecosystem. LICHEN runs on existing Meshtastic-compatible
hardware as a reflash -- same radios, new protocol.

## Table of Contents

### Core Specification

1. [Architecture](01-architecture.md) - Design Principles and Protocol Stack
2. [Physical and Link Layers](02-physical-link.md) - LoRa PHY and Frame Format
3. [Adaptation Layer](03-adaptation.md) - SCHC/6LoWPAN Compression
4. [Network Layer](04-network.md) - IPv6 Addressing
5. [Routing](05-routing.md) - RPL Mesh Routing
6. [Security](06-security.md) - Security Architecture
7. [Transport and Application](07-transport-app.md) - UDP, CoAP, MQTT-SN
8. [Node Types](08-nodes.md) - Roles and Responsibilities
9. [Packets and Timing](09-packets-timing.md) - Formats and Duty Cycle
10. [Implementation](10-implementation.md) - Platform and Software Notes
11. [Local Client Interface](11-lci.md) - Phone/Desktop Connectivity
12. [Applications](12-apps.md) - Messaging, Position, Emergency

### Appendices

- [Appendix A: SCHC Rules](appendix-schc.md) - Compression Rule Definitions
- [Appendix B: RPL Configuration](appendix-rpl.md) - Routing Parameters
- [Appendix C-E: Miscellaneous](appendix-misc.md) - Resource Directory, Comparison, Example
- [Appendix F: SenML Profile](appendix-senml.md) - Sensor Data Format

---

*This document is a design sketch, not a finalized specification. Implementation
will require detailed engineering of timing, buffer management, and edge cases
not covered here.*
