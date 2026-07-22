<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Gateway Coordination Protocol (GCP)

## GCP-1. Scope

This document defines the LICHEN Gateway Coordination Protocol for multi-gateway deployments. It enables cooperating gateways to:

- Coordinate TDMA slots to avoid collisions
- Manage channel ownership
- Perform node handoff for mobility
- Maintain a unified DODAG view
- Support both closed (PSK) and open (Ed25519 + TOFU) federation modes

Single-gateway deployments require no coordination. The protocol is OPTIONAL but RECOMMENDED for deployments with 2+ gateways. Implementations MUST support both federation modes as specified in the notes from project-LICHEN-mugl.1.

Gateways coordinate primarily over a backbone link (Ethernet, WiFi, or Internet) using CoAP. LoRa-side discovery provides fallback.

This builds on:
- RPL multi-instance (RFC 6550 §5)
- Adapted 6TiSCH MSF concepts for LoRa (CoAP-based, not 6P)
- OSCORE for security
- Existing LICHEN Ed25519 identities

## GCP-2. Terminology

- **Gateway (GW)**: Border router with backbone connectivity. Each is a RPL DODAG root.
- **Federation**: Set of cooperating gateways.
- **Closed federation**: PSK-based, single operator.
- **Open federation**: Signature-based with TOFU/PKI, multi-operator.
- **Backbone**: IP network connecting gateways (not LoRa).
- **Superframe**: TDMA period synchronized across gateways.
- **Slot allocation**: Division of TDMA slots among gateways.
- **Handoff**: Transfer of node ownership between gateways.
- **lichen-gw**: CoAP resource prefix for coordination (/.well-known/lichen-gw).
- **IID**: Interface Identifier derived from gateway's Ed25519 key (as for nodes).

## GCP-3. Trust Models (MUST implement both)

### 3.1. Closed Federation (PSK)
- All gateways share a pre-configured PSK.
- CoAP messages protected with OSCORE using the PSK.
- Suitable for enterprise, events, single-organization deployments.
- Simple provisioning: one shared secret per federation.
- MUST be supported.

### 3.2. Open Federation (Signatures)
- Gateways use their Ed25519 identity keys (same as nodes).
- Messages signed using truncated Schnorr signatures (see draft-lichen-schnorr-00).
- Trust established via TOFU on first contact; keys pinned thereafter.
- Optional PKI/DANE for stronger verification.
- Enables permissionless community meshes.
- MUST be supported.
- Dual-mode gateways participate in both simultaneously.

Mode selection is per-gateway via configuration. No per-mesh default is mandated. Mixed deployments are explicitly supported for migration.

Non-goals: No central authority, no blockchain, no mandatory PKI.

## GCP-4. Discovery

### 4.1. Backbone Discovery (Primary)
- Gateways send multicast CoAP GET to `ff02::1` on backbone for `/.well-known/lichen-gw/info`.
- Response contains: gateway IID, capabilities, current slot map, superframe time, supported federation modes.
- Periodic announcements and on-change notifications via CoAP Observe.

### 4.2. LoRa Discovery (Fallback)
- Gateway announce frames include GATEWAY flag in link layer.
- Other gateways receiving on LoRa establish radio-path awareness.
- Used when backbone is unavailable or for initial synchronization.

## GCP-5. RPL Multi-Instance Coordination

- All cooperating gateways use the **same RPLInstanceID**.
- Each gateway acts as DODAG root for that instance.
- Nodes see a unified DODAG with multiple possible parents.
- DAO messages propagate across backbone as needed for route aggregation.
- See RFC 6550 Section 5 for multi-instance details; LICHEN-specific parameters in appendix-rpl.md.

## GCP-6. Slot Coordination (6TiSCH-lite for LoRa)

Adapts MSF concepts without full 6P complexity:

### 6.1. Superframe Synchronization
- GPS-equipped gateways use GPS epoch for absolute time.
- Non-GPS: Elect time master (lowest IID wins); others sync via backbone CoAP.
- Superframe duration configurable (e.g. 60 seconds, aligned to UTC).

### 6.2. Slot Allocation
Two options (both MUST be supported):

1. **Interleaved**: Gateway with ordinal N owns slots N, N+G, N+2G... where G = gateway count.
2. **Contiguous blocks**: Simpler for handoff; each gateway owns sequential block of slots.

Gateways claim slots via POST to `/.well-known/lichen-gw/slots` on peer gateways.

### 6.3. Conflict Resolution
- If two gateways claim overlapping slot: lowest IID wins.
- Loser selects next available slot and re-claims.
- Broadcast updated schedule via CoAP to peers and LoRa announces.

### 6.4. CoAP Resources
New resource: `/.well-known/lichen-gw`

| Method | Path          | Description                  | Payload Format |
|--------|---------------|------------------------------|----------------|
| GET    | /info         | Gateway info & capabilities  | SenML/CBOR     |
| GET    | /slots        | Current slot allocation      | CBOR map       |
| POST   | /slots        | Claim or update slots        | CBOR claim obj |
| GET    | /channels     | Channel ownership map        | CBOR map       |
| POST   | /handoff      | Node handoff request         | Node EUI+state |
| GET    | /nodes        | Node registry query          | SenML list     |

All CoAP messages use OSCORE (PSK or signature context per mode).

## GCP-7. Node Handoff

When a node moves (detected via better parent/RSSI):

1. Node sends DAO to new Gateway B.
2. B sends POST /handoff to A (via backbone) with node details.
3. A releases node from its registry, sends confirmation.
4. B confirms handoff to node via CoAP.
5. Routes updated in RPL DODAG.

State transferred includes recent sequence numbers, security contexts if applicable.

## GCP-8. Backwards Compatibility

- Single gateway: no coordination messages sent/expected.
- Legacy gateways without GCP: operate standalone; new gateways detect absence and run independently.
- Gradual rollout supported via dual-mode operation.
- Nodes unaware of coordination (protocol is gateway-to-gateway).

## GCP-9. Security Considerations

- All coordination messages authenticated and encrypted (OSCORE).
- Closed mode: PSK provides group authentication.
- Open mode: Per-gateway signatures + TOFU prevents spoofing.
- Replay protection via sequence numbers and timestamps.
- Rate limiting on CoAP endpoints to prevent DoS.
- See section 6-security.md for overall LICHEN security model.

## GCP-10. Implementation Notes

- Gateways MUST implement both federation modes.
- Use existing LICHEN CoAP/OSCORE stack.
- Rust gateway implementation in `rust/mesh-gateway/` to be extended.
- Zephyr border router support via lichen/subsys.
- Test vectors to be added to test/vectors/ for coordination messages.
- Update LICHEN-plan.md and other specs as needed.
- See project-LICHEN-mugl epic for acceptance criteria.

## References

- RFC 6550: RPL (multi-instance)
- RFC 9030: 6TiSCH Minimal Scheduling Function (adapted)
- LICHEN spec/06-security.md
- LICHEN spec/05-routing.md
- draft-lichen-schnorr-00.md
- test/vectors/ (to be expanded)

This completes the specification for multi-gateway coordination as defined in project-LICHEN-mugl.1. Both federation modes are fully specified as REQUIRED.

