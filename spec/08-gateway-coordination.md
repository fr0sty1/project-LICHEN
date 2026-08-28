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
- If two gateways claim overlapping slot: lowest IID MUST win.
- Loser MUST select next available slot and re-claim.
- Loser MUST broadcast updated schedule via CoAP to peers and LoRa announces.
- Gateways MUST verify the Schnorr signature on any slot-claim message from another gateway. Claims with invalid or missing signatures MUST be silently discarded.
- Overlapping claims where both signatures verify MUST be resolved by lowest IID (above). Overlapping claims where one signature fails and the other succeeds: the valid claim MUST be accepted and the invalid one MUST be ignored.

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

### 6.5. GCP Slot Claim COSE_Sign1

Slot claims (POST to `/.well-known/lichen-gw/slots`) are authenticated using
COSE_Sign1 with the Schnorr48-Ed25519 algorithm, enabling signature verification
per GCP-6.3 conflict resolution.

**COSE_Sign1 Structure:**

```
POST coap://[peer-gateway]/.well-known/lichen-gw/slots
Content-Format: application/cose; cose-type="cose-sign1" (TBD)
OSCORE: <gateway pairwise context>

COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<gateway-iid>'},  ; unprotected: {kid: claiming gateway 8-byte IID}
  h'<payload>',           ; see Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

**Payload Structure (CBOR map):**

```cbor
{
  1: [<slot indices>],    ; slots: array of uint slot numbers being claimed
  2: <uint>,              ; superframe_epoch: superframe counter at claim time
  3: <0|1>,               ; mode: 0=interleaved, 1=contiguous (per 6.2)
  4: <unix timestamp>,    ; expiry: uint, claim valid until
  5: h'<8-byte IID>',     ; gateway_iid: binds claim to this gateway
  6: <uint>               ; claim_seq: monotonic sequence number
}
```

Integer keys minimize payload size. The payload is the serialized CBOR map.

| Key | Name | Type | Description |
|-----|------|------|-------------|
| 1 | slots | array[uint] | Slot indices being claimed |
| 2 | superframe_epoch | uint | Superframe counter when claim issued |
| 3 | mode | uint | 0=interleaved, 1=contiguous |
| 4 | expiry | uint | Unix timestamp, claim expires after |
| 5 | gateway_iid | bstr(8) | Claiming gateway's IID |
| 6 | claim_seq | uint | Monotonic claim sequence |

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for COSE_Sign1:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(gateway_privkey, SHA256(CBOR(Sig_structure)))
```

Gateway's Ed25519 private key signs the canonical CBOR encoding of Sig_structure.

**Validation:**

On receiving slot claim POST:

1. Verify OSCORE protection (authenticates peer gateway)
2. Decode COSE_Sign1 structure
3. Extract `kid` from unprotected header; verify it matches a known gateway IID
4. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
5. Reconstruct Sig_structure per RFC 9052 and verify signature using peer's pubkey
6. Decode payload; verify `gateway_iid` matches `kid`
7. Verify `expiry` > now
8. Verify `claim_seq` > cached claim_seq for this gateway, or no cached entry
9. Check for conflicts with existing slot allocations (see below)
10. If no conflict or conflict resolved: cache claim, respond 2.04 Changed
11. If conflict unresolved: respond 4.09 Conflict with winning gateway's claim

On validation failure (signature invalid, expired, etc.), respond 4.03 Forbidden.
Claims with invalid or missing signatures MUST be silently discarded per GCP-6.3.

**Conflict Resolution Integration (GCP-6.3):**

When overlapping slot claims are received:

1. Both claims MUST have valid Schnorr48 signatures (invalid claims discarded)
2. Compare `gateway_iid` values: lowest IID wins
3. Losing gateway MUST select next available slots and issue new claim
4. Losing gateway MUST broadcast updated schedule to all peers

**claim_seq Persistence:**

The `claim_seq` counter MUST persist across gateway reboots. Implementations
MUST store `claim_seq` in non-volatile storage and increment atomically before
each claim. This prevents replay of stale claims after restart.

| Event | Behavior |
|-------|----------|
| Gateway boot | Load claim_seq from NVS; if missing, initialize to 0 |
| Before claim | Increment claim_seq; persist to NVS; then sign and send |
| Receive claim | Reject if claim_seq <= cached value for that gateway |

**Security Considerations:**

- claim_seq replay protection requires persistent storage
- Signature verification MUST complete before conflict resolution
- Rate limiting SHOULD apply to slot claim endpoints (see GCP-9)

## GCP-7. Node Handoff

When a node moves (detected via better parent/RSSI):

1. Node sends DAO to new Gateway B.
2. B sends POST /handoff to A (via backbone) with node details.
3. A releases node from its registry, sends confirmation.
4. B confirms handoff to node via CoAP.
5. Routes updated in RPL DODAG.

State transferred includes recent sequence numbers, security contexts if applicable.

### GCP-7.1. GCP Handoff COSE_Sign1

Gateway handoff uses two COSE_Sign1 messages to transfer node ownership and
link-layer replay state between gateways. Both messages use the Schnorr48-Ed25519
algorithm (-65537) registered in 06-security.md section 8.11.

**Handoff Request (new GW -> old GW):**

New gateway B sends handoff request to old gateway A via CoAP:

```
POST coap://[old-gw]/.well-known/lichen-gw/handoff
Content-Format: application/cose; cose-type="cose-sign1" (TBD)
OSCORE: <B-A pairwise context>

COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<new-gw-iid>'},   ; unprotected: {kid: new gateway 8-byte IID}
  h'<payload>',           ; see Request Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

**Request Payload Structure (CBOR map):**

| Key | Name     | Type         | Description                              |
|-----|----------|--------------|------------------------------------------|
| 1   | node     | bstr (8)     | Node IID being transferred               |
| 2   | old_gw   | bstr (8)     | Current owner gateway IID                |
| 3   | seq      | uint         | Handoff sequence number (monotonic)      |
| 4   | ts       | uint         | Unix timestamp of request                |
| 5   | expiry   | uint         | Request validity expiry (unix timestamp) |
| 6   | rssi     | int          | RSSI observed by new gateway (dBm)       |

```cbor
{
  1: h'<8-byte node IID>',
  2: h'<8-byte old gateway IID>',
  3: <uint>,              ; seq: handoff sequence, strictly increasing
  4: <unix timestamp>,    ; ts: request timestamp
  5: <unix timestamp>,    ; expiry: request validity window
  6: <int>                ; rssi: signal strength at new gateway
}
```

**Handoff Confirm (old GW -> new GW):**

Old gateway A confirms handoff and transfers replay state:

```
2.04 Changed
Content-Format: application/cose; cose-type="cose-sign1" (TBD)
OSCORE: <A-B pairwise context>

COSE_Sign1 = [
  h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
  {4: h'<old-gw-iid>'},   ; unprotected: {kid: old gateway 8-byte IID}
  h'<payload>',           ; see Confirm Payload below
  h'<48-byte signature>'  ; Schnorr48 signature
]
```

**Confirm Payload Structure (CBOR map):**

| Key | Name       | Type         | Description                              |
|-----|------------|--------------|------------------------------------------|
| 1   | node       | bstr (8)     | Node IID being transferred               |
| 2   | new_gw     | bstr (8)     | New owner gateway IID                    |
| 3   | seq        | uint         | Echoed handoff sequence number           |
| 4   | ts         | uint         | Confirmation timestamp                   |
| 5   | link_epoch | uint         | Node's link-layer epoch (8-bit)          |
| 6   | link_seq   | uint         | Node's link-layer sequence (16-bit)      |

```cbor
{
  1: h'<8-byte node IID>',
  2: h'<8-byte new gateway IID>',
  3: <uint>,              ; seq: echoed from request
  4: <unix timestamp>,    ; ts: confirmation timestamp
  5: <uint>,              ; link_epoch: node's current epoch
  6: <uint>               ; link_seq: node's last accepted seqnum
}
```

**Signature Computation (COSE_Sign1):**

Per RFC 9052, the Sig_structure for both messages:

```
Sig_structure = [
  "Signature1",           ; context string
  protected,              ; protected header bytes
  h'',                    ; external_aad (empty)
  payload                 ; payload bytes
]
sig = Schnorr48(gw_privkey, SHA256(CBOR(Sig_structure)))
```

The signing gateway's Ed25519 private key signs the canonical CBOR encoding.

**Validation (Handoff Request):**

Old gateway A validates incoming request:

1. Verify OSCORE protection (authenticates new gateway B)
2. Decode COSE_Sign1 structure
3. Extract `kid` from unprotected header; verify it is a known federation peer
4. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
5. Reconstruct Sig_structure per RFC 9052 and verify signature using B's pubkey
6. Decode payload; verify `old_gw` matches own IID
7. Verify `node` is currently owned by this gateway
8. Verify `expiry` > now
9. Verify `seq` > last handoff seq for this node (prevents replay)
10. If valid: release node, respond with confirm message
11. If invalid: respond 4.03 Forbidden

**Validation (Handoff Confirm):**

New gateway B validates incoming confirm:

1. Verify OSCORE protection (authenticates old gateway A)
2. Decode COSE_Sign1 structure
3. Extract `kid` from unprotected header; verify matches expected old gateway
4. Verify algorithm in protected header is -65537 (Schnorr48-Ed25519)
5. Reconstruct Sig_structure per RFC 9052 and verify signature using A's pubkey
6. Decode payload; verify `new_gw` matches own IID
7. Verify `seq` matches the request sequence number
8. Initialize node's replay window with (link_epoch, link_seq)
9. Add node to local registry; confirm handoff to node via CoAP

**Link-Layer Replay State Transfer:**

The `link_epoch` and `link_seq` fields transfer the node's current replay
position. The new gateway MUST:

- Initialize replay window floor at (link_epoch, link_seq)
- Accept only frames with epoch > link_epoch, or epoch == link_epoch AND seq > link_seq
- This prevents replay of frames the old gateway already accepted

**Security Considerations:**

| Threat                  | Mitigation                                        |
|-------------------------|---------------------------------------------------|
| Forged handoff request  | OSCORE + COSE signature verify sender identity    |
| Replay of old request   | Monotonic seq per-node; expiry window             |
| Replay window gap       | Explicit state transfer; no window reset          |
| Rogue gateway injection | Federation membership required (PSK or TOFU)      |

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

