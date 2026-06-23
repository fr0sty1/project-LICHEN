# LICHEN Over-the-Air Firmware Update

```
Internet-Draft                                              LICHEN Project
draft-lichen-ota-00                                             June 2026
Intended status: Experimental
Expires: December 2026
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft. It will be updated as implementation
experience is gained.

## Abstract

This document specifies how LICHEN nodes receive firmware updates over the
LoRa mesh. Firmware images are transferred via CoAP block-wise transfer
(RFC 7959) in segments, verified with a SHA-256 hash and an Ed25519
signature, and applied by the bootloader. The mechanism is designed for
severely constrained links (50-250 byte payloads, multi-minute transfer
times) and does not require a persistent connection.

## 1. Introduction

Field-deployed LICHEN nodes need a way to receive firmware updates without
physical access. The LoRa radio link imposes hard constraints:

- **MTU:** 50–250 bytes per frame after SCHC compression and link overhead.
- **Data rate:** 300 bps – 27 kbps depending on spreading factor.
- **Battery:** Nodes may sleep between transfers; transfers must be resumable.
- **Security:** Firmware MUST be authenticated; unauthenticated images MUST
  be rejected.

LICHEN OTA is built on:
- **CoAP block-wise transfer (RFC 7959):** Segmented, resumable transfer.
- **Ed25519 signatures:** Authenticate the firmware image manifest.
- **SHA-256 hash:** Verify image integrity after all blocks arrive.
- **CoAP observe (RFC 7641):** Nodes subscribe to update announcements.

### 1.1. Design Goals

- **Resumable:** A node that sleeps during transfer can restart from the last
  verified block.
- **Authenticated:** No image without a valid Ed25519 signature from a trusted
  key is applied.
- **Space-efficient:** Nodes SHOULD support dual-bank flash for atomic updates,
  but MUST at minimum support single-bank via a small bootloader stub.
- **Mesh-friendly:** A node that has already applied an update can serve it to
  peers (mesh distribution), reducing gateway load.

### 1.2. Out of Scope

- Key distribution and revocation (handled by the LICHEN security layer).
- Bootloader implementation details (MCU-specific).
- Partial application (applying only changed pages, a.k.a. delta OTA) is a
  future extension.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Border router (BR):** The gateway node with upstream IP connectivity that
  initiates firmware distribution.
- **Image:** A complete firmware binary for a specific board target.
- **Manifest:** A small metadata record describing an image (version, hash,
  signature, block count).
- **Initiator:** The node or server that holds the firmware image and serves it.
- **Target:** A node that needs to apply a firmware update.

## 3. Resources

The update mechanism uses two CoAP resources:

### 3.1. /ota/manifest (GET, OBSERVE)

Returns the current manifest for the latest available firmware image.

Targets OBSERVE this resource to learn when a new version is available.

Payload (CBOR map):

| Key | Type | Description |
|-----|------|-------------|
| `v` | uint | Firmware version number (monotonically increasing) |
| `board` | tstr | Board identifier string, e.g. `"rak4631_nrf52840"` |
| `size` | uint | Total image size in bytes |
| `blocks` | uint | Number of blocks (block size fixed at 64 bytes for LoRa) |
| `sha256` | bstr | SHA-256 hash of the complete image (32 bytes) |
| `sig` | bstr | Ed25519 signature over `sha256 \|\| version \|\| board` (64 bytes) |

A node MUST verify the signature against the provisioned firmware signing key
before beginning block transfer. A manifest with an invalid signature MUST
be discarded.

### 3.2. /ota/image (GET with Block2)

Returns the firmware image in 64-byte blocks using CoAP block-wise transfer
(RFC 7959 Block2 option).

Block size is fixed at 64 bytes (SZX=6) to fit within SCHC-compressed LoRa
frames. The total number of blocks is given by `manifest.blocks`.

A target requests blocks sequentially:

```
→  GET /ota/image, Block2: NUM=0, SZX=6
←  2.05 Content, Block2: NUM=0, M=1, SZX=6, <64 bytes>

→  GET /ota/image, Block2: NUM=1, SZX=6
←  2.05 Content, Block2: NUM=1, M=1, SZX=6, <64 bytes>

... (repeat for all blocks)

→  GET /ota/image, Block2: NUM=N-1, SZX=6
←  2.05 Content, Block2: NUM=N-1, M=0, SZX=6, <final bytes>
```

The `M` (More) bit in the Block2 option is 0 in the last block.

Targets SHOULD persist the last completed block number to non-volatile
storage so that transfer can resume after a reset.

## 4. Update Flow

### 4.1. Discovery

1. The border router (or a designated distributor) publishes a new manifest
   at `/ota/manifest`.
2. Nodes observing `/ota/manifest` receive a CoAP notification with the new
   manifest payload.
3. Each node checks:
   a. Is `manifest.board` my board? If not, discard.
   b. Is `manifest.v` > my current firmware version? If not, discard.
   c. Is `manifest.sig` valid under the provisioned signing key? If not, discard.
4. Nodes that pass all checks enter `UPDATE_PENDING` state.

### 4.2. Block Transfer

5. The target begins block transfer from `/ota/image` starting at block 0
   (or the last saved block if resuming).
6. Blocks are written to a secondary flash partition (dual-bank) or a
   download staging area.
7. After all blocks are received:
   a. Compute SHA-256 of the complete received image.
   b. Compare against `manifest.sha256`. If mismatch, discard and restart.
8. Write the manifest version and hash to a dedicated metadata page in flash.

### 4.3. Application

9. The target signals the bootloader to apply the pending image (e.g., by
   writing a flag to a known flash address or calling a bootloader API).
10. The target reboots.
11. The bootloader verifies the image hash, then flashes it (single-bank) or
    swaps banks (dual-bank) and boots.
12. On successful boot, the new firmware confirms the update by writing its
    own version number to the metadata page. If the new firmware fails to
    confirm within a watchdog period, the bootloader rolls back.

### 4.4. Mesh Distribution

A node that has successfully applied a firmware version MAY serve it to
peers by:
1. Advertising the manifest at its own `/ota/manifest` resource.
2. Serving blocks from its secondary flash partition (which still holds the
   applied image).

This reduces reliance on the border router for multi-hop meshes.

## 5. Timing and Rate Control

LoRa duty-cycle regulations (e.g., 1% in the EU 868 MHz band) impose hard
limits on transmission time. A 512 KB firmware image at 64 bytes/block is
8192 blocks. At LoRa SF10/125 kHz, a 64-byte block takes approximately 330 ms
of airtime. With 1% duty cycle:

- Maximum transmission rate: ~1 block every 33 seconds.
- Total transfer time: ~75 hours at maximum duty cycle.

In practice, OTA SHOULD be performed at night or during low-activity periods.
The CoAP No-Response option (RFC 7967) SHOULD be used for intermediate blocks
to suppress ACKs and halve the airtime.

For SF7 targets (short range, higher bandwidth), transfer time is approximately
2 hours.

Initiators MUST respect duty cycle. Targets MAY throttle requests via the
CoAP `Max-Age` option.

## 6. Block-Size Negotiation

The fixed 64-byte block size (SZX=6) is the default. If the target has
confirmed larger MTU availability (e.g., a native_sim build with no airtime
constraint), the target MAY request SZX=10 (1024 bytes) in the Block2 option.
The initiator MUST respond with the block size it can serve; the target adapts.

## 7. Security Considerations

### 7.1. Manifest Signature

The Ed25519 signature covers `sha256 || version || board` (concatenated, no
length prefix). The signing key is the firmware signing key, provisioned
separately from the node's link key. Nodes MUST NOT accept firmware signed
with a link key.

### 7.2. Rollback Attack

A version number MUST be strictly monotonically increasing. Nodes MUST reject
manifests with `v` <= current firmware version. This prevents a downgrade
attack.

### 7.3. Partition Isolation

During block transfer, image data MUST be written to a separate flash
partition from the running firmware. The bootloader MUST verify the hash
before overwriting the active partition. A power loss during flashing MUST
leave the running firmware intact.

### 7.4. Unsigned Image Rejection

A node that has been provisioned with a firmware signing key MUST NOT boot
an unsigned image after initial provisioning. The bootloader checks the
metadata page; if the page is present and valid, unsigned images are rejected.

## 8. IANA Considerations

This document registers no new CoAP option numbers or CBOR tags. All CoAP
resources are in the vendor namespace (`/ota/`).

## 9. References

- RFC 7252: The Constrained Application Protocol (CoAP)
- RFC 7959: Block-Wise Transfers in CoAP
- RFC 7641: Observing Resources in CoAP
- RFC 7967: CoAP No-Response Option
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- [draft-lichen-schnorr-00]: Schnorr Signatures with Truncated Challenge

## Authors

LICHEN Project
