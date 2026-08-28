# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GCP-6 Slot Claim oracle (spec 08-gateway-coordination.md Section 6).

Implements slot claim message handling for gateway-to-gateway coordination:
- Slot claim creation and validation
- CBOR canonical encoding for signatures
- Schnorr48 signature verification (SECURITY requirement)
- Conflict resolution (lowest IID wins)
- Interleaved and contiguous allocation modes

Per GCP-6.3:
- Gateways MUST verify Schnorr signature on any slot-claim message
- Claims with invalid or missing signatures MUST be silently discarded
- Overlapping claims where both signatures verify: lowest IID wins
- Overlapping claims where one signature fails: valid claim wins

All implementations MUST match test vectors in:
- test/vectors/gcp_slot_claim.json
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

import cbor2

from lichen.crypto import schnorr48

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "AllocationMode",
    "ClaimError",
    "ClaimRejectReason",
    "SlotClaim",
    "compute_contiguous_slots",
    "compute_interleaved_slots",
    "encode_claim_canonical",
    "resolve_slot_conflict",
    "validate_interleaved_pattern",
    "verify_slot_claim",
]


class ClaimRejectReason(Enum):
    """Reasons a slot claim may be rejected (GCP-6.3)."""

    MISSING_SIGNATURE = auto()  # No signature provided
    INVALID_SIGNATURE = auto()  # Signature failed verification
    INVALID_CLAIM_DATA = auto()  # Malformed claim structure
    SLOT_CONFLICT = auto()  # Overlapping slots, lower IID wins


class AllocationMode(Enum):
    """Slot allocation mode (GCP-6.2)."""

    INTERLEAVED = auto()  # Gateway N owns slots N, N+G, N+2G...
    CONTIGUOUS = auto()  # Gateway owns sequential block of slots


class ClaimError(Exception):
    """Slot claim processing error."""


@dataclass(frozen=True)
class SlotClaim:
    """Slot claim message for POST /.well-known/lichen-gw/slots.

    Per GCP-6.2, gateways claim slots via POST to /slots on peer gateways.
    The claim MUST be signed with the gateway's Ed25519 key (Schnorr48).

    Wire format: CBOR map with deterministic encoding (RFC 8949 Section 4.2)
    for consistent signature computation.

    Attributes:
        gateway_iid: 8-byte gateway Interface Identifier (hex string)
        slots: List of slot indices being claimed (sorted ascending)
        superframe_id: Current superframe number
        timestamp: Optional Unix timestamp of claim (for replay protection)
        gateway_count: Total gateways in federation (for interleaved mode)
        ordinal: This gateway's ordinal position (for interleaved mode)
        signature: 48-byte Schnorr signature (hex string or bytes)
    """

    gateway_iid: str  # Hex string, 16 chars (8 bytes)
    slots: tuple[int, ...]  # Immutable, sorted ascending
    superframe_id: int

    # Optional fields
    timestamp: int | None = None
    gateway_count: int | None = None
    ordinal: int | None = None
    signature: bytes | None = None

    def __post_init__(self) -> None:
        """Validate claim structure."""
        # Validate gateway_iid is 8 bytes (16 hex chars)
        if len(self.gateway_iid) != 16:
            raise ClaimError(f"gateway_iid must be 16 hex chars, got {len(self.gateway_iid)}")
        try:
            bytes.fromhex(self.gateway_iid)
        except ValueError as e:
            raise ClaimError(f"gateway_iid must be valid hex: {e}") from None

        # Slots must be sorted ascending
        if list(self.slots) != sorted(self.slots):
            raise ClaimError("slots must be sorted ascending")

        # Slots must be unique
        if len(self.slots) != len(set(self.slots)):
            raise ClaimError("slots must be unique")

        # Superframe ID must be non-negative
        if self.superframe_id < 0:
            raise ClaimError("superframe_id must be non-negative")

        # Validate signature length if present
        if self.signature is not None and len(self.signature) != 48:
            raise ClaimError(f"signature must be 48 bytes, got {len(self.signature)}")

    def iid_as_int(self) -> int:
        """Return gateway IID as unsigned big-endian integer for comparison."""
        return int.from_bytes(bytes.fromhex(self.gateway_iid), "big")

    def to_cbor_map(self) -> dict[str, object]:
        """Convert to CBOR map for encoding (excludes signature)."""
        result: dict[str, object] = {
            "gateway_iid": bytes.fromhex(self.gateway_iid),
            "slots": list(self.slots),
            "superframe_id": self.superframe_id,
        }
        if self.timestamp is not None:
            result["timestamp"] = self.timestamp
        if self.gateway_count is not None:
            result["gateway_count"] = self.gateway_count
        if self.ordinal is not None:
            result["ordinal"] = self.ordinal
        return result

    @classmethod
    def from_cbor(cls, payload: bytes) -> SlotClaim:
        """Decode from CBOR payload.

        Args:
            payload: CBOR-encoded claim (may include signature field)

        Returns:
            SlotClaim instance

        Raises:
            ClaimError: If payload is malformed
        """
        try:
            data = cbor2.loads(payload)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise ClaimError(f"invalid CBOR: {e}") from None

        if not isinstance(data, dict):
            raise ClaimError("expected CBOR map")

        try:
            iid_bytes = data["gateway_iid"]
            if not isinstance(iid_bytes, bytes):
                raise ClaimError("gateway_iid must be bytes in CBOR")
            gateway_iid = iid_bytes.hex()

            raw_slots = data["slots"]
            if not all(isinstance(s, int) for s in raw_slots):
                raise ClaimError("slots must all be integers")
            slots = tuple(raw_slots)
            superframe_id = int(data["superframe_id"])

            signature = data.get("signature")
            if signature is not None and isinstance(signature, str):
                signature = bytes.fromhex(signature)
            if signature is not None and not isinstance(signature, bytes):
                raise ClaimError("signature must be bytes or hex string")

            return cls(
                gateway_iid=gateway_iid,
                slots=slots,
                superframe_id=superframe_id,
                timestamp=data.get("timestamp"),
                gateway_count=data.get("gateway_count"),
                ordinal=data.get("ordinal"),
                signature=signature,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise ClaimError(f"malformed claim: {e}") from None


def encode_claim_canonical(claim: SlotClaim) -> bytes:
    """Encode claim in CBOR deterministic format for signing.

    Per RFC 8949 Section 4.2.1, deterministic encoding requires:
    - Map keys sorted by byte-wise lexicographic order
    - Shortest integer encoding
    - No indefinite-length items

    Per GCP-6.2, the signature covers the canonical CBOR encoding of
    the claim data (excluding the signature field itself).

    Args:
        claim: SlotClaim to encode

    Returns:
        Deterministically encoded CBOR bytes
    """
    # cbor2 with canonical=True produces RFC 8949 Section 4.2 format
    return cbor2.dumps(claim.to_cbor_map(), canonical=True)


def verify_slot_claim(
    claim: SlotClaim,
    gateway_pubkey: bytes,
) -> tuple[bool, ClaimRejectReason | None]:
    """Verify Schnorr48 signature on slot claim.

    Per GCP-6.3:
    - Gateways MUST verify the Schnorr signature on any slot-claim message
    - Claims with invalid or missing signatures MUST be silently discarded

    SECURITY: This function MUST be called before accepting any slot claim
    from another gateway. Unsigned claims can enable slot hijacking attacks.

    Args:
        claim: SlotClaim to verify
        gateway_pubkey: 32-byte Ed25519 public key of claiming gateway

    Returns:
        Tuple of (is_valid, rejection_reason or None)
    """
    if claim.signature is None:
        return (False, ClaimRejectReason.MISSING_SIGNATURE)

    if len(claim.signature) != 48:
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    if len(gateway_pubkey) != 32:
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    # Compute canonical encoding for signature verification
    signed_data = encode_claim_canonical(claim)

    # Verify Schnorr48 signature
    if not schnorr48.verify(gateway_pubkey, signed_data, claim.signature):
        return (False, ClaimRejectReason.INVALID_SIGNATURE)

    return (True, None)


def resolve_slot_conflict(
    claim_a: SlotClaim,
    claim_b: SlotClaim,
    pubkey_a: bytes | None = None,
    pubkey_b: bytes | None = None,
) -> tuple[SlotClaim, SlotClaim]:
    """Resolve conflict when two gateways claim overlapping slots.

    Per GCP-6.3:
    - If two gateways claim overlapping slot: lowest IID MUST win
    - Loser MUST select next available slot and re-claim
    - Overlapping claims where both signatures verify: lowest IID wins
    - Overlapping claims where one signature fails and other succeeds:
      valid claim wins

    Args:
        claim_a: First slot claim
        claim_b: Second slot claim
        pubkey_a: Public key for claim_a (required if signature present)
        pubkey_b: Public key for claim_b (required if signature present)

    Returns:
        Tuple of (winner, loser) claims

    Raises:
        ClaimError: If no overlapping slots or both claims invalid
    """
    # Check for overlap
    slots_a = set(claim_a.slots)
    slots_b = set(claim_b.slots)
    overlap = slots_a & slots_b

    if not overlap:
        raise ClaimError("no overlapping slots to resolve")

    # Verify signatures
    a_valid = pubkey_a is not None and verify_slot_claim(claim_a, pubkey_a)[0]
    b_valid = pubkey_b is not None and verify_slot_claim(claim_b, pubkey_b)[0]

    # Case 1: Both invalid - cannot resolve
    if not a_valid and not b_valid:
        raise ClaimError("both claims have invalid signatures, cannot resolve")

    # Case 2: One valid, one invalid - valid wins
    if a_valid and not b_valid:
        return (claim_a, claim_b)
    if b_valid and not a_valid:
        return (claim_b, claim_a)

    # Case 3: Both valid - lowest IID wins
    iid_a = claim_a.iid_as_int()
    iid_b = claim_b.iid_as_int()

    if iid_a < iid_b:
        return (claim_a, claim_b)
    elif iid_b < iid_a:
        return (claim_b, claim_a)
    else:
        # Same IID - should not happen in practice (same gateway)
        raise ClaimError("claims have identical gateway IID")


def compute_interleaved_slots(
    ordinal: int,
    gateway_count: int,
    max_slots: int,
) -> list[int]:
    """Compute slot indices for interleaved allocation mode.

    Per GCP-6.2:
    - Gateway with ordinal N owns slots N, N+G, N+2G...
    - Where G = gateway_count

    Args:
        ordinal: This gateway's position (0-indexed)
        gateway_count: Total number of gateways
        max_slots: Maximum slot index (exclusive)

    Returns:
        Sorted list of owned slot indices

    Raises:
        ClaimError: If ordinal >= gateway_count
    """
    if ordinal < 0:
        raise ClaimError(f"ordinal must be non-negative: {ordinal}")
    if gateway_count < 1:
        raise ClaimError(f"gateway_count must be >= 1: {gateway_count}")
    if ordinal >= gateway_count:
        raise ClaimError(f"ordinal {ordinal} >= gateway_count {gateway_count}")
    if max_slots < 1:
        raise ClaimError(f"max_slots must be >= 1: {max_slots}")

    return list(range(ordinal, max_slots, gateway_count))


def compute_contiguous_slots(
    start_slot: int,
    slot_count: int,
    max_slots: int,
) -> list[int]:
    """Compute slot indices for contiguous allocation mode.

    Per GCP-6.2:
    - Gateway owns sequential block of slots

    Args:
        start_slot: First slot index (inclusive)
        slot_count: Number of slots to claim
        max_slots: Maximum slot index (exclusive)

    Returns:
        Sorted list of owned slot indices

    Raises:
        ClaimError: If allocation exceeds max_slots
    """
    if start_slot < 0:
        raise ClaimError(f"start_slot must be non-negative: {start_slot}")
    if slot_count < 0:
        raise ClaimError(f"slot_count must be non-negative: {slot_count}")
    if max_slots < 1:
        raise ClaimError(f"max_slots must be >= 1: {max_slots}")
    if start_slot + slot_count > max_slots:
        raise ClaimError(
            f"contiguous block [{start_slot}, {start_slot + slot_count}) "
            f"exceeds max_slots {max_slots}"
        )

    return list(range(start_slot, start_slot + slot_count))


def validate_interleaved_pattern(
    slots: Sequence[int],
    ordinal: int,
    gateway_count: int,
) -> bool:
    """Validate that slots follow interleaved allocation pattern.

    Per test vectors, interleaved pattern requires:
        slots[i] == ordinal + i * gateway_count

    Args:
        slots: List of claimed slot indices
        ordinal: Gateway's ordinal position
        gateway_count: Total number of gateways

    Returns:
        True if pattern is valid, False otherwise
    """
    if not slots:
        return True  # Empty claim is trivially valid

    if gateway_count < 1:
        return False

    if ordinal < 0 or ordinal >= gateway_count:
        return False

    for i, slot in enumerate(slots):
        expected = ordinal + i * gateway_count
        if slot != expected:
            return False

    return True


def sign_slot_claim(
    claim: SlotClaim,
    privkey: bytes,
    pubkey: bytes,
) -> SlotClaim:
    """Sign a slot claim with Schnorr48.

    Args:
        claim: SlotClaim to sign (signature field ignored)
        privkey: 32-byte Ed25519 private key (clamped)
        pubkey: 32-byte Ed25519 public key

    Returns:
        New SlotClaim with signature field populated
    """
    signed_data = encode_claim_canonical(claim)
    signature = schnorr48.sign(privkey, pubkey, signed_data)

    # Create new claim with signature
    # Using object.__setattr__ because dataclass is frozen
    new_claim = SlotClaim(
        gateway_iid=claim.gateway_iid,
        slots=claim.slots,
        superframe_id=claim.superframe_id,
        timestamp=claim.timestamp,
        gateway_count=claim.gateway_count,
        ordinal=claim.ordinal,
        signature=signature,
    )
    return new_claim
