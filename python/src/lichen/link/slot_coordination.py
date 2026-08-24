# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Slot Coordination oracle (spec 02a-coordinated-capacity.md).

Implements GCP-6 Slot Coordination:
- Superframe synchronization (SFN)
- Slot assignment (hash-derived, interleaved/contiguous)
- Slot map validation
- Multi-root beacon conflict resolution (lowest IID wins)
- TX allowed checks

All implementations MUST match test vectors in:
- test/vectors/ccp_tdma.json
- test/vectors/ccp_sfn_wrap_slot_hash.json
- test/vectors/ccp_slot_map_validation.json
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, NamedTuple

# Re-export core slot/SFN functions from timing.sfn
from lichen.timing.sfn import hash_32, sfn_delta, slot_for

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "HOLDOFF_SUPERFRAMES",
    "MAX_CANDIDATES",
    "MultiRootState",
    "RootCandidate",
    "SlotMapError",
    "VersionChangeOutcome",
    "compare_iid",
    "hash_32",
    "select_root",
    "sfn_delta",
    "slot_for",
    "tx_allowed",
    "validate_slot_map",
]


# Holdoff period for root transition (spec 2a.5.3)
HOLDOFF_SUPERFRAMES: int = 3

#: Maximum number of root candidates per beacon window (memory-exhaustion DoS
#: guard; mirrors Rust ``MAX_CANDIDATES`` in rust/lichen-rpl/src/multi_instance.rs).
MAX_CANDIDATES: int = 32


class SlotMapError(Enum):
    """Slot map validation error types per spec 02a-coordinated-capacity.md:80."""

    SLOT_OUT_OF_BOUNDS = auto()  # Entry >= num_slots
    UNSORTED = auto()  # Array not sorted ascending
    DUPLICATE = auto()  # Duplicate slot entries


def validate_slot_map(
    slot_map: Sequence[int],
    num_slots: int,
) -> tuple[bool, SlotMapError | None]:
    """Validate a slot_map array per CCP spec.

    Per spec 02a-coordinated-capacity.md:80:
    - slot_map is a CBOR array of u8 in beacon cbor_options
    - Each entry MUST be < num_slots
    - Array MUST be sorted ascending
    - Duplicates are rejected (sorted-unique invariant)
    - Empty array is valid (no TX slots assigned)

    Args:
        slot_map: List of u8 slot indices.
        num_slots: Maximum number of slots (entries must be < num_slots).

    Returns:
        Tuple of (is_valid, error_type or None).
    """
    if not slot_map:
        return (True, None)

    prev = -1
    for slot in slot_map:
        if slot >= num_slots:
            return (False, SlotMapError.SLOT_OUT_OF_BOUNDS)
        if slot < prev:
            return (False, SlotMapError.UNSORTED)
        if slot == prev:
            return (False, SlotMapError.DUPLICATE)
        prev = slot

    return (True, None)


def tx_allowed(
    slot_map: Sequence[int],
    current_slot: int,
    num_slots: int,
) -> bool:
    """Check if transmission is allowed in the current slot.

    Per spec 02a-coordinated-capacity.md:80,117:
    - Joiners MUST adopt the assigned slot_map
    - Joiners MUST NOT transmit outside their assigned slots
    - A node MUST only transmit in its assigned slot

    Args:
        slot_map: Sorted list of assigned slot indices.
        current_slot: Current slot index (0 to num_slots-1).
        num_slots: Total number of slots per superframe.

    Returns:
        True if current_slot is in slot_map (transmission allowed).
    """
    if current_slot < 0 or current_slot >= num_slots:
        return False
    return current_slot in slot_map


@dataclass(order=True)
class RootCandidate:
    """Candidate root for multi-root conflict resolution.

    Per spec 02a-coordinated-capacity.md section 2a.5.2, selection criteria
    in order of precedence:
    1. RPL DODAG Preference (lower = less preferred, so higher wins)
    2. Stratum (lower wins)
    3. RSSI+SNR (higher wins, RSSI weighted 2:1 over SNR)
    4. EUI-64 tiebreak (numerically smaller IID wins)

    The order_key is computed for sorting: lower order_key = better candidate.
    """

    # Fields used for sorting (in order of precedence)
    dodag_preference: int = field(compare=True)  # Inverted: -preference for sorting
    stratum: int = field(compare=True)
    neg_rssi_snr: float = field(compare=True)  # Negated for sorting
    iid: int = field(compare=True)  # Lower wins

    # Non-sorting fields
    eui64: bytes = field(compare=False)
    rssi_ema: float = field(default=0.0, compare=False)
    snr_ema: float = field(default=0.0, compare=False)
    # SECURITY: defaults to False (fail-closed, mirroring Rust RootCandidate::new).
    # Set True ONLY after successful Schnorr48 signature verification; an
    # unverified beacon must never be selectable as root (spec 2a.5.1).
    signature_valid: bool = field(default=False, compare=False)

    @classmethod
    def from_beacon(
        cls,
        eui64: bytes,
        dodag_preference: int = 0,
        stratum: int = 255,
        rssi_ema: float = -120.0,
        snr_ema: float = -20.0,
        signature_valid: bool = False,
    ) -> RootCandidate:
        """Create a RootCandidate from beacon parameters.

        SECURITY: ``signature_valid`` defaults to False (fail-closed,
        mirroring Rust ``RootCandidate::new``). Pass True only AFTER
        successful Schnorr48 signature verification of the beacon.

        Args:
            eui64: Root's EUI-64 (8 bytes).
            dodag_preference: RPL DODAG Preference (lower = less preferred).
            stratum: Time-provider stratum (0=GNSS, 1=NTP, higher=worse).
            rssi_ema: EMA-smoothed RSSI in dBm.
            snr_ema: EMA-smoothed SNR in dB.
            signature_valid: Whether Schnorr48 signature verified. Defaults
                to False; set True only after verification succeeds.

        Returns:
            RootCandidate instance ready for comparison.
        """
        if len(eui64) != 8:
            raise ValueError("eui64 must be 8 bytes")

        # Extract IID (last 8 bytes of link-local address = EUI-64)
        # Compared as unsigned big-endian integer
        iid = int.from_bytes(eui64, "big")

        # Combined RSSI+SNR score (RSSI weighted 2:1 over SNR)
        combined_score = 2.0 * rssi_ema + snr_ema

        return cls(
            # For sorting: negate dodag_preference (higher preference = lower key = better)
            dodag_preference=-dodag_preference,
            stratum=stratum,
            # Negate combined score (higher score = better, but we want lower key)
            neg_rssi_snr=-combined_score,
            iid=iid,
            eui64=eui64,
            rssi_ema=rssi_ema,
            snr_ema=snr_ema,
            signature_valid=signature_valid,
        )


def compare_iid(eui64_a: bytes, eui64_b: bytes) -> int:
    """Compare two EUI-64 IIDs for tiebreak ordering.

    Per spec 2a.5.2, the node MUST select the root with the numerically
    smaller link-local IID (last 8 bytes of EUI-64, compared as unsigned
    big-endian integers).

    Args:
        eui64_a: First EUI-64 (8 bytes).
        eui64_b: Second EUI-64 (8 bytes).

    Returns:
        -1 if a < b (a wins), 0 if equal, +1 if a > b (b wins).
    """
    if len(eui64_a) != 8 or len(eui64_b) != 8:
        raise ValueError("both eui64 must be 8 bytes")

    iid_a = int.from_bytes(eui64_a, "big")
    iid_b = int.from_bytes(eui64_b, "big")

    if iid_a < iid_b:
        return -1
    elif iid_a > iid_b:
        return 1
    return 0


def select_root(candidates: Sequence[RootCandidate]) -> RootCandidate | None:
    """Select the best root from multiple candidates.

    Per spec 02a-coordinated-capacity.md section 2a.5:
    1. Discard candidates with invalid signatures (2a.5.1)
    2. Apply selection criteria in order (2a.5.2):
       - RPL DODAG Preference (higher wins)
       - Stratum (lower wins)
       - RSSI+SNR (higher wins, RSSI weighted 2:1)
       - EUI-64 tiebreak (lower IID wins)

    Args:
        candidates: List of RootCandidate instances.

    Returns:
        Best candidate, or None if all candidates have invalid signatures
        or the list is empty.
    """
    # Filter to valid signatures only (2a.5.1)
    valid = [c for c in candidates if c.signature_valid]
    if not valid:
        return None

    # RootCandidate is ordered by our sorting fields, so min() gives best
    return min(valid)


class VersionChangeOutcome(Enum):
    """Outcome of an RPL version change during multi-root conflict.

    Per spec 02a-coordinated-capacity.md section 2a.5.4.
    """

    # Version accepted, SFN reset, continue with current root
    ACCEPTED = auto()
    # Version accepted during holdoff, holdoff counter reset
    HOLDOFF_RESET = auto()
    # Signature verification failed on new version, root discarded
    SIG_FAILED_DISCARD = auto()
    # No version change (same version or not in conflict state)
    NO_CHANGE = auto()


class VersionChangeResult(NamedTuple):
    """Result of processing an RPL version change during multi-root conflict."""

    outcome: VersionChangeOutcome
    new_version: int
    sfn_reset: bool
    holdoff_reset: bool
    evaluate_candidates: bool


@dataclass
class MultiRootState:
    """State machine for multi-root beacon conflict resolution.

    Per spec 02a-coordinated-capacity.md section 2a.5:
    - 2a.5.1: Signature verification gate
    - 2a.5.2: Root selection criteria
    - 2a.5.3: Overlap resolution with holdoff
    - 2a.5.4: RPL version change during multi-root conflict

    This class tracks the current root, candidate roots, holdoff state,
    and handles version changes during conflicts.
    """

    # Current root (None if not synced)
    current_root: RootCandidate | None = None
    # Current RPL DODAG version
    current_version: int = 0
    # Candidates received in current beacon window
    candidates: list[RootCandidate] = field(default_factory=list)
    # Selected root during holdoff transition (may differ from current_root)
    holdoff_selected: RootCandidate | None = None
    # Holdoff counter (0 = not in holdoff, 1-3 = superframes remaining)
    holdoff_counter: int = 0
    # Desync state that depends on prior version (reset on version change)
    desync_state_version: int | None = None

    def add_candidate(self, candidate: RootCandidate) -> bool:
        """Add a candidate root from a received beacon.

        Per 2a.5.1: Only candidates with valid signatures are retained.

        SECURITY: Enforces MAX_CANDIDATES limit to prevent memory exhaustion
        DoS (mirrors Rust ``MultiRootState::add_candidate``). Returns True if
        the candidate was added, False if the limit was reached or the
        signature was invalid.
        """
        if not candidate.signature_valid:
            return False
        if len(self.candidates) >= MAX_CANDIDATES:
            return False
        self.candidates.append(candidate)
        return True

    def clear_candidates(self) -> None:
        """Clear candidate list after beacon window processing."""
        self.candidates.clear()

    def is_in_holdoff(self) -> bool:
        """Return True if in holdoff transition period."""
        return self.holdoff_counter > 0

    def process_beacon_window(self) -> RootCandidate | None:
        """Process overlapping beacons per 2a.5.3.

        Returns the selected root, or None if no valid candidates.
        Initiates holdoff if selected root differs from current root.
        """
        selected = select_root(self.candidates)
        if selected is None:
            return None

        # Check if selected root differs from current root
        if self.current_root is not None and selected.eui64 != self.current_root.eui64:
            # Per 2a.5.3: defer transition for 3 superframes
            if not self.is_in_holdoff():
                self.holdoff_selected = selected
                self.holdoff_counter = HOLDOFF_SUPERFRAMES
        elif not self.is_in_holdoff():
            # Same root or first sync - no holdoff needed
            self.current_root = selected

        return selected

    def advance_holdoff(self) -> bool:
        """Advance holdoff counter by one superframe.

        Returns True if holdoff completed and transition should occur.
        Per 2a.5.3: "If the new root remains preferred across the entire
        hold-off, the node MUST initiate desync and rejoin."
        """
        if not self.is_in_holdoff():
            return False

        self.holdoff_counter -= 1
        if self.holdoff_counter == 0:
            # Holdoff complete - transition to new root
            if self.holdoff_selected is not None:
                self.current_root = self.holdoff_selected
                self.holdoff_selected = None
            return True
        return False

    def on_version_change(
        self,
        new_version: int,
        signature_valid: bool,
        new_epoch: int | None = None,
    ) -> VersionChangeResult:
        """Handle RPL DODAG version change per spec 2a.5.4.

        Args:
            new_version: The new DODAG version number from DIO/beacon.
            signature_valid: Whether the beacon signature verified.
            new_epoch: Optional new epoch for SFN reset.

        Returns:
            VersionChangeResult indicating outcome and required actions.
        """
        # No change if same version
        if new_version == self.current_version:
            return VersionChangeResult(
                outcome=VersionChangeOutcome.NO_CHANGE,
                new_version=new_version,
                sfn_reset=False,
                holdoff_reset=False,
                evaluate_candidates=False,
            )

        # Per 2a.5.4: Re-verify signature upon first beacon with new version
        if not signature_valid:
            # Signature verification failed for new version
            # Discard current root and evaluate remaining candidates
            if self.is_in_holdoff():
                # During holdoff: immediately evaluate remaining candidates
                self.holdoff_counter = 0
                self.holdoff_selected = None
            self.current_root = None
            return VersionChangeResult(
                outcome=VersionChangeOutcome.SIG_FAILED_DISCARD,
                new_version=new_version,
                sfn_reset=False,
                holdoff_reset=False,
                evaluate_candidates=True,
            )

        # Per 2a.5.4 step 1: Accept the new DODAG Version
        old_version = self.current_version
        self.current_version = new_version

        # Per 2a.5.4 step 2: Reset any desync state that depended on prior version
        if self.desync_state_version == old_version:
            self.desync_state_version = None

        # Per 2a.5.4: During holdoff, version change resets holdoff counter
        if self.is_in_holdoff():
            # Reset holdoff counter to zero and restart 3-superframe period
            self.holdoff_counter = HOLDOFF_SUPERFRAMES
            return VersionChangeResult(
                outcome=VersionChangeOutcome.HOLDOFF_RESET,
                new_version=new_version,
                sfn_reset=True,  # Reset SFN relative to new epoch
                holdoff_reset=True,
                evaluate_candidates=False,
            )

        # Not in holdoff: standard version change handling
        # Per 2a.5.4: Reset SFN relative to current root's new epoch
        return VersionChangeResult(
            outcome=VersionChangeOutcome.ACCEPTED,
            new_version=new_version,
            sfn_reset=True,
            holdoff_reset=False,
            evaluate_candidates=False,
        )

    def cancel_holdoff(self) -> None:
        """Cancel holdoff transition (e.g., selected root failed signature).

        Per 2a.5.4: "If the selected root fails signature verification
        on the new version, the node MUST immediately evaluate remaining
        candidates."
        """
        self.holdoff_counter = 0
        self.holdoff_selected = None

    def set_desync_state_version(self, version: int) -> None:
        """Mark that desync state depends on the given version.

        Per 2a.5.4 step 2: This state will be reset when version changes.
        """
        self.desync_state_version = version

    def reset(self) -> None:
        """Reset all state (e.g., for testing or full desync)."""
        self.current_root = None
        self.current_version = 0
        self.candidates.clear()
        self.holdoff_selected = None
        self.holdoff_counter = 0
        self.desync_state_version = None
