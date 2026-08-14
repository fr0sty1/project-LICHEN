# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consolidated DAO origin validation (spec section 8.6).

This module provides origin validation for DAOs as specified in section 8.6
of the LICHEN routing specification. A DAO's origin must be validated against
a pre-pinned Announce identity before any route state mutation.

The validation requires:
1. The verification key MUST be from an already authenticated and pinned
   Announce identity (not self-certified or caller-supplied)
2. The preserved source address IID MUST equal the identity's bound IID
3. The DAO Origin Signature MUST be valid

Per spec: "Receipt of a DAO MUST NOT create or replace an Announce pin."
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass
from enum import Enum, auto
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

from lichen.crypto.identity import _pubkey_to_iid
from lichen.crypto.schnorr48 import verify
from lichen.rpl.messages import DAO, RplOption

if TYPE_CHECKING:
    pass

# DAO Origin Signature Option type (spec 8.6, temporary value pending IANA)
DAO_ORIGIN_SIGNATURE_TYPE: int = 0x12
DAO_ORIGIN_SIGNATURE_LENGTH: int = 56  # 8 bytes sequence + 48 bytes Schnorr48

# Domain separator for DAO origin signature (20 ASCII octets, no NUL)
DAO_ORIGIN_DOMAIN: bytes = b"LICHEN-DAO-ORIGIN-v1"


class DaoOriginRejectReason(Enum):
    """Rejection reasons for DAO origin validation."""

    ORIGIN_NOT_PINNED = auto()
    IID_MISMATCH = auto()
    SIGNATURE_MISSING = auto()
    SIGNATURE_DUPLICATE = auto()
    SIGNATURE_NOT_FINAL = auto()
    SIGNATURE_INVALID_LENGTH = auto()
    SIGNATURE_INVALID = auto()
    SEQUENCE_REPLAY = auto()
    SEQUENCE_EQUAL_DIFFERENT_BYTES = auto()


@dataclass(frozen=True)
class DaoOriginSignature:
    """Parsed DAO Origin Signature Option (spec 8.6).

    Attributes:
        origin_sequence: 64-bit unsigned monotonic counter.
        signature: 48-byte Schnorr48 signature.
    """

    origin_sequence: int
    signature: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.origin_sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("origin_sequence must fit in 64 bits")
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    @classmethod
    def from_option(cls, opt: RplOption) -> DaoOriginSignature:
        """Parse a DAO Origin Signature from an RplOption."""
        if opt.type != DAO_ORIGIN_SIGNATURE_TYPE:
            raise ValueError(f"not a DAO Origin Signature option: type {opt.type:#x}")
        if len(opt.data) != DAO_ORIGIN_SIGNATURE_LENGTH:
            raise ValueError(
                f"DAO Origin Signature must be {DAO_ORIGIN_SIGNATURE_LENGTH} bytes, "
                f"got {len(opt.data)}"
            )
        origin_sequence = struct.unpack(">Q", opt.data[:8])[0]
        signature = opt.data[8:]
        return cls(origin_sequence=origin_sequence, signature=signature)

    def to_option(self) -> RplOption:
        """Serialize to an RplOption."""
        data = struct.pack(">Q", self.origin_sequence) + self.signature
        return RplOption(DAO_ORIGIN_SIGNATURE_TYPE, data)


@dataclass(frozen=True)
class DaoOriginResult:
    """Result of DAO origin validation.

    Attributes:
        valid: True if origin validation passed.
        reject_reason: Reason for rejection if valid is False.
        pubkey: The pinned public key used for verification (if valid).
        origin_sequence: The validated origin sequence (if valid).
        dao_digest: SHA-512 digest of the complete signed DAO bytes (if valid).
        is_fresh: True if this is a fresh DAO that needs replay floor commit.
            False for idempotent retransmissions. Only meaningful when valid is True.
    """

    valid: bool
    reject_reason: DaoOriginRejectReason | None = None
    pubkey: bytes | None = None
    origin_sequence: int | None = None
    dao_digest: bytes | None = None
    is_fresh: bool = True


@runtime_checkable
class PinTable(Protocol):
    """Protocol for looking up pinned public keys by IID.

    This abstracts access to the announce processor's pin table,
    allowing DAO origin validation without tight coupling.
    """

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        """Return the pinned 32-byte pubkey for an IID, or None if not pinned."""
        ...


@runtime_checkable
class OriginReplayStore(Protocol):
    """Protocol for crash-safe origin sequence replay protection.

    Per spec 8.6: "The receiver MUST maintain crash-safe persistent state
    per pinned public key containing the accepted high-water sequence and
    a collision-resistant digest of the complete signed DAO bytes."
    """

    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        """Get (sequence, dao_digest) floor for pubkey, or None if no record."""
        ...

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Durably commit new (sequence, dao_digest) floor for pubkey."""
        ...


def extract_unsigned_dao_bytes(dao: DAO) -> bytes:
    """Extract unsigned DAO bytes for signature verification.

    Per spec 8.6: "The unsigned DAO bytes are the exact received bytes
    beginning with RPLInstanceID and ending immediately before [the DAO
    Origin Signature Option], including the DAO base fields, an explicit
    DODAGID when present, and every preceding option."

    Returns:
        The byte sequence to include in the signature transcript.
    """
    # Find the signature option and exclude it
    options_without_sig = []
    for opt in dao.options:
        if opt.type == DAO_ORIGIN_SIGNATURE_TYPE:
            break
        options_without_sig.append(opt)

    # Rebuild DAO without the signature option
    dao_without_sig = DAO(
        rpl_instance_id=dao.rpl_instance_id,
        dao_sequence=dao.dao_sequence,
        dodag_id=dao.dodag_id,
        ack_requested=dao.ack_requested,
        flags=dao.flags,
        reserved=dao.reserved,
        options=options_without_sig,
    )
    return dao_without_sig.to_bytes()


def compute_signature_transcript(
    origin_address: IPv6Address,
    dodag_id: IPv6Address,
    origin_sequence: int,
    unsigned_dao_bytes: bytes,
) -> bytes:
    """Compute the SHA-512 digest for DAO origin signature verification.

    Per spec 8.6:
        SHA-512("LICHEN-DAO-ORIGIN-v1" || origin IPv6 address ||
                effective DODAGID || Origin Sequence || unsigned DAO bytes)

    Args:
        origin_address: The origin's primary 02xx IPv6 address (16 bytes).
        dodag_id: The effective DODAGID (16 bytes).
        origin_sequence: The 64-bit origin sequence in network byte order.
        unsigned_dao_bytes: The unsigned DAO bytes for this transcript.

    Returns:
        64-byte SHA-512 digest.
    """
    transcript = (
        DAO_ORIGIN_DOMAIN
        + origin_address.packed
        + dodag_id.packed
        + struct.pack(">Q", origin_sequence)
        + unsigned_dao_bytes
    )
    return hashlib.sha512(transcript).digest()


def compute_dao_digest(signed_dao_bytes: bytes) -> bytes:
    """Compute collision-resistant digest of complete signed DAO bytes.

    This is used for replay protection per spec 8.6 to detect
    idempotent retransmissions vs. replay attacks with different content.
    """
    return hashlib.sha512(signed_dao_bytes).digest()


@dataclass
class DaoOriginValidator:
    """Consolidated DAO origin validation per spec section 8.6.

    This validator checks:
    1. Source IID has a pinned pubkey from a prior announce
    2. Key-to-IID binding is valid
    3. DAO Origin Signature Option is present, final, and valid
    4. Origin sequence passes replay protection

    Usage:
        validator = DaoOriginValidator(pin_table, replay_store)
        result = validator.validate(dao, source_address, dodag_id)
        if not result.valid:
            reject_dao(result.reject_reason)
    """

    pin_table: PinTable
    replay_store: OriginReplayStore | None = None

    def validate(
        self,
        dao: DAO,
        source_address: IPv6Address,
        effective_dodag_id: IPv6Address,
    ) -> DaoOriginResult:
        """Validate DAO origin per spec 8.6.

        Args:
            dao: The DAO message to validate.
            source_address: The preserved IPv6 source address (origin's 02xx).
            effective_dodag_id: The effective DODAGID for this DAO.

        Returns:
            DaoOriginResult with validation outcome.
        """
        # Extract source IID from address (bytes 8-16)
        source_iid = source_address.packed[8:16]

        # Step 1: Lookup pinned pubkey (must be from prior announce)
        pubkey = self.pin_table.pinned_pubkey_for(source_iid)
        if pubkey is None:
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.ORIGIN_NOT_PINNED
            )

        # Step 2: Validate key-to-IID binding
        # Catch ValueError from _pubkey_to_iid if pubkey is malformed (wrong length)
        # or TypeError if pubkey is completely wrong type (None, int, etc).
        # (corrupted storage, buggy implementation). Treat as IID_MISMATCH since
        # an invalid pinned pubkey cannot bind to any IID.
        try:
            expected_iid = _pubkey_to_iid(pubkey)
        except (ValueError, TypeError) as e:
            # SECURITY: Log corrupted pin table data for diagnostics
            # Per spec 05-routing.md: "Missing, corrupt, or unavailable state
            # is a hard failure" - logging aids debugging storage corruption.
            logger.warning(
                "pin_table returned corrupted pubkey for IID %s: %s",
                source_iid.hex(),
                e,
            )
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.IID_MISMATCH
            )
        if source_iid != expected_iid:
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.IID_MISMATCH
            )

        # Step 3: Find and validate DAO Origin Signature Option
        sig_options = [
            opt for opt in dao.options if opt.type == DAO_ORIGIN_SIGNATURE_TYPE
        ]

        if not sig_options:
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.SIGNATURE_MISSING
            )

        if len(sig_options) > 1:
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.SIGNATURE_DUPLICATE
            )

        # Signature must be the final option
        if dao.options[-1].type != DAO_ORIGIN_SIGNATURE_TYPE:
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.SIGNATURE_NOT_FINAL
            )

        sig_opt = sig_options[0]
        if len(sig_opt.data) != DAO_ORIGIN_SIGNATURE_LENGTH:
            return DaoOriginResult(
                valid=False,
                reject_reason=DaoOriginRejectReason.SIGNATURE_INVALID_LENGTH,
            )

        try:
            origin_sig = DaoOriginSignature.from_option(sig_opt)
        except ValueError:
            return DaoOriginResult(
                valid=False,
                reject_reason=DaoOriginRejectReason.SIGNATURE_INVALID_LENGTH,
            )

        # Step 4: Verify Schnorr48 signature
        unsigned_dao_bytes = extract_unsigned_dao_bytes(dao)
        transcript = compute_signature_transcript(
            source_address,
            effective_dodag_id,
            origin_sig.origin_sequence,
            unsigned_dao_bytes,
        )

        if not verify(pubkey, transcript, origin_sig.signature):
            return DaoOriginResult(
                valid=False, reject_reason=DaoOriginRejectReason.SIGNATURE_INVALID
            )

        # Step 5: Replay classification (if store is available)
        # SECURITY: Per spec 8.6, the validator MUST NOT commit the replay floor here.
        # The floor is committed at step 7 (after semantic parsing and Target validation)
        # by the caller (DaoManager). This prevents premature floor commits that would
        # incorrectly block retransmissions when steps 5-6 fail.
        signed_dao_bytes = dao.to_bytes()
        dao_digest = compute_dao_digest(signed_dao_bytes)

        is_fresh = True
        if self.replay_store is not None:
            floor = self.replay_store.get_floor(pubkey)
            if floor is not None:
                floor_seq, floor_digest = floor
                if origin_sig.origin_sequence < floor_seq:
                    return DaoOriginResult(
                        valid=False,
                        reject_reason=DaoOriginRejectReason.SEQUENCE_REPLAY,
                    )
                if origin_sig.origin_sequence == floor_seq:
                    # Equal sequence: must be exact retransmission
                    if dao_digest != floor_digest:
                        return DaoOriginResult(
                            valid=False,
                            reject_reason=DaoOriginRejectReason.SEQUENCE_EQUAL_DIFFERENT_BYTES,
                        )
                    # Idempotent retransmission - valid but no state change needed
                    is_fresh = False

        return DaoOriginResult(
            valid=True,
            pubkey=pubkey,
            origin_sequence=origin_sig.origin_sequence,
            dao_digest=dao_digest,
            is_fresh=is_fresh,
        )


__all__ = [
    "DAO_ORIGIN_DOMAIN",
    "DAO_ORIGIN_SIGNATURE_LENGTH",
    "DAO_ORIGIN_SIGNATURE_TYPE",
    "DaoOriginRejectReason",
    "DaoOriginResult",
    "DaoOriginSignature",
    "DaoOriginValidator",
    "OriginReplayStore",
    "PinTable",
    "compute_dao_digest",
    "compute_signature_transcript",
    "extract_unsigned_dao_bytes",
]
