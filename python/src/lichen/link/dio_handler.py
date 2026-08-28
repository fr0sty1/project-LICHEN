# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DIO authentication handler for LICHEN link layer.

This module manages authenticated DIO state and provides methods for:
- Accepting and validating authenticated DIO evidence
- Registering DIO issuances with bounded per-peer and global limits
- Elevating authenticated DIOs for use by upper layers
- Validating and elevating time generation credentials

The handler is designed to work with LinkLayer, delegating shared state
operations while maintaining DIO-specific issuance tracking.

Classes:
    DioHandler: Manages authenticated DIO state and generation leases.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from .._sync_callbacks import reject_awaitable_result, require_sync_callable
from ..crypto.identity import PeerIdentity
from ..gradient import MAX_ENTRIES
from .frames import RxFrame

if TYPE_CHECKING:
    from ..rpl.authenticated_dio import (
        AuthenticatedDio,
        DetachedAuthenticatedDio,
        _AuthenticatedDioSnapshot,
    )

# Bounded cache sizes for authenticated DIO issuances.
MAX_AUTHENTICATED_DIO_ISSUANCES = MAX_ENTRIES * 2
MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER = 2

_ELEVATED = TypeVar("_ELEVATED")


class DioHandler:
    """Manages authenticated DIO state and generation lease validation.

    This handler tracks authenticated DIO issuances and provides methods
    to accept, validate, and elevate DIO evidence for upper-layer use.

    The handler maintains a bounded cache of DIO issuances per peer
    and globally, evicting oldest entries when limits are exceeded.

    Attributes:
        _link: Reference to the owning LinkLayer for shared state access.
        _authenticated_dio_issuances: Ordered cache of DIO issuances.
    """

    __slots__ = ("_link", "_authenticated_dio_issuances")

    def __init__(self, link: object) -> None:
        """Initialize the DIO handler with a LinkLayer reference.

        Args:
            link: The owning LinkLayer instance. Type is object to avoid
                circular import; expected to be a LinkLayer with required
                attributes (_security_lock, _ensure_persistence_healthy, etc.).
        """
        self._link = link
        self._authenticated_dio_issuances: OrderedDict[int, _AuthenticatedDioSnapshot] = (
            OrderedDict()
        )

    def accept_authenticated_dio(
        self,
        received: RxFrame,
        *,
        expected_rpl_instance_id: int,
        expected_dodag_id: IPv6Address,
        expected_mop: int,
        expected_role: Literal["root", "peer"],
    ) -> AuthenticatedDio:
        """Consume one receipt and issue canonical DIO evidence for safe fan-out.

        Validates the received frame, issues authenticated DIO evidence,
        and registers the issuance for later validation.

        Args:
            received: A verified RxFrame from LinkLayer.receive().
            expected_rpl_instance_id: Expected RPL instance ID (0-191).
            expected_dodag_id: Expected DODAG ID as IPv6Address.
            expected_mop: Expected Mode of Operation (0-3).
            expected_role: Expected sender role ('root' or 'peer').

        Returns:
            AuthenticatedDio evidence suitable for fan-out to upper layers.

        Raises:
            TypeError: If received is not an exact RxFrame.
            ValueError: If DIO validation fails (mismatch, bad format, etc.).
            RuntimeError: If persistence or clock state is unhealthy.
        """
        from ..rpl.authenticated_dio import _issue_authenticated_dio

        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            self._link._receipt_now()
            snapshot = self._link._take_verified_receipt_unlocked(received, "dio-authenticated")
            authenticated = _issue_authenticated_dio(
                snapshot,
                expected_rpl_instance_id=expected_rpl_instance_id,
                expected_dodag_id=expected_dodag_id,
                expected_mop=expected_mop,
                expected_role=expected_role,
            )
            self._register_authenticated_dio(authenticated)
            return authenticated

    def _register_authenticated_dio(
        self, authenticated: AuthenticatedDio
    ) -> _AuthenticatedDioSnapshot:
        """Register one sealed DIO while the link security lock is held.

        Captures the authenticated DIO state and stores it in the issuance
        cache. Evicts oldest entries per-peer and globally when limits
        are exceeded.

        Args:
            authenticated: The AuthenticatedDio to register.

        Returns:
            The captured issuance snapshot for internal tracking.

        Note:
            Must be called while holding _link._security_lock.
        """
        from ..rpl.authenticated_dio import _capture_authenticated_dio

        issuance = _capture_authenticated_dio(authenticated)
        same_signer = [
            issuance_id
            for issuance_id, existing in self._authenticated_dio_issuances.items()
            if existing.sender_pubkey == issuance.sender_pubkey
        ]
        while len(same_signer) >= MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER:
            self._authenticated_dio_issuances.pop(same_signer.pop(0), None)
        self._authenticated_dio_issuances[id(authenticated)] = issuance
        while len(self._authenticated_dio_issuances) > MAX_AUTHENTICATED_DIO_ISSUANCES:
            self._authenticated_dio_issuances.popitem(last=False)
        return issuance

    def accepts_authenticated_dio(self, authenticated: object) -> bool:
        """Validate exact ownership and the full immutable DIO issuance snapshot.

        Checks that the authenticated DIO was issued by this handler's
        LinkLayer, that it has not been mutated, and that the underlying
        key generation remains current.

        Args:
            authenticated: Object to validate (expected AuthenticatedDio).

        Returns:
            True if the DIO is a valid, current issuance from this link.
            False otherwise (wrong type, not issued here, mutated, stale).
        """
        from ..rpl.authenticated_dio import AuthenticatedDio, _capture_authenticated_dio

        if type(authenticated) is not AuthenticatedDio:
            return False
        try:
            self._link._ensure_persistence_healthy()
        except RuntimeError:
            return False
        with self._link._security_lock:
            try:
                self._link._ensure_persistence_healthy()
                self._link._receipt_now()
            except RuntimeError:
                return False
            issued = self._authenticated_dio_issuances.get(id(authenticated))
            if issued is None or issued.facade is not authenticated:
                return False
            try:
                current = _capture_authenticated_dio(authenticated)
            except (AttributeError, TypeError, ValueError):
                return False
            return (
                current.facade is issued.facade
                and current.rx_snapshot is issued.rx_snapshot
                and current.receiving_link_identity is self._link._receiving_link_identity
                and current.receiving_link_identity is issued.receiving_link_identity
                and current.clock_domain_identity is issued.clock_domain_identity
                and current.key_generation is issued.key_generation
                and current.structural_state == issued.structural_state
            )

    def elevate_authenticated_dio(
        self,
        authenticated: object,
        *,
        elevate: Callable[[DetachedAuthenticatedDio], _ELEVATED],
    ) -> _ELEVATED:
        """Validate and detach DIO evidence inside one security transaction.

        Verifies the authenticated DIO is current and untampered, acquires
        a generation lease to block rekey during the callback, and invokes
        the elevation callback with detached DIO evidence.

        Args:
            authenticated: The AuthenticatedDio to elevate.
            elevate: Synchronous callback receiving DetachedAuthenticatedDio.
                Must not be async; must not raise.

        Returns:
            The value returned by the elevate callback.

        Raises:
            TypeError: If authenticated is not an exact AuthenticatedDio.
            ValueError: If the DIO is not a live issuance, is stale, or mutated.
            RuntimeError: If persistence state is unhealthy.
        """
        from ..rpl.authenticated_dio import (
            AuthenticatedDio,
            _capture_authenticated_dio,
            _detach_authenticated_dio,
        )

        if type(authenticated) is not AuthenticatedDio:
            raise TypeError("authenticated must be an exact AuthenticatedDio")
        callback = require_sync_callable(elevate, "DIO elevation callback")
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            self._link._receipt_now()
            issued = self._authenticated_dio_issuances.get(id(authenticated))
            if issued is None or issued.facade is not authenticated:
                raise ValueError("authenticated DIO is not a live LinkLayer issuance")
            current = _capture_authenticated_dio(authenticated)
            signer = issued.sender_pubkey
            if (
                current.rx_snapshot is not issued.rx_snapshot
                or current.structural_state != issued.structural_state
                or current.receiving_link_identity is not self._link._receiving_link_identity
                or current.key_generation is not issued.key_generation
                or self._link._key_generations.get(signer) is not issued.key_generation
                or signer in self._link._retired_remote_keys
                or self._link._pinned_keys.get(PeerIdentity.from_pubkey(signer).iid) != signer
            ):
                raise ValueError("authenticated DIO is stale, mutated, or no longer trusted")
            detached = _detach_authenticated_dio(issued)
            self._link._acquire_generation_lease_unlocked(signer, issued.key_generation)
        try:
            return cast(
                _ELEVATED,
                reject_awaitable_result(
                    callback(detached),
                    "DIO elevation callback",
                ),
            )
        finally:
            self._link._release_generation_lease(signer)

    def accepts_time_generation(self, signer: bytes, generation: object) -> bool:
        """Return whether one adopted time source remains pinned and current.

        Validates that the signer's key has not been retired, the generation
        matches the current one, and the key remains pinned.

        Args:
            signer: The 32-byte public key of the time source.
            generation: The opaque generation object to validate.

        Returns:
            True if the time source is still valid and pinned.
            False otherwise.
        """
        if type(signer) is not bytes or len(signer) != 32:
            return False
        try:
            self._link._ensure_persistence_healthy()
        except RuntimeError:
            return False
        with self._link._security_lock:
            try:
                self._link._ensure_persistence_healthy()
                self._link._receipt_now()
            except RuntimeError:
                return False
            return (
                signer not in self._link._retired_remote_keys
                and self._link._key_generations.get(signer) is generation
                and self._link._pinned_keys.get(PeerIdentity.from_pubkey(signer).iid) == signer
            )

    def elevate_time_generation(
        self,
        signer: bytes,
        generation: object,
        *,
        elevate: Callable[[], _ELEVATED],
    ) -> _ELEVATED:
        """Commit one time-policy transition while its peer generation is current.

        Acquires a generation lease to prevent rekey during the callback,
        then invokes the elevation callback. Multiple time generation leases
        may overlap for the same signer.

        Args:
            signer: The 32-byte public key of the time source.
            generation: The opaque generation object that must be current.
            elevate: Synchronous callback to invoke under the lease.

        Returns:
            The value returned by the elevate callback.

        Raises:
            ValueError: If signer is invalid or generation is no longer current.
            RuntimeError: If persistence state is unhealthy.
        """
        if type(signer) is not bytes or len(signer) != 32:
            raise ValueError("signer must be a 32-byte public key")
        callback = require_sync_callable(elevate, "time generation callback")
        self._link._ensure_persistence_healthy()
        with self._link._security_lock:
            self._link._ensure_persistence_healthy()
            self._link._receipt_now()
            # Generation-validation leases may overlap. Each pins the same
            # current key against rekey until its callback returns; waiting for
            # another callback here would invert any external lock held by the
            # caller (notably StratumTracker's state lock) against a callback
            # already waiting for that external lock.
            self._link._acquire_generation_lease_unlocked(signer, generation)
        try:
            return cast(
                _ELEVATED,
                reject_awaitable_result(callback(), "time generation callback"),
            )
        finally:
            self._link._release_generation_lease(signer)
