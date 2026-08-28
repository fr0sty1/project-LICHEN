# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link layer with signature and replay protection (muq).

Why this exists: The link layer is the boundary between:
- Above: IPv6/SCHC packets that assume reliable, authenticated delivery
- Below: Raw radio bytes that can be forged, replayed, or corrupted

This module provides:
1. Frame construction with proper sequencing
2. Schnorr signature generation on TX
3. Signature verification on RX (integrity + authentication)
4. Replay detection using per-sender sliding windows
5. Key pinning (TOFU) for change detection

Threading model: Concurrent send() via per-entry TxReservations; TX serialized by _tx_lock.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import random
import secrets
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import InitVar, dataclass, field
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal, TypeVar, cast

from .._sync_callbacks import reject_awaitable_result, require_sync_callable
from ..constants import (
    CAD_MAX_BACKOFF_EXPONENT,
    CAD_MAX_CYCLES,
    CAD_SLOT_MS,
    LORA_CAD_TIMEOUT_MS,
)
from ..crypto.identity import Identity, PeerIdentity, yggdrasil_address
from ..crypto.schnorr48 import sign, verify
from ..gradient import MAX_ENTRIES
from ..ipv6.addr import eui64_to_iid, iid_to_eui64, make_link_local
from .dio_handler import DioHandler
from .frame import (
    LINK_SIGNATURE_DOMAIN,
    MAX_FRAME_BODY,
    AddrMode,
    EncryptedFrameError,
    FrameError,
    LichenFrame,
    MicLength,
)
from .frames import (
    ReceiveError,
    RxFrame,
    _AuthenticatedPeerSchcIssuance,
    _VerifiedReceipt,
)
from .persistence import LinkPersistence
from .protocols import (
    LinkPersistenceError,
    LinkSecurityClockError,
    PersistenceRevisionAnchor,
    _PeerCandidate,
)
from .receipts import (
    MAX_VERIFIED_RECEIPTS_PER_PEER as _RECEIPT_MAX_PER_PEER,
)
from .receipts import (
    VERIFIED_RECEIPT_PURPOSES as _RECEIPT_PURPOSES,
)
from .receipts import (
    VERIFIED_RECEIPT_TTL_SECONDS as _RECEIPT_TTL,
)

# Import extracted helper classes
from .receipts import (
    ReceiptStore,
)
from .replay import ReplayCapacityError, ReplayProtector, logical_counter
from .schc_handler import SchcHandler
from .tx_queue import Priority, TxQueue

# Re-export extracted classes for backwards compatibility
__all__ = [
    "LinkLayer",
    "RxFrame",
    "ReceiveError",
    "PersistenceRevisionAnchor",
    "LinkPersistenceError",
    "LinkSecurityClockError",
    "encode_rekey_request",
    "_VerifiedReceipt",
    "_AuthenticatedPeerSchcIssuance",
    "_PeerCandidate",
]

if TYPE_CHECKING:
    from ..radio.base import Radio
    from ..rpl.authenticated_dio import (
        AuthenticatedDio,
        DetachedAuthenticatedDio,
        _AuthenticatedDioSnapshot,
    )
    from ..schc.context import AuthenticatedPeerSchcContext
    from ..schc.fragment import FragmentSender
    from ..schc.reassembly import ReceiverResult, _AuthenticatedReassemblyManager
    from ..schc.session_manager import SchcSessionManager
    from ..timing.time_sync import MonotonicClock

logger = logging.getLogger(__name__)

# A signed frame puts the full Schnorr-48 value in the MIC field.
SIGNATURE_LENGTH = 48
# Re-export constants from receipts module for backwards compatibility
MAX_VERIFIED_RECEIPTS_PER_PEER = _RECEIPT_MAX_PER_PEER
VERIFIED_RECEIPT_TTL_SECONDS = _RECEIPT_TTL
VERIFIED_RECEIPT_PURPOSES = _RECEIPT_PURPOSES
MAX_VERIFIED_RECEIPTS = MAX_ENTRIES * MAX_VERIFIED_RECEIPTS_PER_PEER
MAX_SINGLE_FRAME_SCHC_PACKET = (
    MAX_FRAME_BODY
    - 4
    - AddrMode.EXTENDED.addr_len
    - 8  # mandatory signer EUI-64 (SI)
    - SIGNATURE_LENGTH
    - 1  # L2 SCHC dispatch
)
_ELEVATED = TypeVar("_ELEVATED")
REKEY_CONTROL_PREFIX = b"\xfeLKR1"


MAX_RETIRED_REMOTE_KEYS = MAX_ENTRIES
MAX_AUTHENTICATED_DIO_ISSUANCES = MAX_ENTRIES * 2
MAX_AUTHENTICATED_DIO_ISSUANCES_PER_PEER = 2

_LINK_RECEIPT_CLOCK_BINDINGS_LOCK = threading.RLock()
_LINK_RECEIPT_CLOCK_BINDINGS: weakref.WeakKeyDictionary[
    LinkLayer, tuple[MonotonicClock, tuple[object, ...]]
] = weakref.WeakKeyDictionary()

# Track whether we've warned about encrypted frames being rejected.
# Why reject: Encryption is not implemented. Frames claiming to be encrypted
# cannot be decrypted, so accepting them would misinterpret the payload.
_encrypted_frame_warned = False


def encode_rekey_request(new_remote_signer_identity: bytes) -> bytes:
    """Encode the new key carried by an old-key-signed rekey control frame."""
    if type(new_remote_signer_identity) is not bytes or len(new_remote_signer_identity) != 32:
        raise ValueError("new remote signer identity must be 32 bytes")
    return REKEY_CONTROL_PREFIX + new_remote_signer_identity


@dataclass(eq=False)
class LinkLayer:
    """Link layer with signing, verification, and replay protection.

    Why dataclass: Clear field documentation, automatic __init__, works well
    with dependency injection for testing.

    Attributes:
        radio: The underlying radio for TX/RX.
        identity: This node's cryptographic identity.
        peer_lookup: Callback to resolve sender IID to PeerIdentity.
            Why a callback: The peer database is owned by upper layers.
            We don't want the link layer to own peer state.
        replay_protector: Per-sender replay detection.
        cad_enabled: If True, perform CAD before transmit with exponential
            backoff on busy channel. Defaults to True.
        _epoch: Current 8-bit epoch (increments on seqnum wrap).
        _seqnum: Current 16-bit sequence number.
    """

    radio: Radio
    identity: Identity
    peer_lookup: Callable[[bytes], PeerIdentity | None]
    replay_protector: ReplayProtector = field(default_factory=ReplayProtector)
    # peer_lookup_all: For brute-force sender identification when no hint available.
    # NOTE: O(n) verification is unavoidable without sender IID in frame format.
    # Protocol-level fix needed: add sender IID to header extension.
    peer_lookup_all: Callable[[], list[PeerIdentity]] | None = field(default=None, repr=False)
    cad_enabled: bool = field(default=True)
    tx_queue: TxQueue = field(default_factory=TxQueue)
    persist_path: str | None = field(default=None, repr=False)
    receipt_clock: InitVar[MonotonicClock | None] = None
    receipt_clock_domain: InitVar[object | None] = None
    persistence_revision_anchor: InitVar[PersistenceRevisionAnchor | None] = None
    allow_persistence_bootstrap: InitVar[bool] = False
    local_short_addr: int | None = None
    # ponytail: random epoch in [128,255] for reboot resilience without flash.
    # Half-space arithmetic treats upper-half counters as "ahead" of lower-half.
    # SECURITY: Use secrets module for cryptographically secure random epoch.
    _epoch: int = field(default_factory=lambda: secrets.randbelow(128) + 128, repr=False)
    _seqnum: int = field(default=0, repr=False)
    _exhausted: bool = field(default=False, repr=False)
    _pinned_keys: OrderedDict[bytes, bytes] = field(default_factory=OrderedDict, repr=False)
    _tx_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _sequence_started: bool = field(default=False, init=False, repr=False)
    _security_lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _retired_remote_keys: set[bytes] = field(default_factory=set, init=False, repr=False)
    _rekeyed_peers: dict[bytes, PeerIdentity] = field(default_factory=dict, init=False, repr=False)
    # Receipt storage delegated to ReceiptStore helper
    _receipts: ReceiptStore = field(init=False, repr=False)
    # DIO issuance tracking delegated to DioHandler helper
    _dio: DioHandler = field(init=False, repr=False)
    # SCHC operations delegated to SchcHandler helper
    _schc: SchcHandler = field(init=False, repr=False)
    _receipt_clock: object = field(init=False, repr=False)
    _clock_domain: object = field(default_factory=object, init=False, repr=False)
    _receiving_link_identity: object = field(default_factory=object, init=False, repr=False)
    _key_generations: dict[bytes, object] = field(default_factory=dict, init=False, repr=False)
    _schc_session_manager: SchcSessionManager = field(init=False, repr=False)
    _schc_peer_contexts: dict[bytes, AuthenticatedPeerSchcContext] = field(
        default_factory=dict, init=False, repr=False
    )
    _schc_peer_context_issuances: dict[int, _AuthenticatedPeerSchcIssuance] = field(
        default_factory=dict, init=False, repr=False
    )
    _schc_reassembly_manager: _AuthenticatedReassemblyManager = field(init=False, repr=False)
    _local_pubkey: bytes = field(init=False, repr=False)
    _local_privkey: bytes = field(init=False, repr=False)
    _local_iid: bytes = field(init=False, repr=False)
    _local_eui64: bytes = field(init=False, repr=False)
    _local_ygg_addr: bytes = field(init=False, repr=False)
    _configured_short_addr: int | None = field(init=False, repr=False)
    _replay_owner_token: object = field(default_factory=object, init=False, repr=False)
    _receipt_clock_lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False
    )
    _receipt_clock_high_water: float = field(default=-1.0, init=False, repr=False)
    _receipt_clock_failed: bool = field(default=False, init=False, repr=False)
    _receipt_clock_active: bool = field(default=False, init=False, repr=False)
    _generation_condition: threading.Condition = field(init=False, repr=False)
    _generation_leases: dict[bytes, int] = field(default_factory=dict, init=False, repr=False)
    _generation_lease_owners: dict[tuple[bytes, int], int] = field(
        default_factory=dict, init=False, repr=False
    )
    _persistence: LinkPersistence = field(init=False, repr=False)

    def __post_init__(
        self,
        receipt_clock: MonotonicClock | None,
        receipt_clock_domain: object | None,
        persistence_revision_anchor: PersistenceRevisionAnchor | None,
        allow_persistence_bootstrap: bool,
    ) -> None:
        # Why validate: Catch misconfiguration early
        if self.identity is None:
            raise ValueError("identity is required")
        if self.radio is None:
            raise ValueError("radio is required")
        if self.peer_lookup is None:
            raise ValueError("peer_lookup callback is required")
        if (
            type(self.identity.pubkey) is not bytes
            or len(self.identity.pubkey) != 32
            or type(self.identity.privkey) is not bytes
            or len(self.identity.privkey) != 32
        ):
            raise ValueError("identity must expose exact 32-byte key material")
        self._local_pubkey = bytes(self.identity.pubkey)
        self._local_privkey = bytes(self.identity.privkey)
        self._local_iid = PeerIdentity.from_pubkey(self._local_pubkey).iid
        self._local_eui64 = iid_to_eui64(self._local_iid)
        self._local_ygg_addr = yggdrasil_address(self._local_pubkey).packed
        self._generation_condition = threading.Condition(self._security_lock)
        from ..timing.time_sync import SYSTEM_MONOTONIC_CLOCK, MonotonicClock

        if receipt_clock is not None and type(receipt_clock) is not MonotonicClock:
            raise TypeError("receipt_clock must be an exact MonotonicClock or None")
        if receipt_clock_domain is not None:
            raise ValueError("receipt_clock_domain is derived and cannot be supplied")
        if type(allow_persistence_bootstrap) is not bool:
            raise TypeError("allow_persistence_bootstrap must be bool")
        if self.local_short_addr is not None:
            from .short_addr import SHORT_ADDR_RESERVED

            if (
                type(self.local_short_addr) is not int
                or not 0 <= self.local_short_addr <= 0xFFFF
                or self.local_short_addr in SHORT_ADDR_RESERVED
            ):
                raise ValueError("local_short_addr must be a non-reserved 16-bit address")
        self._configured_short_addr = self.local_short_addr
        if self.persist_path is None:
            if persistence_revision_anchor is not None or allow_persistence_bootstrap:
                raise ValueError("persistence anchor/bootstrap requires persist_path")
        elif (
            persistence_revision_anchor is None
            or not callable(getattr(persistence_revision_anchor, "read", None))
            or not callable(getattr(persistence_revision_anchor, "advance", None))
        ):
            raise ValueError("persist_path requires an independent monotonic revision anchor")
        if persistence_revision_anchor is not None:
            require_sync_callable(persistence_revision_anchor.read, "persistence anchor read")
            require_sync_callable(persistence_revision_anchor.advance, "persistence anchor advance")
        clock_capability = receipt_clock or SYSTEM_MONOTONIC_CLOCK
        self._receipt_clock = clock_capability
        self._clock_domain = clock_capability.domain_identity
        with _LINK_RECEIPT_CLOCK_BINDINGS_LOCK:
            _LINK_RECEIPT_CLOCK_BINDINGS[self] = (
                clock_capability,
                clock_capability._binding_snapshot(),
            )
        from ..schc.reassembly import _AuthenticatedReassemblyManager
        from ..schc.session_manager import SchcSessionManager

        self.replay_protector._claim_owner(self._replay_owner_token)
        self._schc_control_issuer_token = object()
        self._schc_session_manager = SchcSessionManager(
            local_identity=self._local_pubkey,
            replay_protector=self.replay_protector,
            security_lock=self._security_lock,
            replay_owner_token=self._replay_owner_token,
            receipt_consumer=self._consume_verified_receipt_unlocked,
            control_issuer_token=self._schc_control_issuer_token,
            key_generation_lookup=self._key_generations.get,
            state_change=self._save_persisted_state,
            clock=clock_capability,
        )
        self._schc_reassembly_manager = _AuthenticatedReassemblyManager(
            local_identity=self._local_pubkey,
            security_lock=self._security_lock,
            clock=clock_capability,
        )
        # Instantiate helper modules for extracted functionality
        self._receipts = ReceiptStore(self._receipt_now)
        self._dio = DioHandler(self)
        self._schc = SchcHandler(self)
        # Create persistence handler (delegates all persistence operations)
        self._persistence = LinkPersistence(
            persist_path=self.persist_path,
            local_privkey=self._local_privkey,
            local_pubkey=self._local_pubkey,
            security_lock=self._security_lock,
            revision_anchor=persistence_revision_anchor,
            allow_bootstrap=allow_persistence_bootstrap,
            state_exporter=self,
            state_restorer=self,
            failure_handler=self,
        )
        if self.persist_path is not None:
            self._load_persisted_state()

    @property
    def clock_domain_identity(self) -> object:
        """Opaque identity for timestamps produced by this link's receipt clock."""
        capability = self._receipt_clock_capability()
        return capability.domain_identity

    def _receipt_clock_capability(self) -> MonotonicClock:
        from ..timing.time_sync import MonotonicClock

        with _LINK_RECEIPT_CLOCK_BINDINGS_LOCK:
            binding = _LINK_RECEIPT_CLOCK_BINDINGS.get(self)
        if binding is None:
            raise RuntimeError("receipt clock capability binding is missing")
        capability, snapshot = binding
        if (
            type(capability) is not MonotonicClock
            or capability._binding_snapshot() != snapshot
            or self._receipt_clock is not capability
            or self._clock_domain is not capability.domain_identity
        ):
            raise RuntimeError("receipt clock capability binding changed")
        return capability

    def _receipt_now(self) -> float:
        failure: BaseException | None = None
        with self._receipt_clock_lock:
            if self._receipt_clock_failed:
                raise LinkSecurityClockError(
                    "receipt clock is disabled after a terminal security-clock failure"
                )
            if self._receipt_clock_active:
                self._receipt_clock_failed = True
                failure = RuntimeError("receipt clock reentered")
            else:
                self._receipt_clock_active = True
                try:
                    try:
                        current = self._receipt_clock_capability()()
                    except BaseException as exc:
                        self._receipt_clock_failed = True
                        failure = exc
                finally:
                    self._receipt_clock_active = False
                if failure is None:
                    if (
                        isinstance(current, bool)
                        or not isinstance(current, (int, float))
                        or not math.isfinite(current)
                        or current < 0
                    ):
                        self._receipt_clock_failed = True
                        failure = RuntimeError(
                            "receipt_clock must return a finite non-negative number"
                        )
                    else:
                        result = float(current)
                        if result < self._receipt_clock_high_water:
                            self._receipt_clock_failed = True
                            failure = RuntimeError("receipt clock regressed")
                        else:
                            self._receipt_clock_high_water = result
        if failure is not None:
            with self._security_lock:
                self._verified_receipts.clear()
                self._authenticated_dio_issuances.clear()
            raise LinkSecurityClockError(
                "receipt clock failed, regressed, or reentered; authenticated "
                "receipts and DIO issuances are permanently disabled"
            ) from failure
        return result

    def _wire_is_for_local(self, frame: LichenFrame) -> bool:
        """Check the authenticated wire destination without mutating security state."""
        from ..schc.codec import SchcError
        from .addressing import derive_elided_destination

        if frame.addr_mode is AddrMode.NONE:
            return True
        if frame.addr_mode is AddrMode.EXTENDED:
            return frame.dst_addr == self._local_eui64
        if frame.addr_mode is AddrMode.SHORT:
            return (
                self._configured_short_addr is not None
                and frame.dst_addr == self._configured_short_addr.to_bytes(2, "big")
            )
        if frame.addr_mode is not AddrMode.ELIDED:
            return False
        try:
            destination = derive_elided_destination(frame.payload)
        except (SchcError, TypeError, ValueError):
            return False
        return (
            destination.is_multicast
            or destination == make_link_local(self._local_iid)
            or destination.packed == self._local_ygg_addr
        )

    def _peer_has_eviction_blocker_unlocked(self, signer: bytes) -> bool:
        """Return whether ``signer`` owns an active or held-down transaction."""
        if self._generation_leases.get(signer, 0) != 0:
            return True
        if self._schc_session_manager.replacement_occupied(signer):
            return True
        return self._schc_reassembly_manager.peer_eviction_blocked(signer)

    def _retire_evicted_peer_unlocked(self, iid: bytes, signer: bytes) -> None:
        """Retire bounded peer registries while preserving replay high-water."""
        self._schc_session_manager.retire_remote(signer)
        self._schc_reassembly_manager.invalidate_remote_policy(signer)
        stale_peer = self._schc_peer_contexts.pop(signer, None)
        if stale_peer is not None:
            self._schc_peer_context_issuances.pop(id(stale_peer), None)
        for issuance_id in [
            issuance_id
            for issuance_id, issuance in self._schc_peer_context_issuances.items()
            if issuance.signer_identity == signer
        ]:
            self._schc_peer_context_issuances.pop(issuance_id, None)
        for receipt_id in [
            receipt_id
            for receipt_id, receipt in self._verified_receipts.items()
            if receipt.snapshot.sender_pubkey == signer
        ]:
            self._verified_receipts.pop(receipt_id, None)
        for issuance_id in [
            issuance_id
            for issuance_id, issuance in self._authenticated_dio_issuances.items()
            if issuance.sender_pubkey == signer
        ]:
            self._authenticated_dio_issuances.pop(issuance_id, None)
        self._rekeyed_peers.pop(signer, None)
        self._key_generations.pop(signer, None)
        self._pinned_keys.pop(iid, None)

    @property
    def receiving_link_identity(self) -> object:
        """Opaque identity for this exact receiving LinkLayer instance."""
        return self._receiving_link_identity

    @property
    def _verified_receipts(self) -> OrderedDict[int, _VerifiedReceipt]:
        """Access to receipt storage for internal operations. Delegates to ReceiptStore."""
        return self._receipts._receipts

    @property
    def _authenticated_dio_issuances(self) -> OrderedDict[int, _AuthenticatedDioSnapshot]:
        """Access to DIO issuances for internal operations. Delegates to DioHandler."""
        return self._dio._authenticated_dio_issuances

    def create_fragment_sender(
        self,
        payload: bytes,
        remote_signer_identity: bytes,
        receiver_limit: int = 1281,
    ) -> FragmentSender:
        """Create the sole active T=0 SCHC sender for an authenticated link key.

        Delegates to SchcHandler.
        """
        return self._schc.create_fragment_sender(
            payload, remote_signer_identity, receiver_limit
        )

    def cancel_fragment_sender(self, sender: FragmentSender) -> bytes | None:
        """Cancel one exact sender and return its one-use Sender-Abort authority.

        Delegates to SchcHandler.
        """
        return self._schc.cancel_fragment_sender(sender)

    def compress_schc_for_peer(
        self,
        raw_ipv6: bytes,
        remote_signer_identity: bytes,
        *,
        single_frame_limit: int = MAX_SINGLE_FRAME_SCHC_PACKET,
        allow_fragmentation: bool = False,
    ) -> bytes:
        """Compress one unfragmented datagram under current peer policy.

        Delegates to SchcHandler.
        """
        return self._schc.compress_schc_for_peer(
            raw_ipv6,
            remote_signer_identity,
            single_frame_limit=single_frame_limit,
            allow_fragmentation=allow_fragmentation,
        )

    def accept_authenticated_schc_packet(
        self,
        received: RxFrame,
        *,
        single_frame_limit: int = MAX_SINGLE_FRAME_SCHC_PACKET,
    ) -> bytes:
        """Consume one link receipt and decode it under current signer policy.

        Delegates to SchcHandler.
        """
        return self._schc.accept_authenticated_schc_packet(
            received, single_frame_limit=single_frame_limit
        )

    def accept_authenticated_schc_fragment(
        self,
        received: RxFrame,
    ) -> tuple[ReceiverResult, bytes | None]:
        """Consume and apply one authenticated fragment/control frame.

        Delegates to SchcHandler.
        """
        return self._schc.accept_authenticated_schc_fragment(received)

    def accept_authenticated_schc_fragment_dio(
        self,
        received: RxFrame,
        *,
        expected_rpl_instance_id: int,
        expected_dodag_id: IPv6Address,
        expected_mop: int,
        expected_role: Literal["root", "peer"],
    ) -> tuple[ReceiverResult, bytes | None, AuthenticatedDio | None]:
        """Reassemble a fragment and issue DIO evidence in one link transaction.

        Delegates to SchcHandler.
        """
        return self._schc.accept_authenticated_schc_fragment_dio(
            received,
            expected_rpl_instance_id=expected_rpl_instance_id,
            expected_dodag_id=expected_dodag_id,
            expected_mop=expected_mop,
            expected_role=expected_role,
        )

    def expire_authenticated_schc_reassembly(self) -> list[tuple[bytes, bytes, bytes]]:
        """Drain proactive inactivity aborts as ``(peer_key, dst_eui64, wire)``.

        Each due inbound context produces its exact Receiver-Abort once.  The
        caller transmits ``wire`` to ``dst_eui64`` with ACK priority; the full
        peer key is included so higher layers can retain authenticated ownership.

        Delegates to SchcHandler.
        """
        return self._schc.expire_authenticated_schc_reassembly()

    def accept_authenticated_schc_sender_control(
        self,
        received: RxFrame,
    ) -> list[bytes] | None:
        """Apply a Link-registered sender ACK/abort before receiver dispatch.

        Delegates to SchcHandler.
        """
        return self._schc.accept_authenticated_schc_sender_control(received)

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

        Delegates to DioHandler.
        """
        return self._dio.accept_authenticated_dio(
            received,
            expected_rpl_instance_id=expected_rpl_instance_id,
            expected_dodag_id=expected_dodag_id,
            expected_mop=expected_mop,
            expected_role=expected_role,
        )

    def _register_authenticated_dio_unlocked(
        self, authenticated: AuthenticatedDio
    ) -> _AuthenticatedDioSnapshot:
        """Register one sealed DIO while the link security lock is held.

        Delegates to DioHandler.
        """
        return self._dio._register_authenticated_dio(authenticated)

    def accepts_authenticated_dio(self, authenticated: object) -> bool:
        """Validate exact ownership and the full immutable DIO issuance snapshot.

        Delegates to DioHandler.
        """
        return self._dio.accepts_authenticated_dio(authenticated)

    def elevate_authenticated_dio(
        self,
        authenticated: object,
        *,
        elevate: Callable[[DetachedAuthenticatedDio], _ELEVATED],
    ) -> _ELEVATED:
        """Validate and detach DIO evidence inside one security transaction.

        Delegates to DioHandler.
        """
        return self._dio.elevate_authenticated_dio(authenticated, elevate=elevate)

    def accepts_time_generation(self, signer: bytes, generation: object) -> bool:
        """Return whether one adopted time source remains pinned and current.

        Delegates to DioHandler.
        """
        return self._dio.accepts_time_generation(signer, generation)

    def elevate_time_generation(
        self,
        signer: bytes,
        generation: object,
        *,
        elevate: Callable[[], _ELEVATED],
    ) -> _ELEVATED:
        """Commit one time-policy transition while its peer generation is current.

        Delegates to DioHandler.
        """
        return self._dio.elevate_time_generation(signer, generation, elevate=elevate)

    def elevate_peer_generation(
        self,
        signer: bytes,
        generation: object,
        *,
        elevate: Callable[[], _ELEVATED],
    ) -> _ELEVATED:
        """Run an atomic peer-policy commit while rekey and rival DIOs wait."""
        if type(signer) is not bytes or len(signer) != 32:
            raise ValueError("signer must be a 32-byte public key")
        callback = require_sync_callable(elevate, "peer generation callback")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            self._receipt_now()
            self._wait_for_foreign_generation_leases_unlocked(signer)
            self._ensure_persistence_healthy()
            self._acquire_generation_lease_unlocked(signer, generation)
        try:
            return cast(
                _ELEVATED,
                reject_awaitable_result(callback(), "peer generation callback"),
            )
        finally:
            self._release_generation_lease(signer)

    def _wait_for_foreign_generation_leases_unlocked(self, signer: bytes) -> None:
        owner_count = self._generation_lease_owners.get((signer, threading.get_ident()), 0)
        while self._generation_leases.get(signer, 0) > owner_count:
            self._generation_condition.wait()

    def _acquire_generation_lease_unlocked(self, signer: bytes, generation: object) -> None:
        if (
            signer in self._retired_remote_keys
            or self._key_generations.get(signer) is not generation
            or self._pinned_keys.get(PeerIdentity.from_pubkey(signer).iid) != signer
        ):
            raise ValueError("peer key generation is no longer current")
        owner = (signer, threading.get_ident())
        self._generation_leases[signer] = self._generation_leases.get(signer, 0) + 1
        self._generation_lease_owners[owner] = self._generation_lease_owners.get(owner, 0) + 1

    def _release_generation_lease(self, signer: bytes) -> None:
        with self._generation_condition:
            owner = (signer, threading.get_ident())
            owner_count = self._generation_lease_owners.get(owner, 0)
            if owner_count <= 1:
                self._generation_lease_owners.pop(owner, None)
            else:
                self._generation_lease_owners[owner] = owner_count - 1
            count = self._generation_leases.get(signer, 0)
            if count <= 1:
                self._generation_leases.pop(signer, None)
            else:
                self._generation_leases[signer] = count - 1
            self._generation_condition.notify_all()

    def _validated_authenticated_peer_schc_context(
        self,
        peer: AuthenticatedPeerSchcContext,
    ) -> tuple[int, bytes]:
        """Return the immutable policy behind one exact, current peer handle."""
        from ..schc.context import AuthenticatedPeerSchcContext

        if type(peer) is not AuthenticatedPeerSchcContext:
            raise ValueError("SCHC peer context is not an exact LinkLayer issuance")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            issued = self._schc_peer_context_issuances.get(id(peer))
            if issued is None or issued.facade is not peer:
                raise ValueError("SCHC peer context is not an exact LinkLayer issuance")
            signer = issued.signer_identity
            pinned = self._pinned_keys.get(PeerIdentity.from_pubkey(signer).iid)
            if (
                self._schc_peer_contexts.get(signer) is not peer
                or signer in self._retired_remote_keys
                or pinned != signer
                or self._key_generations.get(signer) is not issued.key_generation
            ):
                raise ValueError("SCHC peer context is stale or no longer trusted")
            return issued.remote_version, signer

    def accept_authenticated_schc_dio(
        self,
        received: RxFrame | AuthenticatedDio,
        *,
        expected_rpl_instance_id: int | None = None,
        expected_dodag_id: IPv6Address | None = None,
        expected_mop: int | None = None,
        expected_role: Literal["root", "peer"] | None = None,
    ) -> tuple[AuthenticatedDio, AuthenticatedPeerSchcContext]:
        """Derive SCHC policy from one sealed, canonical authenticated DIO."""
        from ..rpl.authenticated_dio import (
            AuthenticatedDio,
            _capture_authenticated_dio,
            _detach_authenticated_dio,
        )
        from ..schc.context import AuthenticatedPeerSchcContext
        from ..schc.rules import SCHC_RULE_VERSION_TYPE, SchcRuleVersionOption

        if type(received) is RxFrame:
            if (
                expected_rpl_instance_id is None
                or expected_dodag_id is None
                or expected_mop is None
                or expected_role is None
            ):
                raise TypeError("RxFrame DIO admission requires complete expected DODAG scope")
            authenticated = self.accept_authenticated_dio(
                received,
                expected_rpl_instance_id=expected_rpl_instance_id,
                expected_dodag_id=expected_dodag_id,
                expected_mop=expected_mop,
                expected_role=expected_role,
            )
        elif type(received) is AuthenticatedDio:
            authenticated = received
        else:
            raise TypeError("received must be an exact RxFrame or AuthenticatedDio")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            self._receipt_now()
            issued = self._authenticated_dio_issuances.get(id(authenticated))
            if issued is None or issued.facade is not authenticated:
                raise ValueError("authenticated DIO was not issued unchanged by this LinkLayer")
            current = _capture_authenticated_dio(authenticated)
            if (
                current.rx_snapshot is not issued.rx_snapshot
                or current.structural_state != issued.structural_state
                or current.receiving_link_identity is not self._receiving_link_identity
                or current.key_generation is not issued.key_generation
            ):
                raise ValueError("authenticated DIO was not issued unchanged by this LinkLayer")
            detached = _detach_authenticated_dio(issued)
            version_options = [
                option for option in detached.options if option.type == SCHC_RULE_VERSION_TYPE
            ]
            if len(version_options) != 1:
                raise ValueError(
                    "authenticated DIO must contain exactly one SCHC Rule Version option"
                )
            option_data = version_options[0].data
            option = SchcRuleVersionOption.from_bytes(
                bytes([SCHC_RULE_VERSION_TYPE, len(option_data)]) + option_data
            )
            signer = detached.sender_pubkey
            self._wait_for_foreign_generation_leases_unlocked(signer)
            self._ensure_persistence_healthy()
            key_generation = self._key_generations.get(signer)
            if key_generation is None or issued.key_generation is not key_generation:
                raise ValueError("authenticated DIO key generation is no longer current")
            previous = self._schc_peer_contexts.get(signer)
            if previous is not None:
                previous_issuance = self._schc_peer_context_issuances.get(id(previous))
                if previous_issuance is None:
                    raise ValueError("current SCHC peer context lost its LinkLayer issuance")
                admitted_counter = logical_counter(detached.epoch, detached.seqnum)
                if admitted_counter <= previous_issuance.admitted_counter:
                    raise ValueError(
                        "authenticated DIO policy counter is not newer than current policy"
                    )
                if previous_issuance.remote_version != option.version:
                    self._schc_session_manager.invalidate_remote_policy(signer)
                    self._schc_reassembly_manager.invalidate_remote_policy(signer)
                self._schc_peer_context_issuances.pop(id(previous), None)
            peer = AuthenticatedPeerSchcContext._issue_from_verified_dio(
                option,
                signer,
                owner=self,
            )
            self._schc_peer_contexts[signer] = peer
            self._schc_peer_context_issuances[id(peer)] = _AuthenticatedPeerSchcIssuance(
                facade=peer,
                remote_version=option.version,
                signer_identity=signer,
                key_generation=key_generation,
                admitted_counter=logical_counter(detached.epoch, detached.seqnum),
            )
            return authenticated, peer

    def transact_authenticated_schc_dio(
        self,
        authenticated: AuthenticatedDio,
        *,
        prepare: Callable[
            [DetachedAuthenticatedDio],
            Callable[[AuthenticatedPeerSchcContext], _ELEVATED] | None,
        ],
        consumer_lock: contextlib.AbstractContextManager[object] | None = None,
    ) -> tuple[AuthenticatedPeerSchcContext, _ELEVATED] | None:
        """Atomically commit one DIO's SCHC policy and its prepared consumer.

        Foreign generation leases drain before ``consumer_lock`` is acquired,
        establishing Link-before-consumer lock order. ``prepare`` may validate
        detached evidence and return ``None`` without changing link policy. A
        returned synchronous commit callback runs with both locks held. The
        proposed peer policy is installed before that callback so the callback
        observes the exact policy it is admitting; any callback failure restores
        the previous policy before either lock is released.
        Version-driven sender/receiver invalidation is deferred until the
        callback succeeds, so a rejected routing candidate cannot tear down
        live SCHC sessions.
        """
        from ..rpl.authenticated_dio import (
            AuthenticatedDio,
            _capture_authenticated_dio,
            _detach_authenticated_dio,
        )
        from ..schc.context import AuthenticatedPeerSchcContext
        from ..schc.rules import SCHC_RULE_VERSION_TYPE, SchcRuleVersionOption

        if type(authenticated) is not AuthenticatedDio:
            raise TypeError("authenticated must be an exact AuthenticatedDio")
        prepare_callback = require_sync_callable(prepare, "DIO transaction prepare callback")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            self._receipt_now()
            issued = self._authenticated_dio_issuances.get(id(authenticated))
            if issued is None or issued.facade is not authenticated:
                raise ValueError("authenticated DIO was not issued unchanged by this LinkLayer")
            signer = issued.sender_pubkey
            # Elevation callbacks hold generation leases while running outside
            # this lock.  Waiting releases the condition lock, so every piece
            # of security state used below must be captured and checked again
            # only after all foreign callbacks for this signer have finished.
            self._wait_for_foreign_generation_leases_unlocked(signer)
            self._ensure_persistence_healthy()
            self._receipt_now()
            issued = self._authenticated_dio_issuances.get(id(authenticated))
            if (
                issued is None
                or issued.facade is not authenticated
                or issued.sender_pubkey != signer
            ):
                raise ValueError("authenticated DIO was not issued unchanged by this LinkLayer")
            current = _capture_authenticated_dio(authenticated)
            if (
                current.rx_snapshot is not issued.rx_snapshot
                or current.structural_state != issued.structural_state
                or current.receiving_link_identity is not self._receiving_link_identity
                or current.key_generation is not issued.key_generation
                or signer in self._retired_remote_keys
                or self._key_generations.get(signer) is not issued.key_generation
                or self._pinned_keys.get(PeerIdentity.from_pubkey(signer).iid) != signer
            ):
                raise ValueError("authenticated DIO is stale, mutated, or no longer trusted")
            detached = _detach_authenticated_dio(issued)
            version_options = [
                option for option in detached.options if option.type == SCHC_RULE_VERSION_TYPE
            ]
            if len(version_options) != 1:
                raise ValueError(
                    "authenticated DIO must contain exactly one SCHC Rule Version option"
                )
            option_data = version_options[0].data
            option = SchcRuleVersionOption.from_bytes(
                bytes((SCHC_RULE_VERSION_TYPE, len(option_data))) + option_data
            )
            previous = self._schc_peer_contexts.get(signer)
            previous_issuance = (
                None if previous is None else self._schc_peer_context_issuances.get(id(previous))
            )
            if previous is not None and previous_issuance is None:
                raise ValueError("current SCHC peer context lost its LinkLayer issuance")
            admitted_counter = logical_counter(detached.epoch, detached.seqnum)
            if (
                previous_issuance is not None
                and admitted_counter <= previous_issuance.admitted_counter
            ):
                raise ValueError(
                    "authenticated DIO policy counter is not newer than current policy"
                )

            lock_context = contextlib.nullcontext() if consumer_lock is None else consumer_lock
            with lock_context:
                prepared = cast(
                    Callable[[AuthenticatedPeerSchcContext], _ELEVATED] | None,
                    reject_awaitable_result(
                        prepare_callback(detached),
                        "DIO transaction prepare callback",
                    ),
                )
                if prepared is None:
                    return None
                commit_callback = require_sync_callable(
                    prepared,
                    "DIO transaction commit callback",
                )
                peer = AuthenticatedPeerSchcContext._issue_from_verified_dio(
                    option,
                    signer,
                    owner=self,
                )
                issuance = _AuthenticatedPeerSchcIssuance(
                    facade=peer,
                    remote_version=option.version,
                    signer_identity=signer,
                    key_generation=issued.key_generation,
                    admitted_counter=admitted_counter,
                )
                if previous is not None:
                    self._schc_peer_context_issuances.pop(id(previous), None)
                self._schc_peer_contexts[signer] = peer
                self._schc_peer_context_issuances[id(peer)] = issuance
                try:
                    result = cast(
                        _ELEVATED,
                        reject_awaitable_result(
                            commit_callback(peer),
                            "DIO transaction commit callback",
                        ),
                    )
                except BaseException:
                    self._schc_peer_context_issuances.pop(id(peer), None)
                    if previous is None:
                        self._schc_peer_contexts.pop(signer, None)
                    else:
                        self._schc_peer_contexts[signer] = previous
                        assert previous_issuance is not None
                        self._schc_peer_context_issuances[id(previous)] = previous_issuance
                    raise
                if (
                    previous_issuance is not None
                    and previous_issuance.remote_version != option.version
                ):
                    self._schc_session_manager.invalidate_remote_policy(signer)
                    self._schc_reassembly_manager.invalidate_remote_policy(signer)
                return peer, result

    def _purge_verified_receipts_unlocked(self, now: float | None = None) -> None:
        """Purge expired receipts. Delegates to ReceiptStore."""
        self._receipts.purge(now)

    def _store_verified_receipt_unlocked(
        self,
        facade: RxFrame,
        snapshot: RxFrame,
        *,
        sender_was_pinned: bool,
    ) -> None:
        """Store a verified receipt. Delegates to ReceiptStore."""
        self._receipts.store(facade, snapshot, sender_was_pinned=sender_was_pinned)

    def _take_verified_receipt_entry_unlocked(
        self,
        received: RxFrame,
        purpose: str,
    ) -> _VerifiedReceipt:
        """Take and return the full receipt entry. Delegates to ReceiptStore."""
        return self._receipts.take(received, purpose)

    def _take_verified_receipt_unlocked(self, received: RxFrame, purpose: str) -> RxFrame:
        """Take receipt and return snapshot. Delegates to ReceiptStore."""
        return self._receipts.consume(received, purpose)

    def _consume_verified_receipt_unlocked(self, received: RxFrame, purpose: str) -> RxFrame:
        """Consume receipt and return snapshot. Delegates to ReceiptStore."""
        return self._receipts.consume(received, purpose)

    def consume_verified_receipt(self, received: RxFrame, *, purpose: str) -> RxFrame:
        """Consume an exact LinkLayer-issued frame receipt for one trust purpose.

        Parsers that elevate authenticated wire data into a security-sensitive
        domain value (for example a parsed DIO Time option) must call this on
        the receiving LinkLayer. Merely constructing or copying an ``RxFrame``
        cannot create the corresponding link-owned receipt.
        """
        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            return self._take_verified_receipt_unlocked(received, purpose)

    def elevate_verified_receipt(
        self,
        received: RxFrame,
        *,
        purpose: str,
        elevate: Callable[[RxFrame], _ELEVATED],
    ) -> _ELEVATED:
        """Consume and synchronously elevate a receipt inside the security transaction."""
        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        callback = require_sync_callable(elevate, "receipt elevation callback")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            self._receipt_now()
            snapshot = self._take_verified_receipt_unlocked(received, purpose)
            signer = snapshot.sender_pubkey
            self._acquire_generation_lease_unlocked(signer, snapshot.key_generation)
        try:
            return cast(
                _ELEVATED,
                reject_awaitable_result(callback(snapshot), "receipt elevation callback"),
            )
        finally:
            self._release_generation_lease(signer)

    def apply_authenticated_rekey(self, received: RxFrame) -> None:
        """Consume an old-key-signed rekey receipt and atomically install its new key."""
        if type(received) is not RxFrame:
            raise TypeError("received must be an exact RxFrame")
        self._ensure_persistence_healthy()
        with self._security_lock:
            self._ensure_persistence_healthy()
            evidence = self._take_verified_receipt_entry_unlocked(received, "link-rekey")
            authenticated = evidence.snapshot
            if authenticated.local_pubkey != self._local_pubkey:
                raise ValueError("rekey evidence belongs to a different local identity")
            if not evidence.sender_was_pinned:
                raise ValueError("rekey signer was not trusted before this control frame")
            if not authenticated.payload.startswith(REKEY_CONTROL_PREFIX):
                raise ValueError("authenticated frame is not a rekey control message")
            if len(authenticated.payload) != len(REKEY_CONTROL_PREFIX) + 32:
                raise ValueError("malformed rekey control message")
            old_remote_signer_identity = authenticated.sender_pubkey
            new_remote_signer_identity = authenticated.payload[len(REKEY_CONTROL_PREFIX) :]
            old_peer = PeerIdentity.from_pubkey(old_remote_signer_identity)
            if self._pinned_keys.get(old_peer.iid) != old_remote_signer_identity:
                raise ValueError("rekey signer is not the current pinned identity")
            self._rotate_remote_unlocked(
                old_remote_signer_identity,
                new_remote_signer_identity,
            )
        self._save_persisted_state()

    def _rotate_remote_unlocked(
        self,
        old_remote_signer_identity: bytes,
        new_remote_signer_identity: bytes,
    ) -> None:
        """Install a validated replacement while ``_security_lock`` is held."""
        if type(old_remote_signer_identity) is not bytes or len(old_remote_signer_identity) != 32:
            raise ValueError("old remote signer identity must be 32 bytes")
        if type(new_remote_signer_identity) is not bytes or len(new_remote_signer_identity) != 32:
            raise ValueError("new remote signer identity must be 32 bytes")
        if old_remote_signer_identity == new_remote_signer_identity:
            raise ValueError("key rotation requires a distinct replacement key")
        thread_id = threading.get_ident()
        if any(
            self._generation_lease_owners.get((signer, thread_id), 0)
            for signer in (old_remote_signer_identity, new_remote_signer_identity)
        ):
            raise RuntimeError("cannot rekey from inside a generation elevation callback")
        while any(
            self._generation_leases.get(signer, 0)
            for signer in (old_remote_signer_identity, new_remote_signer_identity)
        ):
            self._generation_condition.wait()
        new_peer = PeerIdentity.from_pubkey(new_remote_signer_identity)
        old_peer = PeerIdentity.from_pubkey(old_remote_signer_identity)
        replacement_occupied = (
            new_remote_signer_identity in self._retired_remote_keys
            or new_peer.iid in self._pinned_keys
            or new_remote_signer_identity in self._rekeyed_peers
            or self.replay_protector.has_state(new_remote_signer_identity)
            or self._schc_session_manager.replacement_occupied(new_remote_signer_identity)
            or self._schc_reassembly_manager.replacement_occupied(new_remote_signer_identity)
        )
        if replacement_occupied:
            raise ValueError("replacement signer identity already has live security state")
        if (
            old_remote_signer_identity not in self._retired_remote_keys
            and len(self._retired_remote_keys) >= MAX_RETIRED_REMOTE_KEYS
        ):
            raise ValueError("retired signer registry is full; administrative recovery required")
        self._schc_session_manager.preflight_rotate_remote(
            old_remote_signer_identity,
            new_remote_signer_identity,
        )
        self.replay_protector._rotate_owned(
            old_remote_signer_identity,
            new_remote_signer_identity,
            self._replay_owner_token,
        )
        self._schc_session_manager.rotate_remote(
            old_remote_signer_identity,
            new_remote_signer_identity,
        )
        self._schc_reassembly_manager.rotate_remote(
            old_remote_signer_identity,
            new_remote_signer_identity,
        )
        self._retired_remote_keys.add(old_remote_signer_identity)
        self._key_generations.pop(old_remote_signer_identity, None)
        self._key_generations[new_remote_signer_identity] = object()
        self._rekeyed_peers.pop(old_remote_signer_identity, None)
        self._rekeyed_peers[new_remote_signer_identity] = new_peer
        stale_receipts = [
            receipt_id
            for receipt_id, receipt in self._verified_receipts.items()
            if receipt.snapshot.sender_pubkey
            in (old_remote_signer_identity, new_remote_signer_identity)
        ]
        for receipt_id in stale_receipts:
            self._verified_receipts.pop(receipt_id, None)
        stale_dios = [
            issuance_id
            for issuance_id, issuance in self._authenticated_dio_issuances.items()
            if issuance.sender_pubkey in (old_remote_signer_identity, new_remote_signer_identity)
        ]
        for issuance_id in stale_dios:
            self._authenticated_dio_issuances.pop(issuance_id, None)
        self._pinned_keys.pop(old_peer.iid, None)
        self._pinned_keys[new_peer.iid] = new_peer.pubkey
        self._pinned_keys.move_to_end(new_peer.iid)
        for signer in (old_remote_signer_identity, new_remote_signer_identity):
            stale_peer = self._schc_peer_contexts.pop(signer, None)
            if stale_peer is not None:
                self._schc_peer_context_issuances.pop(id(stale_peer), None)

    def _next_seqnum(self) -> tuple[int, int]:
        """Get next (epoch, seqnum) pair and advance the counter.

        Why internal: Sequence management is link layer's responsibility.
        Upper layers should not manipulate sequence numbers.

        Returns:
            (epoch, seqnum) for the next frame.
        """
        if self._exhausted:
            logger.error("tuple space exhausted; key rotation required before further TX")
            # Fail closed per e220
            raise OverflowError("link tuple exhaustion")

        epoch, seqnum = self._epoch, self._seqnum
        self._sequence_started = True

        # Advance for next call
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._exhausted = True
        elif seqnum == 0xFFFF:
            # Why wrap handling: seqnum is 16-bit, epoch is 8-bit
            # Together they form a 24-bit monotonic counter
            self._seqnum = 0
            self._epoch += 1
            logger.debug("epoch wrapped to %d", self._epoch)
            if self._epoch == 0:
                self._exhausted = True
                logger.warning("24-bit tuple space exhausted; will trigger rotation on next load")
        else:
            self._seqnum += 1

        self._save_persisted_state()
        return epoch, seqnum

    def _build_signable_data(
        self,
        epoch: int,
        seqnum: int,
        dst_addr: bytes,
        payload: bytes,
        length: int | None = None,
        llsec: int | None = None,
        signer_eui64: bytes | None = None,
    ) -> bytes:
        """Construct the data that gets signed.

        Why explicit: The signature must cover all immutable fields. This
        function documents exactly what is signed, preventing subtle bugs
        where fields are added but not covered by the signature.

        Signed fields follow link transcript domain version 1 exactly:
        LINK_SIGNATURE_DOMAIN || LENGTH || LLSec || EPO || SEQ || DST_LEN(1)
        || DST || SIID || PLD.

        Returns:
            Bytes to be signed.
        """
        if llsec is None:
            llsec = int(AddrMode.NONE) | (1 << 5) | (1 << 7)
        signature_present = bool(llsec & (1 << 5))
        signer_eui64_present = bool(llsec & (1 << 7))
        if signature_present != signer_eui64_present:
            raise ValueError("signature and signer EUI-64 presence bits must match")
        if signer_eui64 is None:
            signer_eui64 = self._local_eui64 if signer_eui64_present else b""
        if len(signer_eui64) != (8 if signer_eui64_present else 0):
            raise ValueError("signer EUI-64 length does not match LLSec SI bit")
        if length is None:
            length = (
                4
                + len(dst_addr)
                + len(signer_eui64)
                + len(payload)
                + (SIGNATURE_LENGTH if signature_present else 0)
            )
        return (
            LINK_SIGNATURE_DOMAIN
            + bytes([length, llsec, epoch])
            + seqnum.to_bytes(2, "big")
            + bytes([len(dst_addr)])
            + dst_addr
            + signer_eui64
            + payload
        )

    async def send(
        self,
        payload: bytes,
        dst_addr: bytes = b"",
        addr_mode: AddrMode = AddrMode.NONE,
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
    ) -> bool:
        """Queue and transmit one frame while serializing TX state."""
        async with self._tx_lock:
            return await self._send_locked(payload, dst_addr, addr_mode, priority, deadline_ms)

    async def _send_locked(
        self,
        payload: bytes,
        dst_addr: bytes = b"",
        addr_mode: AddrMode = AddrMode.NONE,
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
    ) -> bool:
        """Build, enqueue, and drain while the TX lock is held.

        Args:
            payload: The data to send (typically SCHC-compressed packet).
            dst_addr: Destination address. Length must match addr_mode:
                NONE/ELIDED require empty (b''), SHORT requires 2 bytes,
                EXTENDED requires 8 bytes. ELIDED means address is derived
                from upper-layer IPv6 destination by the receiver.
            addr_mode: How to encode the destination.
            priority: Queue priority (ROUTING, ACK, URGENT, or BULK).
            deadline_ms: Absolute deadline in ms. If None, uses default
                         for the priority level.

        Raises:
            QueueFullError: If queue is full and cannot preempt lower priority.
            FrameError: If the frame cannot be constructed (e.g., too large).
            ValueError: If dst_addr length does not match addr_mode.
        """
        self._ensure_persistence_healthy()
        if self._exhausted:
            raise OverflowError("link tuple exhaustion")
        from ..l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body

        if (
            classify_l2_payload(payload) is L2PayloadKind.SCHC
            and (wrapped_body := l2_payload_body(payload))
            and wrapped_body[0] in (0x78, 0x79)
        ):
            raise ValueError("SCHC fragmentation Rules 0x78/0x79 are raw link dispatches")
        if payload and payload[0] in (0x78, 0x79):
            from ..schc.fragment import (
                Ack,
                FragmentError,
                _IssuedFragmentWire,
                ack_request,
                receiver_abort,
                sender_abort,
            )

            if addr_mode is not AddrMode.EXTENDED:
                raise ValueError("SCHC fragmentation requires an Extended-unicast destination")

            if type(payload) is not _IssuedFragmentWire:
                raise ValueError(
                    "SCHC fragmentation emission requires a manager-issued one-use wire"
                )
            wire_bytes = bytes(payload)
            window = wire_bytes[1] >> 7 if len(wire_bytes) >= 2 else 0
            is_control = wire_bytes in (
                ack_request(wire_bytes[0], window),
                sender_abort(wire_bytes[0]),
                receiver_abort(wire_bytes[0]),
            )
            if not is_control:
                try:
                    Ack.from_bytes(wire_bytes)
                except FragmentError:
                    pass
                else:
                    is_control = True
            if is_control and priority is not Priority.ACK:
                raise ValueError("SCHC fragmentation controls require ACK priority")
            if not self._schc_session_manager.consume_fragment_wire(payload, dst_addr):
                raise ValueError(
                    "fragment wire is stale, wrong-target, or not issued by this session"
                )
            # The manager-owned bytes subclass is only a one-use authority
            # token.  Serialize/sign an exact built-in bytes snapshot.
            payload = wire_bytes
        # Validate dst_addr length matches addr_mode early
        expected_len = addr_mode.addr_len
        if len(dst_addr) != expected_len:
            raise ValueError(
                f"dst_addr is {len(dst_addr)} bytes but {addr_mode.name} "
                f"requires {expected_len} bytes"
            )

        # Validate frame fits on-air size constraint BEFORE signing
        frame_length = 4 + len(dst_addr) + len(self._local_eui64) + len(payload) + SIGNATURE_LENGTH
        if frame_length > MAX_FRAME_BODY:
            raise FrameError(f"frame body is {frame_length} bytes, exceeds {MAX_FRAME_BODY}")

        # Peek at current sequence numbers without consuming
        # Why peek first: If push() raises QueueFullError, we don't want to
        # waste a sequence number. Only consume after successful push.
        epoch, seqnum = self._epoch, self._seqnum

        llsec = int(addr_mode) | (1 << 5) | (1 << 7)
        signable = self._build_signable_data(
            epoch,
            seqnum,
            dst_addr,
            payload,
            frame_length,
            llsec,
            self._local_eui64,
        )
        signature = sign(self._local_privkey, self._local_pubkey, signable)

        frame = LichenFrame(
            epoch=epoch,
            seqnum=seqnum,
            dst_addr=dst_addr,
            payload=payload,
            mic=signature,
            addr_mode=addr_mode,
            mic_length=MicLength.BITS32,
            signature_present=True,
            encrypted=False,
            signer_eui64=self._local_eui64,
        )

        frame_bytes = frame.to_bytes()

        logger.debug(
            "TX queue: epoch=%d seqnum=%d dst=%s payload=%d bytes priority=%s",
            epoch,
            seqnum,
            dst_addr.hex() if dst_addr else "broadcast",
            len(payload),
            priority.name,
        )

        # Queue with per-entry reservation for concurrent safety and specific completion
        reservation = self.tx_queue.push(
            frame_bytes,
            priority=priority,
            deadline_ms=deadline_ms,
            return_reservation=True,
        )
        assert reservation is not None, "push with reservation failed"

        try:
            # Push succeeded - now consume the sequence number.
            self._next_seqnum()

            # Drain while serialized by _tx_lock. Every exit either resolves
            # this exact reservation or the exception cleanup removes it.
            await self._drain_tx_queue_locked()
            return await reservation.wait()
        except BaseException:
            self.tx_queue.cancel_reservation(reservation)
            raise

    async def drain_tx_queue(self) -> bool:
        """Drain pending frames while serializing all radio transmission."""
        async with self._tx_lock:
            self._ensure_persistence_healthy()
            return await self._drain_tx_queue_locked()

    async def _drain_tx_queue_locked(self) -> bool:
        """Drain pending frames; caller must hold ``_tx_lock``."""
        transmitted_any = False
        while True:
            self.tx_queue.expire_stale()
            if len(self.tx_queue) == 0:
                break  # Queue empty
            if self.cad_enabled and not await self._wait_for_clear_channel():
                logger.warning(
                    "TX deferred: channel busy after %d backoff cycles, %d packets remain queued",
                    CAD_MAX_CYCLES,
                    len(self.tx_queue),
                )
                # False is terminal: remove every untransmitted frame so a
                # caller retry cannot later be delivered alongside the stale
                # original under a distinct replay counter.
                self.tx_queue.clear()
                break
            entry = self.tx_queue.reserve()
            if entry is None:
                break
            try:
                transmitted = await self.radio.transmit(entry.data)
            except BaseException:
                self.tx_queue.fail(entry)
                self.tx_queue.clear()
                raise
            if transmitted:
                transmitted_any = True
                logger.debug(
                    "TX success, %d packets remain queued",
                    len(self.tx_queue),
                )
                self.tx_queue.complete(entry, True)
            else:
                logger.warning("TX radio transmit failed")
                self.tx_queue.fail(entry)
                self.tx_queue.clear()
                break
        return transmitted_any

    async def _wait_for_clear_channel(self) -> bool:
        """Perform CAD with exponential backoff until channel is clear.

        Algorithm: For each cycle, attempt CAD with increasing backoff.
        - attempt 0: CAD, if busy wait 0 slots (immediate retry)
        - attempt 1: CAD, if busy wait 0-1 slots
        - attempt 2: CAD, if busy wait 0-3 slots
        - ...
        - attempt 5: CAD, if busy wait 0-31 slots (max)

        If we complete CAD_MAX_BACKOFF_EXPONENT attempts and still busy,
        that's one cycle. After CAD_MAX_CYCLES full cycles, give up.

        Note: radio.cad() False now documented as clear (timeout conflated per
        P4 design in project-LICHEN-b4pw); treats timeout as clear for TX.

        Returns:
            True if channel became clear, False after max retries.
        """
        max_slots = (1 << CAD_MAX_BACKOFF_EXPONENT) - 1  # 31

        for cycle in range(CAD_MAX_CYCLES):
            for attempt in range(CAD_MAX_BACKOFF_EXPONENT + 1):
                channel_busy = await self.radio.cad(LORA_CAD_TIMEOUT_MS)

                if not channel_busy:
                    logger.debug(
                        "CAD clear: cycle=%d attempt=%d",
                        cycle,
                        attempt,
                    )
                    return True

                # Channel busy - compute backoff
                # Window size: 2^attempt, capped at 2^max_exponent
                window = min(1 << attempt, max_slots + 1)
                slots = random.randint(0, window - 1)
                backoff_ms = slots * CAD_SLOT_MS

                logger.debug(
                    "CAD busy: cycle=%d attempt=%d backoff=%dms (%d slots)",
                    cycle,
                    attempt,
                    backoff_ms,
                    slots,
                )

                if backoff_ms > 0:
                    await asyncio.sleep(backoff_ms / 1000.0)

        return False

    async def receive(self, timeout_ms: int) -> RxFrame | ReceiveError | None:
        """Receive and validate a frame.

        Why async: Radio reception blocks until a packet arrives or timeout.

        Validation steps (in order):
        1. Parse frame structure
        2. Extract signature from mic field (when signature_present)
        3. Look up sender by IID (reject if unknown)
        4. Verify signature (reject if invalid) — signature covers frame integrity
        5. Pin sender key (TOFU) after successful signature verification
        6. Check replay protection (reject if replay)

        Args:
            timeout_ms: Maximum time to wait for a frame, in milliseconds.

        Returns:
            RxFrame on success, ReceiveError on validation failure, None on timeout.
            problem where all failures collapsed to None; callers can now
            distinguish security events from malformed frames from timeouts.
        """
        self._ensure_persistence_healthy()
        result = await self.radio.receive(timeout_ms)
        if result is None:
            return None

        raw_bytes, rssi_dbm, snr_db = result
        received_monotonic = self._receipt_now()

        # Step 1: Parse frame structure
        try:
            frame = LichenFrame.from_bytes(raw_bytes)
        except EncryptedFrameError:
            global _encrypted_frame_warned
            if not _encrypted_frame_warned:
                logger.warning(
                    "Encrypted frames NOT SUPPORTED - rejecting. "
                    "Encryption is not implemented; frames with encrypted=True are dropped."
                )
                _encrypted_frame_warned = True
            else:
                logger.debug("RX encrypted frame rejected (encryption not implemented)")
            return ReceiveError.ENCRYPTED
        except FrameError as e:
            logger.warning("RX malformed frame: %s", e)
            return ReceiveError.MALFORMED

        # Why check signature_present: Unsigned frames are not authenticated.
        # In a real deployment, we might accept them for specific purposes
        # (e.g., discovery), but for now we require signatures.
        if not frame.signature_present:
            logger.warning("RX unsigned frame rejected (policy requires signatures)")
            return ReceiveError.UNSIGNED

        # S=1 makes the MIC field the 48-byte Schnorr signature.
        signature = frame.mic
        inner_payload = frame.payload

        # Step 3: Resolve the mandatory Signer Identifier. SIID carries the
        # signer's canonical EUI-64, enabling indexed peer lookup; the bounded
        # exhaustive callback is only a compatibility fallback for stores that
        # cannot resolve that identifier directly.
        sender = self._find_sender(frame, signature, inner_payload)
        if sender is None:
            logger.warning("RX frame from unknown sender or bad signature")
            return ReceiveError.BAD_SIGNATURE

        # Destination admission is deliberately after authentication (ELIDED
        # decoding may depend on canonical SCHC parsing) but before replay,
        # TOFU, receipts, or any protocol allocation.
        if not self._wire_is_for_local(frame):
            logger.debug("RX authenticated frame is not addressed to this node")
            return ReceiveError.NOT_FOR_US

        # Step 4 happened inside _find_sender (signature verification)

        # Step 4.5 through replay acceptance are one security transaction. This
        # linearizes session-baseline capture against receive acceptance.
        # Why verify: The signature in _find_sender already authenticated the
        # sender's pubkey. Key pinning detects key changes for the same IID.
        with self._security_lock:
            self._ensure_persistence_healthy()
            self._purge_verified_receipts_unlocked(received_monotonic)
            if sender.pubkey in self._retired_remote_keys:
                logger.error("RX frame signed by retired peer key %s", sender.iid.hex())
                return ReceiveError.KEY_CHANGE
            pinned_pk = self._pinned_keys.get(sender.iid)
            sender_was_pinned = pinned_pk == sender.pubkey
            if pinned_pk is not None and pinned_pk != sender.pubkey:
                logger.error(
                    "link-layer KEY CHANGE DETECTED for IID %s: pinned=%s got=%s",
                    sender.iid.hex(),
                    pinned_pk.hex()[:16],
                    sender.pubkey.hex()[:16],
                )
                return ReceiveError.KEY_CHANGE

            # Establish capacity before touching replay or trust state.  If
            # every existing pin is protected by a live generation lease, a
            # new signer cannot be admitted durably and must fail atomically.
            evictable_pin: tuple[bytes, bytes] | None = None
            if pinned_pk is None and len(self._pinned_keys) >= MAX_ENTRIES:
                evictable_pin = next(
                    (
                        (iid, pubkey)
                        for iid, pubkey in self._pinned_keys.items()
                        if not self._peer_has_eviction_blocker_unlocked(pubkey)
                    ),
                    None,
                )
                if evictable_pin is None:
                    logger.error("RX TOFU pin capacity exhausted; failing closed")
                    return ReceiveError.CAPACITY_EXHAUSTED

            # Every over-air frame, including a frame signed by our own key, is
            # replay checked. Internal loopback must use a separate local API.
            try:
                fresh = self.replay_protector._check_and_update_owned(
                    sender.pubkey,
                    frame.epoch,
                    frame.seqnum,
                    self._replay_owner_token,
                )
            except ReplayCapacityError:
                logger.error("RX replay state capacity exhausted; failing closed")
                return ReceiveError.CAPACITY_EXHAUSTED
            if not fresh:
                logger.warning(
                    "RX replay detected: epoch=%d seqnum=%d sender=%s",
                    frame.epoch,
                    frame.seqnum,
                    sender.iid.hex(),
                )
                return ReceiveError.REPLAY

            # Pin only after replay admission succeeds.  A capacity-rejected
            # peer must not change the TOFU table or its eviction order.
            if evictable_pin is not None:
                evicted_iid, evicted_pubkey = evictable_pin
                self._retire_evicted_peer_unlocked(evicted_iid, evicted_pubkey)
            self._pinned_keys[sender.iid] = sender.pubkey
            self._pinned_keys.move_to_end(sender.iid)
            key_generation = self._key_generations.setdefault(sender.pubkey, object())

            canonical_sender = PeerIdentity.from_pubkey(sender.pubkey)
            received = object.__new__(RxFrame)
            object.__setattr__(received, "sender", canonical_sender)
            object.__setattr__(received, "rssi_dbm", rssi_dbm)
            object.__setattr__(received, "snr_db", snr_db)
            object.__setattr__(received, "_authenticated_payload", bytes(inner_payload))
            object.__setattr__(received, "_authenticated_sender_pubkey", sender.pubkey)
            object.__setattr__(received, "_authenticated_local_pubkey", self._local_pubkey)
            object.__setattr__(received, "_authenticated_epoch", frame.epoch)
            object.__setattr__(received, "_authenticated_seqnum", frame.seqnum)
            object.__setattr__(received, "_authenticated_dst_addr", bytes(frame.dst_addr))
            object.__setattr__(received, "_authenticated_signer_eui64", bytes(frame.signer_eui64))
            object.__setattr__(received, "_authenticated_mic", bytes(frame.mic))
            object.__setattr__(received, "_authenticated_addr_mode", frame.addr_mode)
            object.__setattr__(received, "_authenticated_mic_length", frame.mic_length)
            object.__setattr__(received, "_authenticated_signature_present", True)
            object.__setattr__(received, "_authenticated_encrypted", False)
            object.__setattr__(received, "_authenticated_received_monotonic", received_monotonic)
            object.__setattr__(
                received,
                "_authenticated_clock_domain",
                self.clock_domain_identity,
            )
            object.__setattr__(received, "_authenticated_key_generation", key_generation)
            object.__setattr__(
                received,
                "_authenticated_receiving_link_identity",
                self._receiving_link_identity,
            )

            # Keep a detached, unexposed snapshot behind the one-use receipt.
            # Timing and other security-sensitive consumers receive this copy,
            # so mutating the caller-visible frozen object via object.__setattr__
            # cannot alter elevated evidence.
            snapshot = object.__new__(RxFrame)
            object.__setattr__(snapshot, "sender", PeerIdentity.from_pubkey(sender.pubkey))
            object.__setattr__(snapshot, "rssi_dbm", rssi_dbm)
            object.__setattr__(snapshot, "snr_db", snr_db)
            for attribute in (
                "_authenticated_payload",
                "_authenticated_sender_pubkey",
                "_authenticated_local_pubkey",
                "_authenticated_epoch",
                "_authenticated_seqnum",
                "_authenticated_dst_addr",
                "_authenticated_signer_eui64",
                "_authenticated_mic",
                "_authenticated_addr_mode",
                "_authenticated_mic_length",
                "_authenticated_signature_present",
                "_authenticated_encrypted",
                "_authenticated_received_monotonic",
                "_authenticated_clock_domain",
                "_authenticated_key_generation",
                "_authenticated_receiving_link_identity",
            ):
                object.__setattr__(snapshot, attribute, getattr(received, attribute))
            self._store_verified_receipt_unlocked(
                received,
                snapshot,
                sender_was_pinned=sender_was_pinned,
            )
            self._schc_session_manager.record_verified_frame(received)
        self._save_persisted_state()

        # Success! Return the validated frame
        logger.debug(
            "RX valid frame: epoch=%d seqnum=%d sender=%s payload=%d bytes",
            frame.epoch,
            frame.seqnum,
            sender.iid.hex(),
            len(inner_payload),
        )

        return received

    def _find_sender(
        self,
        frame: LichenFrame,
        signature: bytes,
        payload: bytes,
    ) -> PeerIdentity | None:
        """Find the sender selected by its authenticated wire EUI-64.

        The mandatory SIID field carries the signer's canonical EUI-64. It is
        converted to the key-derived IID for the indexed lookup, then checked
        again against each candidate before signature verification. The
        exhaustive callback remains a bounded compatibility path for stores
        that cannot resolve the indexed hint.

        Returns:
            PeerIdentity if found and signature valid, None otherwise.
        """
        signable = self._build_signable_data(
            frame.epoch,
            frame.seqnum,
            frame.dst_addr,
            payload,
            4 + len(frame.dst_addr) + len(frame.signer_eui64) + len(payload) + SIGNATURE_LENGTH,
            frame.llsec_byte(),
            frame.signer_eui64,
        )

        # Why try self first: In loopback/testing scenarios, we might receive
        # our own broadcasts. Check self before iterating peers.
        if frame.signer_eui64 == self._local_eui64 and verify(
            self._local_pubkey, signable, signature
        ):
            # It's from us - might be a loopback or echo
            logger.debug("RX frame from self (loopback)")
            return PeerIdentity.from_pubkey(self._local_pubkey)

        with self._security_lock:
            rekeyed_candidates = tuple(self._rekeyed_peers.values())
        for candidate in rekeyed_candidates:
            canonical = self._canonical_peer_candidate(candidate)
            if (
                canonical is not None
                and iid_to_eui64(canonical.iid) == frame.signer_eui64
                and verify(canonical.pubkey, signable, signature)
            ):
                return canonical

        try:
            hinted = self._canonical_peer_candidate(
                self.peer_lookup(eui64_to_iid(frame.signer_eui64))
            )
        except Exception:
            hinted = None
        if (
            hinted is not None
            and iid_to_eui64(hinted.iid) == frame.signer_eui64
            and verify(hinted.pubkey, signable, signature)
        ):
            return hinted

        # Exhaustive compatibility lookup. Every candidate still has to match
        # the authenticated wire EUI-64 before its signature is attempted.
        if self.peer_lookup_all is not None:
            try:
                candidates = self.peer_lookup_all()
            except Exception:
                return None
            if type(candidates) is not list or len(candidates) > MAX_ENTRIES:
                return None
            candidate_snapshot = candidates.copy()
            if len(candidate_snapshot) > MAX_ENTRIES:
                return None
            for candidate in candidate_snapshot:
                canonical = self._canonical_peer_candidate(candidate)
                if (
                    canonical is not None
                    and iid_to_eui64(canonical.iid) == frame.signer_eui64
                    and verify(canonical.pubkey, signable, signature)
                ):
                    return canonical

        # Bounded zero-hop Announce bootstrap.  An unknown link signer may
        # introduce exactly its own key only through the routing dispatch and
        # canonical Announce structure.  Both the inner Announce transcript
        # and the outer link transcript must verify before replay/TOFU state is
        # touched by ``receive``.  Relayed announces cannot bootstrap their
        # (different) outer signer.
        try:
            from lichen.announce.messages import AnnounceError, AnnounceMessage
            from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body

            body = l2_payload_body(payload)
            if classify_l2_payload(payload) is not L2PayloadKind.ROUTING:
                return None
            announce = AnnounceMessage.from_bytes(body)
            candidate = PeerIdentity.from_pubkey(announce.pubkey)
        except (AnnounceError, TypeError, ValueError):
            return None
        if (
            announce.hop_count != 0
            or announce.originator_iid != candidate.iid
            or frame.signer_eui64 != iid_to_eui64(candidate.iid)
            or not verify(candidate.pubkey, announce.signed_data(), announce.signature)
            or not verify(candidate.pubkey, signable, signature)
        ):
            return None
        return candidate

    @staticmethod
    def _canonical_peer_candidate(candidate: object) -> PeerIdentity | None:
        """Snapshot exactly one callback-owned key and detach all later use."""
        try:
            pubkey = cast(_PeerCandidate, candidate).pubkey
        except Exception:
            return None
        if type(pubkey) is not bytes or len(pubkey) != 32:
            return None
        try:
            return PeerIdentity.from_pubkey(bytes(pubkey))
        except ValueError:
            return None

    def set_sequence(self, epoch: int, seqnum: int) -> None:
        """Set the sequence counter (for persistence across restarts).

        Why exposed: Sequence numbers must be monotonic across reboots to
        prevent replay attacks against peers who cached our old counter.
        The caller should persist and restore these values.

        Args:
            epoch: 8-bit epoch.
            seqnum: 16-bit sequence number.

        Raises:
            ValueError: If values are out of range.
            RuntimeError: If any frame has already been accepted for transmission.
        """
        self._ensure_persistence_healthy()
        if not 0 <= epoch <= 0xFF:
            raise ValueError(f"epoch out of range: {epoch}")
        if not 0 <= seqnum <= 0xFFFF:
            raise ValueError(f"seqnum out of range: {seqnum}")
        if self._exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        if self._sequence_started:
            raise RuntimeError("link-layer sequence cannot be reset after use")
        self._epoch = epoch
        self._seqnum = seqnum
        if epoch == 0xFF and seqnum == 0xFFFF:
            self._exhausted = True
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        logger.info("sequence set to epoch=%d seqnum=%d", epoch, seqnum)

    def get_sequence(self) -> tuple[int, int]:
        """Get current sequence counter (for persistence).

        Returns:
            (epoch, seqnum) tuple.
        """
        self._ensure_persistence_healthy()
        if self._exhausted:
            raise OverflowError("link-layer sequence exhausted; rotate identity key")
        return self._epoch, self._seqnum

    def _load_persisted_state(self) -> None:
        """Load persisted state. Delegates to LinkPersistence."""
        self._persistence.load_state()

    def _save_persisted_state(self) -> None:
        """Persist or disable on failure. Delegates to LinkPersistence."""
        self._persistence.save_state()

    def _ensure_persistence_healthy(self) -> None:
        """Verify persistence is healthy. Delegates to LinkPersistence."""
        self._persistence.ensure_healthy()

    def _restore_security_state(self, state: dict[str, object]) -> None:
        required_v3 = {
            "format",
            "revision",
            "local_pubkey",
            "epoch",
            "seqnum",
            "exhausted",
            "pinned_keys",
            "rekeyed_peers",
            "retired_remote_keys",
            "replay",
            "schc_sessions",
        }
        required_v4 = required_v3 | {"schc_reassembly"}
        if not (
            (state.get("format") == 3 and set(state) == required_v3)
            or (state.get("format") == 4 and set(state) == required_v4)
        ):
            raise RuntimeError("invalid link security persistence schema")
        if state["local_pubkey"] != self._local_pubkey.hex():
            raise RuntimeError("link security persistence belongs to another identity")
        epoch, seqnum, exhausted = state["epoch"], state["seqnum"], state["exhausted"]
        if (
            type(epoch) is not int
            or not 0 <= epoch <= 0xFF
            or type(seqnum) is not int
            or not 0 <= seqnum <= 0xFFFF
            or type(exhausted) is not bool
        ):
            raise RuntimeError("invalid persisted transmit counter")
        raw_pins_value = state["pinned_keys"]
        raw_rekeyed_value = state["rekeyed_peers"]
        raw_retired_value = state["retired_remote_keys"]
        if not all(
            type(value) is list for value in (raw_pins_value, raw_rekeyed_value, raw_retired_value)
        ):
            raise RuntimeError("invalid persisted trust tables")
        raw_pins = cast(list[object], raw_pins_value)
        raw_rekeyed = cast(list[object], raw_rekeyed_value)
        raw_retired = cast(list[object], raw_retired_value)
        pins: OrderedDict[bytes, bytes] = OrderedDict()
        for item in raw_pins:
            if type(item) is not list or len(item) != 2 or not all(type(v) is str for v in item):
                raise RuntimeError("invalid persisted pin")
            iid, pubkey = bytes.fromhex(item[0]), bytes.fromhex(item[1])
            peer = PeerIdentity.from_pubkey(pubkey)
            if len(iid) != 8 or peer.iid != iid or iid in pins:
                raise RuntimeError("invalid persisted pin")
            pins[iid] = pubkey
        rekeyed = [bytes.fromhex(value) for value in raw_rekeyed if type(value) is str]
        retired = {bytes.fromhex(value) for value in raw_retired if type(value) is str}
        if (
            len(rekeyed) != len(raw_rekeyed)
            or len(set(rekeyed)) != len(rekeyed)
            or len(retired) != len(raw_retired)
            or len(pins) > MAX_ENTRIES
            or len(rekeyed) > MAX_ENTRIES
            or len(retired) > MAX_RETIRED_REMOTE_KEYS
            or any(len(value) != 32 for value in (*rekeyed, *retired))
            or retired.intersection(rekeyed)
            or retired.intersection(pins.values())
            or any(pins.get(PeerIdentity.from_pubkey(value).iid) != value for value in rekeyed)
        ):
            raise RuntimeError("invalid persisted trust tables")
        self.replay_protector._import_owned(state["replay"], self._replay_owner_token)
        self._epoch = epoch
        self._seqnum = seqnum
        self._exhausted = exhausted
        self._pinned_keys = pins
        self._rekeyed_peers = {pubkey: PeerIdentity.from_pubkey(pubkey) for pubkey in rekeyed}
        self._retired_remote_keys = retired
        self._key_generations = {pubkey: object() for pubkey in pins.values()}
        try:
            self._schc_session_manager.restore_persistence_state(
                state["schc_sessions"], self._key_generations
            )
            self._schc_reassembly_manager.restore_persistence_state(
                state.get("schc_reassembly", []),
                self._key_generations,
                self.replay_protector.highest,
            )
        except Exception as exc:
            raise RuntimeError("invalid persisted SCHC session state") from exc
        # A restored counter has already been made durable and may have been
        # observed by peers.  It must never be reset through set_sequence().
        self._sequence_started = True

    # Protocol methods for LinkPersistence (SecurityStateExporter, SecurityStateRestorer,
    # PersistenceFailureHandler)

    def export_state(self) -> dict[str, object]:
        """Export current security state for persistence (SecurityStateExporter protocol)."""
        replay_state = self.replay_protector.export_state()
        replay_state["pins"] = []
        replay_state["windows"] = [
            window
            for window in cast(list[dict[str, object]], replay_state["windows"])
            if cast(int, window["highest"]) >= 0
        ]
        return {
            "format": 4,
            "local_pubkey": self._local_pubkey.hex(),
            "epoch": self._epoch,
            "seqnum": self._seqnum,
            "exhausted": self._exhausted,
            "pinned_keys": [
                [iid.hex(), pubkey.hex()] for iid, pubkey in self._pinned_keys.items()
            ],
            "rekeyed_peers": [pubkey.hex() for pubkey in self._rekeyed_peers],
            "retired_remote_keys": sorted(pubkey.hex() for pubkey in self._retired_remote_keys),
            "replay": replay_state,
            "schc_sessions": self._schc_session_manager.export_persistence_state(),
            "schc_reassembly": self._schc_reassembly_manager.export_persistence_state(),
        }

    def export_bootstrap_state(self) -> dict[str, object]:
        """Export initial bootstrap state for persistence (SecurityStateExporter protocol)."""
        replay_state = self.replay_protector.export_state()
        replay_state["pins"] = []
        return {
            "format": 4,
            "local_pubkey": self._local_pubkey.hex(),
            "epoch": self._epoch,
            "seqnum": self._seqnum,
            "exhausted": self._exhausted,
            "pinned_keys": [],
            "rekeyed_peers": [],
            "retired_remote_keys": [],
            "replay": replay_state,
            "schc_sessions": self._schc_session_manager.export_persistence_state(),
            "schc_reassembly": self._schc_reassembly_manager.export_persistence_state(),
        }

    def restore_state(self, state: dict[str, object]) -> None:
        """Restore security state from persistence (SecurityStateRestorer protocol)."""
        self._restore_security_state(state)

    def on_persistence_failure(self) -> None:
        """Handle terminal persistence failure (PersistenceFailureHandler protocol)."""
        with self._security_lock:
            thread_id = threading.get_ident()
            owns_lease = any(
                owner_thread == thread_id and count > 0
                for (_signer, owner_thread), count in self._generation_lease_owners.items()
            )
            while self._generation_leases and not owns_lease:
                self._generation_condition.wait()
            self._exhausted = True
            self.tx_queue.clear()
            self._verified_receipts.clear()
            self._authenticated_dio_issuances.clear()
            self._schc_session_manager.fail_closed()
            self._schc_reassembly_manager.fail_closed()
            self._schc_peer_contexts.clear()
            self._schc_peer_context_issuances.clear()
            self._key_generations.clear()
