# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node handoff protocol for multi-gateway coordination (GCP-7).

Per spec section 08-gateway-coordination.md GCP-7, when a node moves between
gateways (detected via better parent/RSSI):

1. Node sends DAO to new Gateway B
2. B sends POST /handoff to A (via backbone) with node details
3. A releases node from its registry, sends confirmation
4. B confirms handoff to node via CoAP
5. Routes updated in RPL DODAG

State transferred includes:
- Node IPv6 address (derived from Ed25519 IID)
- Recent sequence numbers (DAO, OSCORE sender/recipient)
- Security contexts (OSCORE parameters, replay windows)
- Path sequence and freshness state

SECURITY: Handoff messages MUST be authenticated via OSCORE (PSK mode for
closed federation, signatures for open federation per GCP-3). Unauthenticated
handoff requests enable node hijacking attacks.

SECURITY: Sequence numbers MUST be transferred accurately. Gaps cause replay
acceptance; duplicates cause legitimate messages to be rejected. The receiving
gateway MUST use a sequence number strictly greater than the transferred value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import sha256
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Any

import cbor2

from lichen.crypto import schnorr48
from lichen.crypto.identity import _pubkey_to_iid
from lichen.ipv6 import to_ipv6

if TYPE_CHECKING:
    from lichen.crypto.identity import Identity


class HandoffError(Exception):
    """Base exception for handoff protocol errors."""


class HandoffRejectReason(IntEnum):
    """Reasons a handoff request may be rejected."""

    # Success (not an error, included for completeness)
    SUCCESS = 0

    # Node not found in source gateway's registry
    NODE_NOT_FOUND = 1

    # Node is currently in active communication (retry later)
    NODE_BUSY = 2

    # Authentication failed (OSCORE verification)
    AUTH_FAILED = 3

    # Malformed request payload
    MALFORMED_REQUEST = 4

    # Source gateway internal error
    INTERNAL_ERROR = 5

    # Rate limited (too many handoff requests)
    RATE_LIMITED = 6


# CBOR map keys for handoff request/response (short keys for constrained links)
# Request keys
_KEY_NODE_ADDR = 1  # Node IPv6 address (bytes)
_KEY_DAO_SEQ = 2  # DAO sequence number (int)
_KEY_PATH_SEQ = 3  # Path sequence number (int)
_KEY_OSCORE_PARAMS = 4  # OSCORE context parameters (map)
_KEY_OSCORE_SENDER_SEQ = 5  # OSCORE sender sequence number (int)
_KEY_OSCORE_REPLAY = 6  # OSCORE replay window (array: [index, bitfield])
_KEY_FRESHNESS = 7  # Freshness state (map)
_KEY_PARENTS = 8  # Active parents (array of bytes)
_KEY_RSSI = 9  # Last RSSI from node (int, dBm)
_KEY_TIMESTAMP = 10  # Handoff request timestamp (int, Unix seconds)

# Response keys (use 100+ to avoid collision with request keys)
_KEY_STATUS = 100  # Status code (HandoffRejectReason)
_KEY_MESSAGE = 101  # Human-readable message (text)

# OSCORE parameters subkeys
_KEY_OSCORE_SECRET = 1  # Master secret (bytes)
_KEY_OSCORE_SALT = 2  # Master salt (bytes)
_KEY_OSCORE_SENDER_ID = 3  # Sender ID (bytes)
_KEY_OSCORE_RECIPIENT_ID = 4  # Recipient ID (bytes)
_KEY_OSCORE_ALG = 5  # Algorithm ID (int)
_KEY_OSCORE_HASHFUN = 6  # Hash function name (text)
_KEY_OSCORE_WINDOW = 7  # Window size (int)
_KEY_OSCORE_ID_CTX = 8  # ID context (bytes or null)

# COSE constants per RFC 9052 and spec 08-gateway-coordination.md GCP-7.1
SCHNORR48_ED25519_ALG = -65537
_COSE_ALG = 1
_COSE_KID = 4

# GCP Handoff Request payload keys (CBOR map with integer keys per GCP-7.1)
_REQ_NODE = 1  # node: bstr (8) - Node IID being transferred
_REQ_OLD_GW = 2  # old_gw: bstr (8) - Current owner gateway IID
_REQ_SEQ = 3  # seq: uint - Handoff sequence number (monotonic)
_REQ_TS = 4  # ts: uint - Unix timestamp of request
_REQ_EXPIRY = 5  # expiry: uint - Request validity expiry (unix timestamp)
_REQ_RSSI = 6  # rssi: int - RSSI observed by new gateway (dBm)

# GCP Handoff Confirm payload keys (CBOR map with integer keys per GCP-7.1)
_CONF_NODE = 1  # node: bstr (8) - Node IID being transferred
_CONF_NEW_GW = 2  # new_gw: bstr (8) - New owner gateway IID
_CONF_SEQ = 3  # seq: uint - Echoed handoff sequence number
_CONF_TS = 4  # ts: uint - Confirmation timestamp
_CONF_LINK_EPOCH = 5  # link_epoch: uint - Node's link-layer epoch (8-bit)
_CONF_LINK_SEQ = 6  # link_seq: uint - Node's link-layer sequence (16-bit)


@dataclass(frozen=True)
class OscoreState:
    """OSCORE security context state for handoff transfer.

    Contains all parameters needed to reconstruct an equivalent security
    context on the receiving gateway.

    SECURITY: master_secret is sensitive. This structure should only exist
    transiently during handoff and MUST be protected by OSCORE transport.
    """

    master_secret: bytes
    master_salt: bytes
    sender_id: bytes
    recipient_id: bytes
    algorithm: int  # COSE algorithm ID
    hashfun: str
    window_size: int
    id_context: bytes | None
    sender_sequence: int
    replay_index: int
    replay_bitfield: int

    def to_cbor_map(self) -> dict[int, Any]:
        """Encode as CBOR map with integer keys."""
        params: dict[int, Any] = {
            _KEY_OSCORE_SECRET: self.master_secret,
            _KEY_OSCORE_SALT: self.master_salt,
            _KEY_OSCORE_SENDER_ID: self.sender_id,
            _KEY_OSCORE_RECIPIENT_ID: self.recipient_id,
            _KEY_OSCORE_ALG: self.algorithm,
            _KEY_OSCORE_HASHFUN: self.hashfun,
            _KEY_OSCORE_WINDOW: self.window_size,
        }
        if self.id_context is not None:
            params[_KEY_OSCORE_ID_CTX] = self.id_context
        return {
            _KEY_OSCORE_PARAMS: params,
            _KEY_OSCORE_SENDER_SEQ: self.sender_sequence,
            _KEY_OSCORE_REPLAY: [self.replay_index, self.replay_bitfield],
        }

    @classmethod
    def from_cbor_map(cls, data: dict[int, Any]) -> OscoreState:
        """Decode from CBOR map.

        Raises:
            HandoffError: If required fields are missing or malformed.
        """
        # SECURITY: OSCORE replay windows are typically 32 or 64 bits.
        # Python integers are arbitrary precision, so we must validate
        # bounds to prevent memory exhaustion from malicious payloads.
        max_u64 = (1 << 64) - 1  # 64-bit max
        max_window = 256  # Reasonable max for replay window size

        try:
            params = data[_KEY_OSCORE_PARAMS]
            replay = data[_KEY_OSCORE_REPLAY]

            replay_index = replay[0]
            replay_bitfield = replay[1]
            sender_sequence = data[_KEY_OSCORE_SENDER_SEQ]
            window_size = params[_KEY_OSCORE_WINDOW]

            # SECURITY: Validate integer bounds to prevent memory DoS
            if not isinstance(replay_index, int) or not 0 <= replay_index <= max_u64:
                raise HandoffError("replay_index out of range (must be 0 to 2^64-1)")
            if not isinstance(replay_bitfield, int) or not 0 <= replay_bitfield <= max_u64:
                raise HandoffError("replay_bitfield out of range (must be 0 to 2^64-1)")
            if not isinstance(sender_sequence, int) or not 0 <= sender_sequence <= max_u64:
                raise HandoffError("sender_sequence out of range (must be 0 to 2^64-1)")
            if not isinstance(window_size, int) or not 0 < window_size <= max_window:
                raise HandoffError(f"window_size out of range (must be 1 to {max_window})")

            return cls(
                master_secret=params[_KEY_OSCORE_SECRET],
                master_salt=params[_KEY_OSCORE_SALT],
                sender_id=params[_KEY_OSCORE_SENDER_ID],
                recipient_id=params[_KEY_OSCORE_RECIPIENT_ID],
                algorithm=params[_KEY_OSCORE_ALG],
                hashfun=params[_KEY_OSCORE_HASHFUN],
                window_size=window_size,
                id_context=params.get(_KEY_OSCORE_ID_CTX),
                sender_sequence=sender_sequence,
                replay_index=replay_index,
                replay_bitfield=replay_bitfield,
            )
        except (KeyError, IndexError, TypeError) as e:
            raise HandoffError(f"malformed OSCORE state: {e}") from None


@dataclass(frozen=True)
class FreshnessState:
    """DAO freshness tracking state for handoff transfer."""

    sequence: int
    active_until: float | None
    retain_until: float
    updated_at: float

    def to_cbor_map(self) -> dict[str, Any]:
        """Encode as CBOR map."""
        result: dict[str, Any] = {
            "seq": self.sequence,
            "retain": self.retain_until,
            "updated": self.updated_at,
        }
        if self.active_until is not None:
            result["active"] = self.active_until
        return result

    @classmethod
    def from_cbor_map(cls, data: dict[str, Any]) -> FreshnessState:
        """Decode from CBOR map.

        Raises:
            HandoffError: If required fields are missing or have wrong types.
        """
        try:
            sequence = data["seq"]
            active_until = data.get("active")
            retain_until = data["retain"]
            updated_at = data["updated"]
        except KeyError as e:
            raise HandoffError(f"malformed freshness state: missing {e}") from None

        # Validate types
        if not isinstance(sequence, int) or sequence < 0:
            raise HandoffError("sequence must be a non-negative integer")
        if active_until is not None and not isinstance(active_until, (int, float)):
            raise HandoffError("active_until must be numeric")
        if not isinstance(retain_until, (int, float)):
            raise HandoffError("retain_until must be numeric")
        if not isinstance(updated_at, (int, float)):
            raise HandoffError("updated_at must be numeric")

        return cls(
            sequence=sequence,
            active_until=float(active_until) if active_until is not None else None,
            retain_until=float(retain_until),
            updated_at=float(updated_at),
        )


@dataclass
class HandoffRequest:
    """POST /handoff request payload from new gateway to old gateway.

    Sent by Gateway B (new) to Gateway A (old) to request node state
    transfer. Gateway A should:
    1. Verify authentication (OSCORE)
    2. Check if node is in its registry
    3. Check if node is not in active communication
    4. Extract and package state
    5. Release node from registry
    6. Send HandoffResponse with state
    """

    node_address: IPv6Address
    timestamp: int  # Unix seconds
    rssi: int | None = None  # Last RSSI from node at new gateway (dBm)

    def encode(self) -> bytes:
        """Encode as CBOR for transmission."""
        data: dict[int, Any] = {
            _KEY_NODE_ADDR: self.node_address.packed,
            _KEY_TIMESTAMP: self.timestamp,
        }
        if self.rssi is not None:
            data[_KEY_RSSI] = self.rssi
        return cbor2.dumps(data)

    @classmethod
    def decode(cls, payload: bytes) -> HandoffRequest:
        """Decode from CBOR payload.

        Raises:
            HandoffError: If payload is malformed.
        """
        try:
            data = cbor2.loads(payload)
        except (cbor2.CBORDecodeError, OverflowError):
            raise HandoffError("invalid CBOR") from None

        if not isinstance(data, dict):
            raise HandoffError("expected CBOR map")

        try:
            node_addr = IPv6Address(data[_KEY_NODE_ADDR])
            timestamp = data[_KEY_TIMESTAMP]
            rssi = data.get(_KEY_RSSI)
        except (KeyError, TypeError, ValueError) as e:
            raise HandoffError(f"malformed request: {e}") from None

        if not isinstance(timestamp, int):
            raise HandoffError("timestamp must be integer")
        if rssi is not None and not isinstance(rssi, int):
            raise HandoffError("rssi must be integer")

        return cls(node_address=node_addr, timestamp=timestamp, rssi=rssi)


@dataclass
class HandoffResponse:
    """POST /handoff response payload from old gateway to new gateway.

    On success, contains all state needed for the new gateway to take
    over responsibility for the node. On failure, contains rejection
    reason.
    """

    status: HandoffRejectReason
    message: str = ""

    # State fields (only present on success)
    node_address: IPv6Address | None = None
    dao_sequence: int | None = None
    path_sequence: int | None = None
    oscore_state: OscoreState | None = None
    freshness: FreshnessState | None = None
    parents: tuple[IPv6Address, ...] = field(default_factory=tuple)

    def encode(self) -> bytes:
        """Encode as CBOR for transmission."""
        data: dict[int, Any] = {
            _KEY_STATUS: int(self.status),
        }
        if self.message:
            data[_KEY_MESSAGE] = self.message

        if self.status == HandoffRejectReason.SUCCESS:
            if self.node_address is not None:
                data[_KEY_NODE_ADDR] = self.node_address.packed
            if self.dao_sequence is not None:
                data[_KEY_DAO_SEQ] = self.dao_sequence
            if self.path_sequence is not None:
                data[_KEY_PATH_SEQ] = self.path_sequence
            if self.oscore_state is not None:
                data.update(self.oscore_state.to_cbor_map())
            if self.freshness is not None:
                data[_KEY_FRESHNESS] = self.freshness.to_cbor_map()
            if self.parents:
                data[_KEY_PARENTS] = [p.packed for p in self.parents]

        return cbor2.dumps(data)

    @classmethod
    def decode(cls, payload: bytes) -> HandoffResponse:
        """Decode from CBOR payload.

        Raises:
            HandoffError: If payload is malformed.
        """
        try:
            data = cbor2.loads(payload)
        except (cbor2.CBORDecodeError, OverflowError):
            raise HandoffError("invalid CBOR") from None

        if not isinstance(data, dict):
            raise HandoffError("expected CBOR map")

        try:
            status = HandoffRejectReason(data[_KEY_STATUS])
        except (KeyError, ValueError):
            raise HandoffError("missing or invalid status") from None

        message = data.get(_KEY_MESSAGE, "")

        if status != HandoffRejectReason.SUCCESS:
            return cls(status=status, message=message)

        # Parse success response with state
        node_address: IPv6Address | None = None
        if _KEY_NODE_ADDR in data:
            try:
                node_address = IPv6Address(data[_KEY_NODE_ADDR])
            except ValueError:
                raise HandoffError("invalid node address") from None

        dao_seq = data.get(_KEY_DAO_SEQ)
        path_seq = data.get(_KEY_PATH_SEQ)

        if dao_seq is not None and not isinstance(dao_seq, int):
            raise HandoffError("dao_sequence must be integer")
        if path_seq is not None and not isinstance(path_seq, int):
            raise HandoffError("path_sequence must be integer")

        oscore_state: OscoreState | None = None
        if _KEY_OSCORE_PARAMS in data:
            oscore_state = OscoreState.from_cbor_map(data)

        freshness: FreshnessState | None = None
        if _KEY_FRESHNESS in data:
            freshness = FreshnessState.from_cbor_map(data[_KEY_FRESHNESS])

        parents: tuple[IPv6Address, ...] = ()
        if _KEY_PARENTS in data:
            try:
                parents = tuple(IPv6Address(p) for p in data[_KEY_PARENTS])
            except (TypeError, ValueError):
                raise HandoffError("invalid parents") from None

        return cls(
            status=status,
            message=message,
            node_address=node_address,
            dao_sequence=dao_seq,
            path_sequence=path_seq,
            oscore_state=oscore_state,
            freshness=freshness,
            parents=parents,
        )

    @classmethod
    def success(
        cls,
        node_address: IPv6Address,
        dao_sequence: int,
        path_sequence: int,
        *,
        oscore_state: OscoreState | None = None,
        freshness: FreshnessState | None = None,
        parents: tuple[IPv6Address, ...] = (),
    ) -> HandoffResponse:
        """Create a successful handoff response with state transfer."""
        return cls(
            status=HandoffRejectReason.SUCCESS,
            node_address=node_address,
            dao_sequence=dao_sequence,
            path_sequence=path_sequence,
            oscore_state=oscore_state,
            freshness=freshness,
            parents=parents,
        )

    @classmethod
    def error(cls, reason: HandoffRejectReason, message: str = "") -> HandoffResponse:
        """Create an error response."""
        if reason == HandoffRejectReason.SUCCESS:
            raise ValueError("use success() for success responses")
        return cls(status=reason, message=message)


@dataclass
class NodeRegistryEntry:
    """State tracked per node in a gateway's registry.

    This is the internal state that gets exported during handoff.
    """

    address: IPv6Address
    dao_sequence: int = 0
    path_sequence: int = 0
    oscore_state: OscoreState | None = None
    freshness: FreshnessState | None = None
    parents: tuple[IPv6Address, ...] = field(default_factory=tuple)
    last_seen: float = 0.0
    busy: bool = False  # True if node is in active transaction
    pending_handoff: bool = False  # True if handoff initiated but not confirmed


class NodeRegistry:
    """Gateway-side node registry for handoff protocol.

    Tracks nodes that have joined via this gateway and their state.
    Provides extraction for handoff and registration for incoming nodes.
    """

    def __init__(self) -> None:
        self._nodes: dict[IPv6Address, NodeRegistryEntry] = {}

    def register(
        self,
        address: IPv6Address,
        *,
        dao_sequence: int = 0,
        path_sequence: int = 0,
        oscore_state: OscoreState | None = None,
        freshness: FreshnessState | None = None,
        parents: tuple[IPv6Address, ...] = (),
        last_seen: float = 0.0,
    ) -> None:
        """Register a node or update its state."""
        address = to_ipv6(address)
        self._nodes[address] = NodeRegistryEntry(
            address=address,
            dao_sequence=dao_sequence,
            path_sequence=path_sequence,
            oscore_state=oscore_state,
            freshness=freshness,
            parents=parents,
            last_seen=last_seen,
        )

    def unregister(self, address: IPv6Address) -> NodeRegistryEntry | None:
        """Remove a node from the registry, returning its entry if present."""
        address = to_ipv6(address)
        return self._nodes.pop(address, None)

    def get(self, address: IPv6Address) -> NodeRegistryEntry | None:
        """Get a node's registry entry."""
        address = to_ipv6(address)
        return self._nodes.get(address)

    def contains(self, address: IPv6Address) -> bool:
        """Check if a node is registered."""
        address = to_ipv6(address)
        return address in self._nodes

    def set_busy(self, address: IPv6Address, busy: bool) -> None:
        """Mark a node as busy (in active transaction) or not."""
        address = to_ipv6(address)
        if address in self._nodes:
            self._nodes[address].busy = busy

    def handle_handoff_request(self, request: HandoffRequest) -> HandoffResponse:
        """Process a handoff request from another gateway.

        This is the core handoff logic on the source gateway side:
        1. Check if node exists in registry
        2. Check if node is busy or already pending handoff
        3. Extract state
        4. Mark as pending handoff (NOT removed yet)
        5. Return success response with state

        SECURITY: Caller MUST verify OSCORE authentication before calling.
        This method assumes the request is from a trusted peer gateway.

        SECURITY: This method uses two-phase commit. The node is marked as
        pending_handoff but NOT removed. Caller MUST call finalize_handoff()
        after successful response delivery, or rollback_handoff() on failure.
        This prevents node orphaning if the response is lost in transit.

        Returns:
            HandoffResponse with state on success, or error response.
        """
        address = to_ipv6(request.node_address)

        entry = self.get(address)
        if entry is None:
            return HandoffResponse.error(
                HandoffRejectReason.NODE_NOT_FOUND,
                f"node {address} not in registry",
            )

        if entry.busy:
            return HandoffResponse.error(
                HandoffRejectReason.NODE_BUSY,
                f"node {address} is in active transaction, retry later",
            )

        if entry.pending_handoff:
            return HandoffResponse.error(
                HandoffRejectReason.NODE_BUSY,
                f"node {address} has pending handoff, retry later",
            )

        # SECURITY: Mark as pending handoff but do NOT unregister yet.
        # Caller must call finalize_handoff() after successful delivery.
        entry.pending_handoff = True

        return HandoffResponse.success(
            node_address=entry.address,
            dao_sequence=entry.dao_sequence,
            path_sequence=entry.path_sequence,
            oscore_state=entry.oscore_state,
            freshness=entry.freshness,
            parents=entry.parents,
        )

    def finalize_handoff(self, address: IPv6Address) -> bool:
        """Finalize a pending handoff by removing the node from registry.

        Call this ONLY after the HandoffResponse has been successfully
        delivered to the requesting gateway.

        SECURITY: This is the second phase of the two-phase commit. Only
        call after confirming the target gateway received the state.

        Args:
            address: Node address to finalize handoff for

        Returns:
            True if node was removed, False if not found or not pending
        """
        address = to_ipv6(address)
        entry = self._nodes.get(address)
        if entry is None or not entry.pending_handoff:
            return False
        self._nodes.pop(address, None)
        return True

    def rollback_handoff(self, address: IPv6Address) -> bool:
        """Rollback a pending handoff, keeping the node registered.

        Call this if the HandoffResponse failed to deliver to the
        requesting gateway.

        Args:
            address: Node address to rollback handoff for

        Returns:
            True if rollback succeeded, False if not found or not pending
        """
        address = to_ipv6(address)
        entry = self._nodes.get(address)
        if entry is None or not entry.pending_handoff:
            return False
        entry.pending_handoff = False
        return True

    def get_pending_handoffs(self) -> list[IPv6Address]:
        """Get list of nodes with pending handoffs.

        Useful for implementing timeout-based cleanup of stale pending
        handoffs that were never finalized or rolled back.

        Returns:
            List of node addresses with pending_handoff=True
        """
        return [addr for addr, entry in self._nodes.items() if entry.pending_handoff]

    def accept_handoff(self, response: HandoffResponse) -> None:
        """Accept a successful handoff response from another gateway.

        Called on the new gateway after receiving a success response.
        Registers the node with transferred state.

        SECURITY: The receiving gateway MUST increment sequence numbers
        before using them to prevent replay attacks from in-flight messages.

        Raises:
            HandoffError: If response is not successful or missing required fields.
        """
        if response.status != HandoffRejectReason.SUCCESS:
            raise HandoffError(f"cannot accept failed handoff: {response.status.name}")

        if response.node_address is None:
            raise HandoffError("success response missing node_address")
        if response.dao_sequence is None:
            raise HandoffError("success response missing dao_sequence")
        if response.path_sequence is None:
            raise HandoffError("success response missing path_sequence")

        # SECURITY: Increment sequence numbers to ensure no replay of
        # in-flight messages from before the handoff. A gap of 1 is the
        # minimum safe increment; production may want a larger margin.
        safe_dao_seq = response.dao_sequence + 1
        safe_path_seq = response.path_sequence + 1

        # SECURITY: For OSCORE, increment sender sequence to prevent
        # nonce reuse. The replay window can be used as-is since it
        # tracks received messages (which haven't changed).
        oscore_state = response.oscore_state
        if oscore_state is not None:
            oscore_state = OscoreState(
                master_secret=oscore_state.master_secret,
                master_salt=oscore_state.master_salt,
                sender_id=oscore_state.sender_id,
                recipient_id=oscore_state.recipient_id,
                algorithm=oscore_state.algorithm,
                hashfun=oscore_state.hashfun,
                window_size=oscore_state.window_size,
                id_context=oscore_state.id_context,
                sender_sequence=oscore_state.sender_sequence + 1,  # Increment!
                replay_index=oscore_state.replay_index,
                replay_bitfield=oscore_state.replay_bitfield,
            )

        self.register(
            address=response.node_address,
            dao_sequence=safe_dao_seq,
            path_sequence=safe_path_seq,
            oscore_state=oscore_state,
            freshness=response.freshness,
            parents=response.parents,
        )

    def list_nodes(self) -> list[IPv6Address]:
        """List all registered node addresses."""
        return list(self._nodes.keys())

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, address: IPv6Address) -> bool:
        return self.contains(address)


# ---------------------------------------------------------------------------
# GCP Handoff COSE_Sign1 (spec 08-gateway-coordination.md GCP-7.1)
# ---------------------------------------------------------------------------


def _encode_protected_header() -> bytes:
    """Encode the COSE protected header: {1: -65537} (alg: Schnorr48-Ed25519)."""
    return cbor2.dumps({_COSE_ALG: SCHNORR48_ED25519_ALG}, canonical=True)


def _build_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build COSE Sig_structure per RFC 9052 section 4.4.

    Sig_structure = [
        "Signature1",     ; context string
        protected,        ; protected header bytes
        h'',              ; external_aad (empty)
        payload           ; payload bytes
    ]

    Returns:
        CBOR-encoded Sig_structure
    """
    sig_structure = [
        "Signature1",  # context string
        protected,  # protected header (already CBOR-encoded)
        b"",  # external_aad (empty)
        payload,  # payload bytes
    ]
    return cbor2.dumps(sig_structure, canonical=True)


def _strict_iid(value: object, field: str) -> bytes:
    """Validate an 8-byte IID field."""
    if not isinstance(value, bytes) or len(value) != 8:
        raise HandoffError(f"{field} must be exactly 8 bytes")
    return value


def _strict_uint(value: object, field: str) -> int:
    """Validate a non-negative integer field."""
    if not isinstance(value, int) or value < 0:
        raise HandoffError(f"{field} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class HandoffRequestCosePayload:
    """GCP Handoff Request payload per spec GCP-7.1.

    Attributes:
        node: 8-byte node IID being transferred
        old_gw: 8-byte current owner gateway IID
        seq: Handoff sequence number (monotonically increasing)
        ts: Unix timestamp of request
        expiry: Unix timestamp when request expires
        rssi: RSSI observed by new gateway (dBm)
    """

    node: bytes
    old_gw: bytes
    seq: int
    ts: int
    expiry: int
    rssi: int

    def __post_init__(self) -> None:
        _strict_iid(self.node, "node")
        _strict_iid(self.old_gw, "old_gw")
        _strict_uint(self.seq, "seq")
        _strict_uint(self.ts, "ts")
        _strict_uint(self.expiry, "expiry")
        if not isinstance(self.rssi, int):
            raise HandoffError("rssi must be an integer")

    def to_cbor(self) -> bytes:
        """Encode as CBOR map with integer keys."""
        payload_map = {
            _REQ_NODE: self.node,
            _REQ_OLD_GW: self.old_gw,
            _REQ_SEQ: self.seq,
            _REQ_TS: self.ts,
            _REQ_EXPIRY: self.expiry,
            _REQ_RSSI: self.rssi,
        }
        return cbor2.dumps(payload_map, canonical=True)

    @classmethod
    def from_cbor(cls, data: bytes) -> HandoffRequestCosePayload:
        """Decode from CBOR bytes."""
        try:
            payload_map = cbor2.loads(data)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid CBOR: {e}") from None

        if not isinstance(payload_map, dict):
            raise HandoffError("payload must be a CBOR map")

        required_keys = {_REQ_NODE, _REQ_OLD_GW, _REQ_SEQ, _REQ_TS, _REQ_EXPIRY, _REQ_RSSI}
        if set(payload_map.keys()) != required_keys:
            raise HandoffError("payload has missing or unknown keys")

        return cls(
            node=_strict_iid(payload_map[_REQ_NODE], "node"),
            old_gw=_strict_iid(payload_map[_REQ_OLD_GW], "old_gw"),
            seq=_strict_uint(payload_map[_REQ_SEQ], "seq"),
            ts=_strict_uint(payload_map[_REQ_TS], "ts"),
            expiry=_strict_uint(payload_map[_REQ_EXPIRY], "expiry"),
            rssi=payload_map[_REQ_RSSI],
        )


@dataclass(frozen=True)
class HandoffConfirmCosePayload:
    """GCP Handoff Confirm payload per spec GCP-7.1.

    Attributes:
        node: 8-byte node IID being transferred
        new_gw: 8-byte new owner gateway IID
        seq: Echoed handoff sequence number
        ts: Confirmation timestamp
        link_epoch: Node's link-layer epoch (8-bit)
        link_seq: Node's link-layer sequence (16-bit)
    """

    node: bytes
    new_gw: bytes
    seq: int
    ts: int
    link_epoch: int
    link_seq: int

    def __post_init__(self) -> None:
        _strict_iid(self.node, "node")
        _strict_iid(self.new_gw, "new_gw")
        _strict_uint(self.seq, "seq")
        _strict_uint(self.ts, "ts")
        if not isinstance(self.link_epoch, int) or not 0 <= self.link_epoch <= 255:
            raise HandoffError("link_epoch must be 0-255")
        if not isinstance(self.link_seq, int) or not 0 <= self.link_seq <= 65535:
            raise HandoffError("link_seq must be 0-65535")

    def to_cbor(self) -> bytes:
        """Encode as CBOR map with integer keys."""
        payload_map = {
            _CONF_NODE: self.node,
            _CONF_NEW_GW: self.new_gw,
            _CONF_SEQ: self.seq,
            _CONF_TS: self.ts,
            _CONF_LINK_EPOCH: self.link_epoch,
            _CONF_LINK_SEQ: self.link_seq,
        }
        return cbor2.dumps(payload_map, canonical=True)

    @classmethod
    def from_cbor(cls, data: bytes) -> HandoffConfirmCosePayload:
        """Decode from CBOR bytes."""
        try:
            payload_map = cbor2.loads(data)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid CBOR: {e}") from None

        if not isinstance(payload_map, dict):
            raise HandoffError("payload must be a CBOR map")

        required_keys = {
            _CONF_NODE, _CONF_NEW_GW, _CONF_SEQ, _CONF_TS, _CONF_LINK_EPOCH, _CONF_LINK_SEQ
        }
        if set(payload_map.keys()) != required_keys:
            raise HandoffError("payload has missing or unknown keys")

        return cls(
            node=_strict_iid(payload_map[_CONF_NODE], "node"),
            new_gw=_strict_iid(payload_map[_CONF_NEW_GW], "new_gw"),
            seq=_strict_uint(payload_map[_CONF_SEQ], "seq"),
            ts=_strict_uint(payload_map[_CONF_TS], "ts"),
            link_epoch=payload_map[_CONF_LINK_EPOCH],
            link_seq=payload_map[_CONF_LINK_SEQ],
        )


@dataclass(frozen=True)
class HandoffRequestCoseSign1:
    """COSE_Sign1 Handoff Request per spec GCP-7.1.

    COSE_Sign1 structure:
    [
        h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
        {4: h'<new-gw-iid>'},   ; unprotected: {kid: new gateway 8-byte IID}
        h'<payload>',           ; CBOR-encoded HandoffRequestCosePayload
        h'<48-byte signature>'  ; Schnorr48 signature
    ]
    """

    payload: HandoffRequestCosePayload
    new_gw_iid: bytes
    signature: bytes
    protected: bytes
    payload_bytes: bytes

    def __post_init__(self) -> None:
        _strict_iid(self.new_gw_iid, "new_gw_iid")
        if len(self.signature) != 48:
            raise HandoffError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure."""
        cose_sign1 = [
            self.protected,
            {_COSE_KID: self.new_gw_iid},
            self.payload_bytes,
            self.signature,
        ]
        return cbor2.dumps(cose_sign1, canonical=True)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> HandoffRequestCoseSign1:
        """Decode from COSE_Sign1 structure.

        Raises:
            HandoffError: If structure is invalid
        """
        try:
            cose_array = cbor2.loads(data)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid CBOR: {e}") from None

        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise HandoffError("COSE_Sign1 must be a 4-element array")

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        if not isinstance(protected_bytes, bytes):
            raise HandoffError("protected header must be bytes")
        if not isinstance(payload_bytes, bytes):
            raise HandoffError("payload must be bytes")
        if not isinstance(signature, bytes):
            raise HandoffError("signature must be bytes")

        # Validate protected header
        try:
            protected = cbor2.loads(protected_bytes)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid protected header: {e}") from None

        if not isinstance(protected, dict):
            raise HandoffError("protected header must be a CBOR map")
        if protected.get(_COSE_ALG) != SCHNORR48_ED25519_ALG:
            raise HandoffError(f"unsupported COSE algorithm: {protected.get(_COSE_ALG)}")
        if set(protected.keys()) != {_COSE_ALG}:
            raise HandoffError("unknown protected header keys")

        # Extract new_gw_iid from unprotected header
        if not isinstance(unprotected, dict) or set(unprotected.keys()) != {_COSE_KID}:
            raise HandoffError("unprotected header must contain only kid")
        new_gw_iid = _strict_iid(unprotected[_COSE_KID], "kid")

        # Decode payload
        payload = HandoffRequestCosePayload.from_cbor(payload_bytes)

        # Validate signature length
        if len(signature) != 48:
            raise HandoffError(f"signature must be 48 bytes, got {len(signature)}")

        return cls(
            payload=payload,
            new_gw_iid=new_gw_iid,
            signature=signature,
            protected=protected_bytes,
            payload_bytes=payload_bytes,
        )

    def signature_digest(self) -> bytes:
        """Compute SHA-256 digest of Sig_structure for verification."""
        sig_structure = _build_sig_structure(self.protected, self.payload_bytes)
        return sha256(sig_structure).digest()

    def verify(self, new_gw_pubkey: bytes) -> bool:
        """Verify the signature using the new gateway's public key.

        SECURITY: Also verifies that kid matches the derived IID from pubkey.

        NOTE: This only verifies the cryptographic signature. Callers MUST also
        call validate_timing() to check expiry and prevent replay attacks.
        """
        if len(new_gw_pubkey) != 32:
            return False
        if _pubkey_to_iid(new_gw_pubkey) != self.new_gw_iid:
            return False
        return schnorr48.verify(new_gw_pubkey, self.signature_digest(), self.signature)

    def validate_timing(self, current_time: int) -> bool:
        """Validate request timing constraints.

        SECURITY: This check is essential to prevent replay attacks. A captured
        handoff request can be replayed after its intended validity period if
        this validation is skipped.

        Checks:
            1. ts <= current_time: Request timestamp is not in the future
            2. current_time < expiry: Request has not expired

        Args:
            current_time: Current Unix timestamp (seconds)

        Returns:
            True if timing is valid, False otherwise
        """
        # Reject requests with timestamps in the future (clock skew tolerance
        # could be added here if needed, but strict check is safer)
        if self.payload.ts > current_time:
            return False
        # Reject expired requests
        return current_time < self.payload.expiry


@dataclass(frozen=True)
class HandoffConfirmCoseSign1:
    """COSE_Sign1 Handoff Confirm per spec GCP-7.1.

    COSE_Sign1 structure:
    [
        h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
        {4: h'<old-gw-iid>'},   ; unprotected: {kid: old gateway 8-byte IID}
        h'<payload>',           ; CBOR-encoded HandoffConfirmCosePayload
        h'<48-byte signature>'  ; Schnorr48 signature
    ]
    """

    payload: HandoffConfirmCosePayload
    old_gw_iid: bytes
    signature: bytes
    protected: bytes
    payload_bytes: bytes

    def __post_init__(self) -> None:
        _strict_iid(self.old_gw_iid, "old_gw_iid")
        if len(self.signature) != 48:
            raise HandoffError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure."""
        cose_sign1 = [
            self.protected,
            {_COSE_KID: self.old_gw_iid},
            self.payload_bytes,
            self.signature,
        ]
        return cbor2.dumps(cose_sign1, canonical=True)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> HandoffConfirmCoseSign1:
        """Decode from COSE_Sign1 structure.

        Raises:
            HandoffError: If structure is invalid
        """
        try:
            cose_array = cbor2.loads(data)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid CBOR: {e}") from None

        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise HandoffError("COSE_Sign1 must be a 4-element array")

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        if not isinstance(protected_bytes, bytes):
            raise HandoffError("protected header must be bytes")
        if not isinstance(payload_bytes, bytes):
            raise HandoffError("payload must be bytes")
        if not isinstance(signature, bytes):
            raise HandoffError("signature must be bytes")

        # Validate protected header
        try:
            protected = cbor2.loads(protected_bytes)
        except (cbor2.CBORDecodeError, OverflowError) as e:
            raise HandoffError(f"invalid protected header: {e}") from None

        if not isinstance(protected, dict):
            raise HandoffError("protected header must be a CBOR map")
        if protected.get(_COSE_ALG) != SCHNORR48_ED25519_ALG:
            raise HandoffError(f"unsupported COSE algorithm: {protected.get(_COSE_ALG)}")
        if set(protected.keys()) != {_COSE_ALG}:
            raise HandoffError("unknown protected header keys")

        # Extract old_gw_iid from unprotected header
        if not isinstance(unprotected, dict) or set(unprotected.keys()) != {_COSE_KID}:
            raise HandoffError("unprotected header must contain only kid")
        old_gw_iid = _strict_iid(unprotected[_COSE_KID], "kid")

        # Decode payload
        payload = HandoffConfirmCosePayload.from_cbor(payload_bytes)

        # Validate signature length
        if len(signature) != 48:
            raise HandoffError(f"signature must be 48 bytes, got {len(signature)}")

        return cls(
            payload=payload,
            old_gw_iid=old_gw_iid,
            signature=signature,
            protected=protected_bytes,
            payload_bytes=payload_bytes,
        )

    def signature_digest(self) -> bytes:
        """Compute SHA-256 digest of Sig_structure for verification."""
        sig_structure = _build_sig_structure(self.protected, self.payload_bytes)
        return sha256(sig_structure).digest()

    def verify(self, old_gw_pubkey: bytes) -> bool:
        """Verify the signature using the old gateway's public key.

        SECURITY: Also verifies that kid matches the derived IID from pubkey.
        """
        if len(old_gw_pubkey) != 32:
            return False
        if _pubkey_to_iid(old_gw_pubkey) != self.old_gw_iid:
            return False
        return schnorr48.verify(old_gw_pubkey, self.signature_digest(), self.signature)


def create_handoff_request(
    identity: Identity,
    node_iid: bytes,
    old_gw_iid: bytes,
    seq: int,
    ts: int,
    expiry: int,
    rssi: int,
) -> HandoffRequestCoseSign1:
    """Create a signed GCP Handoff Request.

    Args:
        identity: New gateway's identity (contains signing key)
        node_iid: 8-byte IID of node being transferred
        old_gw_iid: 8-byte IID of current owner gateway
        seq: Handoff sequence number (must be monotonically increasing)
        ts: Unix timestamp of request
        expiry: Unix timestamp when request expires
        rssi: RSSI observed by new gateway (dBm)

    Returns:
        Signed HandoffRequestCoseSign1 ready for transmission
    """
    payload = HandoffRequestCosePayload(
        node=node_iid,
        old_gw=old_gw_iid,
        seq=seq,
        ts=ts,
        expiry=expiry,
        rssi=rssi,
    )

    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return HandoffRequestCoseSign1(
        payload=payload,
        new_gw_iid=identity.iid,
        signature=signature,
        protected=protected,
        payload_bytes=payload_bytes,
    )


def create_handoff_confirm(
    identity: Identity,
    node_iid: bytes,
    new_gw_iid: bytes,
    seq: int,
    ts: int,
    link_epoch: int,
    link_seq: int,
) -> HandoffConfirmCoseSign1:
    """Create a signed GCP Handoff Confirm.

    Args:
        identity: Old gateway's identity (contains signing key)
        node_iid: 8-byte IID of node being transferred
        new_gw_iid: 8-byte IID of new owner gateway
        seq: Echoed handoff sequence number from request
        ts: Confirmation timestamp
        link_epoch: Node's link-layer epoch (0-255)
        link_seq: Node's link-layer sequence (0-65535)

    Returns:
        Signed HandoffConfirmCoseSign1 ready for transmission
    """
    payload = HandoffConfirmCosePayload(
        node=node_iid,
        new_gw=new_gw_iid,
        seq=seq,
        ts=ts,
        link_epoch=link_epoch,
        link_seq=link_seq,
    )

    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return HandoffConfirmCoseSign1(
        payload=payload,
        old_gw_iid=identity.iid,
        signature=signature,
        protected=protected,
        payload_bytes=payload_bytes,
    )
