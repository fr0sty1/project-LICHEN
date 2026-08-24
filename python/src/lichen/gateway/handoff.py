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
from ipaddress import IPv6Address
from typing import Any

import cbor2

from lichen.ipv6 import to_ipv6


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
        try:
            params = data[_KEY_OSCORE_PARAMS]
            replay = data[_KEY_OSCORE_REPLAY]
            return cls(
                master_secret=params[_KEY_OSCORE_SECRET],
                master_salt=params[_KEY_OSCORE_SALT],
                sender_id=params[_KEY_OSCORE_SENDER_ID],
                recipient_id=params[_KEY_OSCORE_RECIPIENT_ID],
                algorithm=params[_KEY_OSCORE_ALG],
                hashfun=params[_KEY_OSCORE_HASHFUN],
                window_size=params[_KEY_OSCORE_WINDOW],
                id_context=params.get(_KEY_OSCORE_ID_CTX),
                sender_sequence=data[_KEY_OSCORE_SENDER_SEQ],
                replay_index=replay[0],
                replay_bitfield=replay[1],
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
        """Decode from CBOR map."""
        try:
            return cls(
                sequence=data["seq"],
                active_until=data.get("active"),
                retain_until=data["retain"],
                updated_at=data["updated"],
            )
        except (KeyError, TypeError) as e:
            raise HandoffError(f"malformed freshness state: {e}") from None


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
        2. Check if node is busy
        3. Extract state
        4. Remove from registry
        5. Return success response with state

        SECURITY: Caller MUST verify OSCORE authentication before calling.
        This method assumes the request is from a trusted peer gateway.

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

        # Remove from registry (releases ownership)
        self.unregister(address)

        return HandoffResponse.success(
            node_address=entry.address,
            dao_sequence=entry.dao_sequence,
            path_sequence=entry.path_sequence,
            oscore_state=entry.oscore_state,
            freshness=entry.freshness,
            parents=entry.parents,
        )

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
