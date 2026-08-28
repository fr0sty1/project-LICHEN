# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fail-closed authorization for source-routed egress tunnels.

The DODAG root signs an authorization for one source prefix and one exact
source route.  An egress accepts the authorization only over its authenticated
pairwise OSCORE channel and consults the resulting bounded table before it
publishes an inner packet to an external network.

This module deliberately keeps transport I/O behind callbacks.  The root and
egress adapters are therefore usable by the simulator, a TUN gateway, and CoAP
without making authorization state depend on any one event loop.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from ipaddress import IPv6Address, IPv6Network

import cbor2

from lichen.crypto import schnorr48
from lichen.crypto.identity import Identity, _pubkey_to_iid
from lichen.ipv6.packet import IPv6Packet

SCHNORR48_ED25519_ALG = -65537
TUNNEL_AUTH_RESOURCE = "/.well-known/tunnel-auth"
TUNNEL_AUTH_CONTENT_FORMAT = 'application/cose; cose-type="cose-sign1"'
MAX_ROUTE_HOPS = 8
MAX_AUTHORIZATIONS = 256
MAX_U64 = (1 << 64) - 1

_COSE_ALG = 1
_COSE_KID = 4
_P_TARGET = 1
_P_PREFIX_LEN = 2
_P_ROUTE_HASH = 3
_P_PATH_SEQ = 4
_P_EXPIRY = 5
_P_EGRESS_IID = 6
_PAYLOAD_KEYS = {_P_TARGET, _P_PREFIX_LEN, _P_ROUTE_HASH, _P_PATH_SEQ, _P_EXPIRY, _P_EGRESS_IID}
_NATIVE_MESH = IPv6Network("0200::/8")


class TunnelAuthError(ValueError):
    """An authorization cannot be constructed or decoded safely."""


class TunnelDirection(StrEnum):
    """Direction at the egress security boundary."""

    MESH_TO_EXTERNAL = "mesh-to-external"
    EXTERNAL_TO_MESH = "external-to-mesh"
    MESH_TRANSIT = "mesh-transit"


class TunnelDenial(StrEnum):
    """Internal denial categories; wire responses remain uniformly 4.03."""

    NONE = "none"
    MALFORMED = "malformed"
    OSCORE_REQUIRED = "oscore-required"
    WRONG_ROOT = "wrong-root"
    KEY_BINDING = "key-binding"
    ALGORITHM = "algorithm"
    SIGNATURE = "signature"
    WRONG_EGRESS = "wrong-egress"
    EXPIRED = "expired"
    REPLAY = "replay"
    REVOKED = "revoked"
    CAPACITY = "capacity"
    CLOCK_REGRESSION = "clock-regression"
    WRONG_DIRECTION = "wrong-direction"
    INVALID_ROUTE = "invalid-route"
    ROUTE_MISMATCH = "route-mismatch"
    SOURCE_SCOPE = "source-scope"
    DESTINATION_SCOPE = "destination-scope"
    NO_AUTHORIZATION = "no-authorization"
    DELIVERY_FAILED = "delivery-failed"


@dataclass(frozen=True)
class AuthorizationResult:
    """Result safe to return from a CoAP resource or data-plane check."""

    allowed: bool
    denial: TunnelDenial
    response_code: int

    @classmethod
    def permit(cls) -> AuthorizationResult:
        return cls(True, TunnelDenial.NONE, 204)

    @classmethod
    def deny(cls, reason: TunnelDenial) -> AuthorizationResult:
        # Do not disclose the cryptographic or policy oracle on the wire.
        return cls(False, reason, 403)


def _strict_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise TunnelAuthError(f"{field} must be an unsigned 64-bit integer")
    return value


def _strict_bytes(value: object, size: int, field: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise TunnelAuthError(f"{field} must be exactly {size} bytes")
    return value


def _canonical_loads(data: bytes, what: str) -> object:
    if type(data) is not bytes:
        raise TunnelAuthError(f"{what} must be bytes")
    try:
        value = cbor2.loads(data, allow_duplicate_keys=False)
    except (ValueError, TypeError, cbor2.CBORDecodeError) as exc:
        raise TunnelAuthError(f"invalid {what}") from exc
    try:
        canonical = cbor2.dumps(value, canonical=True)
    except (ValueError, TypeError, cbor2.CBOREncodeError) as exc:
        raise TunnelAuthError(f"invalid {what}") from exc
    if canonical != data:
        raise TunnelAuthError(f"{what} must use deterministic CBOR")
    return value


def _prefix_bytes(network: IPv6Network) -> bytes:
    octets = (network.prefixlen + 7) // 8
    return network.network_address.packed[:octets]


def _network_from_prefix(value: object, prefix_len_value: object) -> IPv6Network:
    prefix_len = _strict_u64(prefix_len_value, "prefix_len")
    if prefix_len > 128:
        raise TunnelAuthError("prefix_len must be between 0 and 128")
    expected = (prefix_len + 7) // 8
    prefix = _strict_bytes(value, expected, "target")
    if prefix_len % 8 and prefix and prefix[-1] & ((1 << (8 - prefix_len % 8)) - 1):
        raise TunnelAuthError("target has non-zero bits outside prefix_len")
    return IPv6Network((IPv6Address(prefix + bytes(16 - expected)), prefix_len), strict=True)


def _iid(value: IPv6Address | bytes) -> bytes:
    if isinstance(value, IPv6Address):
        return value.packed[-8:]
    return _strict_bytes(value, 8, "route hop IID")


def compute_route_hash(route: Sequence[IPv6Address | bytes]) -> bytes:
    """Return the 16-byte hash of the ordered source-route hop IIDs."""

    if not 1 <= len(route) <= MAX_ROUTE_HOPS:
        raise TunnelAuthError(f"route must contain 1-{MAX_ROUTE_HOPS} hops")
    iids = tuple(_iid(hop) for hop in route)
    if len(set(iids)) != len(iids):
        raise TunnelAuthError("route must not contain a loop")
    return sha256(b"".join(iids)).digest()[:16]


@dataclass(frozen=True)
class TunnelAuthorizationPayload:
    """Canonical authorization claims carried inside COSE_Sign1."""

    target: IPv6Network
    route_hash: bytes
    path_seq: int
    expiry: int
    egress_iid: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.target, IPv6Network):
            raise TunnelAuthError("target must be an IPv6Network")
        _strict_bytes(self.route_hash, 16, "route_hash")
        _strict_u64(self.path_seq, "path_seq")
        _strict_u64(self.expiry, "expiry")
        _strict_bytes(self.egress_iid, 8, "egress_iid")

    def to_cbor(self) -> bytes:
        return cbor2.dumps(
            {
                _P_TARGET: _prefix_bytes(self.target),
                _P_PREFIX_LEN: self.target.prefixlen,
                _P_ROUTE_HASH: self.route_hash,
                _P_PATH_SEQ: self.path_seq,
                _P_EXPIRY: self.expiry,
                _P_EGRESS_IID: self.egress_iid,
            },
            canonical=True,
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> TunnelAuthorizationPayload:
        value = _canonical_loads(data, "authorization payload")
        if type(value) is not dict or set(value) != _PAYLOAD_KEYS:
            raise TunnelAuthError("authorization payload has missing or unknown claims")
        target = _network_from_prefix(value[_P_TARGET], value[_P_PREFIX_LEN])
        return cls(
            target=target,
            route_hash=_strict_bytes(value[_P_ROUTE_HASH], 16, "route_hash"),
            path_seq=_strict_u64(value[_P_PATH_SEQ], "path_seq"),
            expiry=_strict_u64(value[_P_EXPIRY], "expiry"),
            egress_iid=_strict_bytes(value[_P_EGRESS_IID], 8, "egress_iid"),
        )


@dataclass(frozen=True)
class TunnelAuthorization:
    """Decoded COSE_Sign1 authorization, retaining signed byte strings."""

    payload: TunnelAuthorizationPayload
    root_iid: bytes
    signature: bytes
    protected: bytes
    payload_bytes: bytes

    def to_cose_sign1(self) -> bytes:
        return cbor2.dumps(
            [self.protected, {_COSE_KID: self.root_iid}, self.payload_bytes, self.signature],
            canonical=True,
        )

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> TunnelAuthorization:
        value = _canonical_loads(data, "COSE_Sign1")
        if type(value) is not list or len(value) != 4:
            raise TunnelAuthError("COSE_Sign1 must be a four-element array")
        protected_bytes, unprotected, payload_bytes, signature = value
        if type(protected_bytes) is not bytes or type(payload_bytes) is not bytes:
            raise TunnelAuthError("COSE protected header and payload must be byte strings")
        protected = _canonical_loads(protected_bytes, "COSE protected header")
        if type(protected) is not dict:
            raise TunnelAuthError("COSE protected header must be a map")
        if protected.get(_COSE_ALG) != SCHNORR48_ED25519_ALG:
            raise TunnelAuthError("unsupported COSE algorithm")
        if set(protected) != {_COSE_ALG}:
            raise TunnelAuthError("unknown protected COSE header")
        if type(unprotected) is not dict or set(unprotected) != {_COSE_KID}:
            raise TunnelAuthError("COSE unprotected header must contain only kid")
        root_iid = _strict_bytes(unprotected[_COSE_KID], 8, "root kid")
        sig = _strict_bytes(signature, 48, "signature")
        return cls(
            payload=TunnelAuthorizationPayload.from_cbor(payload_bytes),
            root_iid=root_iid,
            signature=sig,
            protected=protected_bytes,
            payload_bytes=payload_bytes,
        )

    def signature_digest(self) -> bytes:
        structure = ["Signature1", self.protected, b"", self.payload_bytes]
        return sha256(cbor2.dumps(structure, canonical=True)).digest()

    def verify(self, root_pubkey: bytes) -> bool:
        return (
            type(root_pubkey) is bytes
            and len(root_pubkey) == 32
            and _pubkey_to_iid(root_pubkey) == self.root_iid
            and schnorr48.verify(root_pubkey, self.signature_digest(), self.signature)
        )


def create_tunnel_authorization(
    identity: Identity,
    target: IPv6Network,
    route: Sequence[IPv6Address | bytes],
    path_seq: int,
    expiry: int,
    egress_iid: bytes,
) -> TunnelAuthorization:
    """Create a deterministic, egress-bound COSE_Sign1 authorization."""

    route_digest = compute_route_hash(route)
    if _iid(route[-1]) != _strict_bytes(egress_iid, 8, "egress_iid"):
        raise TunnelAuthError("route does not terminate at the requested egress")
    payload = TunnelAuthorizationPayload(
        target=target,
        route_hash=route_digest,
        path_seq=path_seq,
        expiry=expiry,
        egress_iid=egress_iid,
    )
    protected = cbor2.dumps({_COSE_ALG: SCHNORR48_ED25519_ALG}, canonical=True)
    payload_bytes = payload.to_cbor()
    unsigned = TunnelAuthorization(payload, identity.iid, bytes(48), protected, payload_bytes)
    signature = schnorr48.sign(identity.privkey, identity.pubkey, unsigned.signature_digest())
    return TunnelAuthorization(payload, identity.iid, signature, protected, payload_bytes)


@dataclass(frozen=True)
class TunnelAuthPost:
    """Transport-neutral authenticated CoAP request emitted by a root."""

    peer_iid: bytes
    payload: bytes
    method: str = "POST"
    resource: str = TUNNEL_AUTH_RESOURCE
    content_format: str = TUNNEL_AUTH_CONTENT_FORMAT
    require_oscore: bool = True


class RootTunnelAuthorizer:
    """Root-side adapter called when a route through an egress is installed."""

    def __init__(self, identity: Identity) -> None:
        self._identity = identity

    def route_installed(
        self,
        *,
        target: IPv6Network,
        route: Sequence[IPv6Address | bytes],
        path_seq: int,
        expiry: int,
        egress_iid: bytes,
        egress_capable: bool,
        send: Callable[[TunnelAuthPost], bool],
    ) -> AuthorizationResult:
        """Deliver authorization for an egress route before external use."""

        if not egress_capable:
            return AuthorizationResult.deny(TunnelDenial.DESTINATION_SCOPE)
        try:
            authorization = create_tunnel_authorization(
                self._identity, target, route, path_seq, expiry, egress_iid
            )
            request = TunnelAuthPost(peer_iid=egress_iid, payload=authorization.to_cose_sign1())
        except (TunnelAuthError, ValueError, TypeError):
            return AuthorizationResult.deny(TunnelDenial.INVALID_ROUTE)
        try:
            delivered = send(request)
        except Exception:
            return AuthorizationResult.deny(TunnelDenial.DELIVERY_FAILED)
        if delivered is not True:
            return AuthorizationResult.deny(TunnelDenial.DELIVERY_FAILED)
        return AuthorizationResult.permit()


@dataclass(frozen=True)
class TunnelPolicy:
    """Least-privilege address policy for the egress boundary."""

    mesh_prefix: IPv6Network = _NATIVE_MESH

    @staticmethod
    def _unsafe(address: IPv6Address) -> bool:
        return address.is_multicast or address.is_unspecified or address.is_loopback

    def source_allowed(self, source: IPv6Address, claim: IPv6Network) -> bool:
        return not self._unsafe(source) and not source.is_link_local and source in claim

    def destination_allowed(self, destination: IPv6Address) -> bool:
        return (
            not self._unsafe(destination)
            and not destination.is_link_local
            and destination not in self.mesh_prefix
        )


_AuthKey = tuple[IPv6Network, bytes]


class TunnelAuthorizationTable:
    """Thread-safe bounded egress authorization and replay table."""

    def __init__(
        self,
        *,
        egress_iid: bytes,
        root_iid: bytes,
        root_pubkey: bytes,
        max_entries: int = MAX_AUTHORIZATIONS,
        max_history: int | None = None,
        policy: TunnelPolicy | None = None,
    ) -> None:
        self._egress_iid = _strict_bytes(egress_iid, 8, "egress_iid")
        self._root_iid = _strict_bytes(root_iid, 8, "root_iid")
        self._root_pubkey = _strict_bytes(root_pubkey, 32, "root_pubkey")
        if _pubkey_to_iid(root_pubkey) != root_iid:
            raise TunnelAuthError("root public key does not derive root IID")
        if type(max_entries) is not int or max_entries <= 0:
            raise TunnelAuthError("max_entries must be positive")
        history = max_entries * 4 if max_history is None else max_history
        if type(history) is not int or history < max_entries:
            raise TunnelAuthError("max_history must be at least max_entries")
        self._max_entries = max_entries
        self._max_history = history
        self._policy = policy or TunnelPolicy()
        self._entries: OrderedDict[_AuthKey, TunnelAuthorizationPayload] = OrderedDict()
        self._floors: OrderedDict[_AuthKey, int] = OrderedDict()
        self._revoked: set[_AuthKey] = set()
        self._last_now: int | None = None
        self._lock = threading.RLock()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def _observe_time(self, now: int) -> TunnelDenial | None:
        _strict_u64(now, "now")
        if self._last_now is not None and now < self._last_now:
            # Wall-clock rollback invalidates every Unix-time authorization.
            self._entries.clear()
            # Retain replay/revocation floors and the high-water time so a
            # captured grant cannot rearm merely because the clock moved back.
            return TunnelDenial.CLOCK_REGRESSION
        self._last_now = now
        return None

    def _purge_expired(self, now: int) -> None:
        expired = [key for key, value in self._entries.items() if value.expiry <= now]
        for key in expired:
            self._entries.pop(key, None)

    def change_root(self, root_iid: bytes, root_pubkey: bytes) -> None:
        """Atomically install a new root and invalidate all old authority."""

        iid = _strict_bytes(root_iid, 8, "root_iid")
        pubkey = _strict_bytes(root_pubkey, 32, "root_pubkey")
        if _pubkey_to_iid(pubkey) != iid:
            raise TunnelAuthError("root public key does not derive root IID")
        with self._lock:
            if iid == self._root_iid and pubkey == self._root_pubkey:
                return
            self._root_iid = iid
            self._root_pubkey = pubkey
            self._entries.clear()
            self._floors.clear()
            self._revoked.clear()
            self._last_now = None

    def receive_post(
        self,
        body: bytes,
        *,
        oscore_authenticated: bool,
        oscore_sender_iid: bytes,
        now: int,
    ) -> AuthorizationResult:
        """Validate a root POST and atomically cache it, or leave state unchanged."""

        if oscore_authenticated is not True:
            return AuthorizationResult.deny(TunnelDenial.OSCORE_REQUIRED)
        with self._lock:
            expected_root_iid = self._root_iid
            expected_root_pubkey = self._root_pubkey
        if type(oscore_sender_iid) is not bytes or oscore_sender_iid != expected_root_iid:
            return AuthorizationResult.deny(TunnelDenial.WRONG_ROOT)
        try:
            authorization = TunnelAuthorization.from_cose_sign1(body)
        except TunnelAuthError as exc:
            reason = TunnelDenial.ALGORITHM if "algorithm" in str(exc) else TunnelDenial.MALFORMED
            return AuthorizationResult.deny(reason)
        if authorization.root_iid != expected_root_iid:
            return AuthorizationResult.deny(TunnelDenial.WRONG_ROOT)
        if not authorization.verify(expected_root_pubkey):
            return AuthorizationResult.deny(TunnelDenial.SIGNATURE)
        payload = authorization.payload
        if payload.egress_iid != self._egress_iid:
            return AuthorizationResult.deny(TunnelDenial.WRONG_EGRESS)
        key = (payload.target, payload.route_hash)
        with self._lock:
            if self._root_iid != expected_root_iid or self._root_pubkey != expected_root_pubkey:
                return AuthorizationResult.deny(TunnelDenial.WRONG_ROOT)
            try:
                time_error = self._observe_time(now)
            except TunnelAuthError:
                return AuthorizationResult.deny(TunnelDenial.MALFORMED)
            if time_error is not None:
                return AuthorizationResult.deny(time_error)
            if payload.expiry <= now:
                return AuthorizationResult.deny(TunnelDenial.EXPIRED)
            self._purge_expired(now)
            floor = self._floors.get(key)
            if floor is not None and payload.path_seq <= floor:
                reason = TunnelDenial.REVOKED if key in self._revoked else TunnelDenial.REPLAY
                return AuthorizationResult.deny(reason)
            if key not in self._floors and len(self._floors) >= self._max_history:
                return AuthorizationResult.deny(TunnelDenial.CAPACITY)
            # Commit only after every parse, crypto, policy, time, and replay check.
            self._entries[key] = payload
            self._entries.move_to_end(key)
            self._floors[key] = payload.path_seq
            self._floors.move_to_end(key)
            self._revoked.discard(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return AuthorizationResult.permit()

    def revoke(self, target: IPv6Network, route_hash: bytes, through_path_seq: int) -> None:
        """Revoke a route through a sequence floor; only a fresher grant can rearm it."""

        digest = _strict_bytes(route_hash, 16, "route_hash")
        floor = _strict_u64(through_path_seq, "through_path_seq")
        key = (target, digest)
        with self._lock:
            existing = self._floors.get(key)
            if existing is None and len(self._floors) >= self._max_history:
                raise TunnelAuthError("authorization replay history is full")
            self._entries.pop(key, None)
            self._floors[key] = max(floor, existing if existing is not None else 0)
            self._floors.move_to_end(key)
            self._revoked.add(key)

    def authorize_decapsulation(
        self,
        packet: IPv6Packet,
        route: Sequence[IPv6Address | bytes],
        *,
        direction: TunnelDirection,
        now: int,
    ) -> AuthorizationResult:
        """Authorize an inner IPv6 packet at the mesh-to-external boundary."""

        if direction is not TunnelDirection.MESH_TO_EXTERNAL:
            return AuthorizationResult.deny(TunnelDenial.WRONG_DIRECTION)
        try:
            if _iid(route[-1]) != self._egress_iid:
                return AuthorizationResult.deny(TunnelDenial.INVALID_ROUTE)
            digest = compute_route_hash(route)
        except (TunnelAuthError, IndexError):
            return AuthorizationResult.deny(TunnelDenial.INVALID_ROUTE)
        source = packet.header.src_addr
        destination = packet.header.dst_addr
        with self._lock:
            try:
                time_error = self._observe_time(now)
            except TunnelAuthError:
                return AuthorizationResult.deny(TunnelDenial.MALFORMED)
            if time_error is not None:
                return AuthorizationResult.deny(time_error)
            candidates = [
                (key, value)
                for key, value in self._entries.items()
                if key[1] == digest and source in key[0]
            ]
            if not candidates:
                return AuthorizationResult.deny(TunnelDenial.NO_AUTHORIZATION)
            key, authorization = max(candidates, key=lambda item: item[0][0].prefixlen)
            if authorization.expiry <= now:
                self._entries.pop(key, None)
                return AuthorizationResult.deny(TunnelDenial.EXPIRED)
            if not self._policy.source_allowed(source, authorization.target):
                return AuthorizationResult.deny(TunnelDenial.SOURCE_SCOPE)
            if not self._policy.destination_allowed(destination):
                return AuthorizationResult.deny(TunnelDenial.DESTINATION_SCOPE)
            self._entries.move_to_end(key)
        return AuthorizationResult.permit()


class TunnelEgressGateway:
    """Data-plane adapter that never calls the external sink before authorization."""

    def __init__(self, authorizations: TunnelAuthorizationTable) -> None:
        self._authorizations = authorizations

    def forward(
        self,
        packet: IPv6Packet,
        route: Sequence[IPv6Address | bytes],
        *,
        direction: TunnelDirection,
        now: int,
        external_send: Callable[[IPv6Packet], bool],
    ) -> AuthorizationResult:
        decision = self._authorizations.authorize_decapsulation(
            packet, route, direction=direction, now=now
        )
        if not decision.allowed:
            return decision
        try:
            delivered = external_send(packet)
        except Exception:
            return AuthorizationResult.deny(TunnelDenial.DELIVERY_FAILED)
        if delivered is not True:
            return AuthorizationResult.deny(TunnelDenial.DELIVERY_FAILED)
        return decision
