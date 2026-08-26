# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded collision detection for authenticated IPv6 address claims."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hmac import compare_digest
from ipaddress import IPv6Address
from typing import Any, cast

from nacl.bindings import crypto_core_ed25519_is_valid_point

from lichen.crypto.identity import yggdrasil_address

ADDRESS_CLAIM_LIFETIME_SECONDS = 1200
MAX_COLLISION_ADDRESSES = 32
MAX_KEYS_PER_ADDRESS = 4
MAX_MONOTONIC_SECONDS = (1 << 64) - 1

AUTHENTICATED_ADDRESS_SOURCES = frozenset({"link_signature", "oscore", "tofu"})


class AddressCollisionError(ValueError):
    """Base error for rejected collision-detector operations."""


class AddressCollisionTimeError(AddressCollisionError):
    """The monotonic clock regressed or an expiry would overflow."""


class AddressCollisionCapacityError(AddressCollisionError):
    """A bounded address or per-address key capacity was exhausted."""


class AddressBindingError(AddressCollisionError):
    """A known public key is not validly bound to its claimed native address."""


class AddressKind(StrEnum):
    """Collision namespaces have different scope rules."""

    NATIVE = "native"
    LINK_LOCAL = "link_local"


class ObservationStatus(StrEnum):
    """Effect of one authenticated observation."""

    NEW = "new"
    IDEMPOTENT = "idempotent"
    COLLISION = "collision"


@dataclass(frozen=True)
class CollisionObservation:
    """Immutable result of an authenticated address observation."""

    status: ObservationStatus
    kind: AddressKind
    address: IPv6Address
    link_scope: str | None
    public_keys: tuple[bytes, ...]
    expires_at_s: int

    @property
    def is_collision(self) -> bool:
        return len(self.public_keys) > 1


_BucketKey = tuple[AddressKind, bytes, str | None]


def _validate_scope(scope: object) -> str:
    if (
        not isinstance(scope, str)
        or not scope
        or "%" in scope
        or any(char.isspace() for char in scope)
    ):
        raise AddressCollisionError("link_scope must be a non-empty identifier")
    return scope


def _normalize_address(
    address: str | IPv6Address, link_scope: str | None
) -> tuple[_BucketKey, IPv6Address]:
    if not isinstance(address, (str, IPv6Address)):
        raise AddressCollisionError("address must be an IPv6 string or IPv6Address")
    try:
        parsed = IPv6Address(address)
    except ValueError as exc:
        raise AddressCollisionError(f"invalid IPv6 address: {address!r}") from exc

    embedded_scope = parsed.scope_id
    canonical = IPv6Address(parsed.packed)
    if parsed.packed[0] == 0x02:
        if embedded_scope is not None or link_scope is not None:
            raise AddressCollisionError("native addresses must not have a link scope")
        return (AddressKind.NATIVE, canonical.packed, None), canonical
    if parsed.is_link_local:
        if embedded_scope is not None and link_scope is not None and embedded_scope != link_scope:
            raise AddressCollisionError("address zone and link_scope disagree")
        scope = _validate_scope(link_scope if link_scope is not None else embedded_scope)
        return (AddressKind.LINK_LOCAL, canonical.packed, scope), canonical
    raise AddressCollisionError("only native 0200::/8 and link-local fe80::/10 claims are tracked")


def verify_native_address_binding(address: str | IPv6Address, public_key: bytes) -> IPv6Address:
    """Return the canonical address when it equals ``AddrForKey(public_key)``.

    Raw address derivation is deliberately defined for every 32-byte input.
    This authenticated identity boundary is stricter: a known Ed25519 key must
    be a canonical prime-order point, matching signature-verification policy.
    """
    if type(public_key) is not bytes or len(public_key) != 32:
        raise AddressBindingError("known public key must be exactly 32 immutable bytes")
    if not crypto_core_ed25519_is_valid_point(public_key):
        raise AddressBindingError("known public key is not a valid prime-order Ed25519 point")
    if not isinstance(address, (str, IPv6Address)):
        raise AddressBindingError("claimed native address must be an IPv6 string or IPv6Address")
    try:
        parsed = IPv6Address(address)
    except ValueError as exc:
        raise AddressBindingError(f"invalid claimed native IPv6 address: {address!r}") from exc
    if parsed.scope_id is not None or parsed.packed[0] != 0x02:
        raise AddressBindingError("claimed address must be an unscoped native 0200::/8 address")
    canonical = IPv6Address(parsed.packed)
    expected = yggdrasil_address(public_key)
    if not compare_digest(canonical.packed, expected.packed):
        raise AddressBindingError("claimed native address does not match AddrForKey(public_key)")
    return canonical


class AddressCollisionDetector:
    """Track authenticated address-to-key bindings until their evidence expires."""

    def __init__(
        self,
        max_addresses: int = MAX_COLLISION_ADDRESSES,
        max_keys_per_address: int = MAX_KEYS_PER_ADDRESS,
    ) -> None:
        for name, value in (
            ("max_addresses", max_addresses),
            ("max_keys_per_address", max_keys_per_address),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._max_addresses = max_addresses
        self._max_keys_per_address = max_keys_per_address
        self._claims: dict[_BucketKey, dict[bytes, int]] = {}
        self._last_now_s: int | None = None

    def __len__(self) -> int:
        return len(self._claims)

    @property
    def claim_count(self) -> int:
        return sum(len(keys) for keys in self._claims.values())

    def _validate_now(self, now_s: int) -> None:
        if isinstance(now_s, bool) or not isinstance(now_s, int):
            raise AddressCollisionTimeError("now_s must be an integer")
        if not 0 <= now_s <= MAX_MONOTONIC_SECONDS:
            raise AddressCollisionTimeError("now_s is outside the unsigned 64-bit range")
        if self._last_now_s is not None and now_s < self._last_now_s:
            raise AddressCollisionTimeError(
                f"monotonic time regressed from {self._last_now_s} to {now_s}"
            )

    def _purge(self, now_s: int) -> int:
        removed = 0
        for bucket_key in list(self._claims):
            bucket = self._claims[bucket_key]
            for public_key in list(bucket):
                if bucket[public_key] <= now_s:
                    del bucket[public_key]
                    removed += 1
            if not bucket:
                del self._claims[bucket_key]
        return removed

    def observe_authenticated(
        self,
        address: str | IPv6Address,
        public_key: bytes,
        now_s: int,
        *,
        source: str,
        link_scope: str | None = None,
    ) -> CollisionObservation:
        """Refresh one verifier-authenticated key claim for exactly 1200 seconds."""
        bucket_key, canonical = _normalize_address(address, link_scope)
        if type(public_key) is not bytes or len(public_key) != 32:
            raise AddressCollisionError("public_key must be exactly 32 immutable bytes")
        if not isinstance(source, str) or source not in AUTHENTICATED_ADDRESS_SOURCES:
            raise AddressCollisionError(f"unauthenticated address evidence source: {source!r}")
        self._validate_now(now_s)
        if now_s > MAX_MONOTONIC_SECONDS - ADDRESS_CLAIM_LIFETIME_SECONDS:
            raise AddressCollisionTimeError("address-claim expiry would overflow u64")

        active = {
            key: {pubkey: expiry for pubkey, expiry in bucket.items() if expiry > now_s}
            for key, bucket in self._claims.items()
        }
        active = {key: bucket for key, bucket in active.items() if bucket}
        bucket = active.get(bucket_key, {})
        is_existing_key = public_key in bucket
        if bucket_key not in active and len(active) >= self._max_addresses:
            raise AddressCollisionCapacityError(
                f"address collision table is full ({self._max_addresses})"
            )
        if not is_existing_key and len(bucket) >= self._max_keys_per_address:
            raise AddressCollisionCapacityError(
                f"address key capacity is full ({self._max_keys_per_address})"
            )

        self._last_now_s = now_s
        self._purge(now_s)
        live_bucket = self._claims.setdefault(bucket_key, {})
        live_bucket[public_key] = now_s + ADDRESS_CLAIM_LIFETIME_SECONDS
        public_keys = tuple(sorted(live_bucket))
        if is_existing_key:
            status = ObservationStatus.IDEMPOTENT
        elif len(public_keys) > 1:
            status = ObservationStatus.COLLISION
        else:
            status = ObservationStatus.NEW
        return CollisionObservation(
            status=status,
            kind=bucket_key[0],
            address=canonical,
            link_scope=bucket_key[2],
            public_keys=public_keys,
            expires_at_s=live_bucket[public_key],
        )

    def observe_bound_native(
        self,
        address: str | IPv6Address,
        public_key: bytes,
        now_s: int,
        *,
        source: str,
    ) -> CollisionObservation:
        """Validate a known key's native binding, then record its live claim."""
        canonical = verify_native_address_binding(address, public_key)
        return self.observe_authenticated(
            canonical,
            public_key,
            now_s,
            source=source,
        )

    def keys_for(
        self,
        address: str | IPv6Address,
        now_s: int,
        *,
        link_scope: str | None = None,
    ) -> tuple[bytes, ...]:
        """Return live keys for the address namespace in deterministic order."""
        bucket_key, _ = _normalize_address(address, link_scope)
        self._validate_now(now_s)
        self._last_now_s = now_s
        self._purge(now_s)
        return tuple(sorted(self._claims.get(bucket_key, {})))

    def is_collision(
        self,
        address: str | IPv6Address,
        now_s: int,
        *,
        link_scope: str | None = None,
    ) -> bool:
        """Return whether two or more live authenticated keys claim the address."""
        return len(self.keys_for(address, now_s, link_scope=link_scope)) > 1

    def snapshot(self, now_s: int) -> bytes:
        """Serialize live evidence for deterministic restart restoration."""
        self._validate_now(now_s)
        self._last_now_s = now_s
        self._purge(now_s)
        claims = []
        for (kind, packed, scope), bucket in sorted(
            self._claims.items(), key=lambda item: (item[0][0].value, item[0][1], item[0][2] or "")
        ):
            for public_key, expires_at_s in sorted(bucket.items()):
                claims.append(
                    {
                        "kind": kind.value,
                        "address_hex": packed.hex(),
                        "link_scope": scope,
                        "public_key_hex": public_key.hex(),
                        "expires_at_s": expires_at_s,
                    }
                )
        document = {
            "version": 1,
            "last_now_s": now_s,
            "max_addresses": self._max_addresses,
            "max_keys_per_address": self._max_keys_per_address,
            "claims": claims,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

    @classmethod
    def from_snapshot(cls, snapshot: bytes, now_s: int) -> AddressCollisionDetector:
        """Restore a validated snapshot and expire claims at restart time."""
        if type(snapshot) is not bytes:
            raise AddressCollisionError("snapshot must be immutable bytes")
        try:
            parsed_document = json.loads(snapshot.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AddressCollisionError("invalid address-collision snapshot") from exc
        if not isinstance(parsed_document, dict):
            raise AddressCollisionError("invalid address-collision snapshot")
        document = cast(dict[str, Any], parsed_document)
        if document.get("version") != 1 or not isinstance(document.get("claims"), list):
            raise AddressCollisionError("unsupported address-collision snapshot")
        try:
            detector = cls(document["max_addresses"], document["max_keys_per_address"])
            saved_now = document["last_now_s"]
            detector._validate_now(saved_now)
            detector._last_now_s = saved_now
            detector._validate_now(now_s)
            for raw in document["claims"]:
                kind = AddressKind(raw["kind"])
                packed = bytes.fromhex(raw["address_hex"])
                public_key = bytes.fromhex(raw["public_key_hex"])
                scope = raw["link_scope"]
                expires_at_s = raw["expires_at_s"]
                canonical = IPv6Address(packed)
                bucket_key, _ = _normalize_address(canonical, scope)
                if bucket_key[0] is not kind or len(public_key) != 32:
                    raise ValueError("snapshot claim mismatch")
                if type(expires_at_s) is not int or not 0 <= expires_at_s <= MAX_MONOTONIC_SECONDS:
                    raise ValueError("snapshot expiry out of range")
                bucket = detector._claims.setdefault(bucket_key, {})
                if public_key in bucket:
                    raise ValueError("duplicate snapshot claim")
                bucket[public_key] = expires_at_s
        except AddressCollisionTimeError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise AddressCollisionError("invalid address-collision snapshot fields") from exc
        if len(detector._claims) > detector._max_addresses or any(
            len(bucket) > detector._max_keys_per_address for bucket in detector._claims.values()
        ):
            raise AddressCollisionError("snapshot exceeds configured capacity")
        detector._last_now_s = now_s
        detector._purge(now_s)
        return detector
