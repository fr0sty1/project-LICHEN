# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group OSCORE key distribution (spec 18.8.5, vectors ``group_oscore_key.json``).

A group controller holds the current group key and distributes it to members
pairwise: each member receives the group key encrypted under a key derived
from an X25519 exchange with the member's own public key, so no other member
(or observer) can unwrap it.

Contract highlights (operative contract is the vector file):

- Pairwise wrap: unique ciphertext per member pubkey
  (X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305-IETF).
- ``key_epoch``: monotonic u32 counter, incremented on every rekey;
  wraps after ``0xFFFFFFFF``.
- OSCORE context isolation: ``id_context = group_id || key_epoch(u32 BE)``.
- Grace window: after a rekey the previous key stays valid for one hour
  (strict expiry), so stragglers can still decrypt in-flight traffic.
- Epoch validation: messages stamped with an epoch below the current one are
  rejected (rollback/replay); epochs more than one above the current one are
  rejected (unknown future key).
- Membership: rekey distributes to current members only (removed members get
  no new key material but can still decrypt the previous key during grace);
  newly added members receive only the current key, never historical ones.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass

import nacl.bindings as bindings

# Old key remains valid this long after a rekey (spec 18.8.5 grace window).
GRACE_PERIOD_S = 3600

# key_epoch is a u32 monotonic counter; it wraps after this value.
EPOCH_WRAP = 0xFFFFFFFF

# Domain separators for HKDF derivations.
_WRAP_INFO = b"LICHEN-GROUP-WRAP-v1"
_NONCE_INFO = b"LICHEN-GROUP-WRAP-NONCE-v1"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with SHA-256 (extract-then-expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def _to_x25519_public(ed25519_pubkey: bytes) -> bytes:
    """Convert an Ed25519 public key to its Curve25519 equivalent."""
    return bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pubkey)


def _to_x25519_private(ed25519_scalar: bytes) -> bytes:
    """Map a LICHEN Ed25519 private scalar to its Curve25519 equivalent.

    ``derive_keypair`` already returns the clamped ``SHA-512(seed)[:32]``
    scalar that Ed25519 uses, which is exactly the X25519 private scalar for
    the same key -- no further hashing (libsodium's ``*_sk_to_curve25519``
    expects a raw seed and would hash a second time).
    """
    if len(ed25519_scalar) != 32:
        raise ValueError("ed25519 private scalar must be 32 bytes")
    return ed25519_scalar


@dataclass(frozen=True)
class GroupKeyMaterial:
    """A group key bound to its epoch."""

    epoch: int
    key: bytes
    created_s: float


class GroupKeyManager:
    """Distributes and rotates a group key among authenticated members.

    Args:
        group_id: Stable group identifier (used in OSCORE id_context).
        group_key: Initial group key material (e.g. 16-byte AES-CCM key).
        members: Mapping of member IID (hex) -> Ed25519 public key.
        time_func: Monotonic clock; defaults to :func:`time.monotonic`
            (spec 18.10.3-style uptime requirement applies equally here).
    """

    def __init__(
        self,
        group_id: bytes,
        group_key: bytes,
        members: dict[str, bytes] | None = None,
        *,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        self.group_id = group_id
        self._time_func = time_func if time_func is not None else time.monotonic
        self._current = GroupKeyMaterial(
            epoch=1, key=group_key, created_s=self._time_func()
        )
        self._previous: list[GroupKeyMaterial] = []
        self.members: dict[str, bytes] = dict(members or {})

    # -- epoch / context ----------------------------------------------------

    @property
    def epoch(self) -> int:
        """Current key_epoch."""
        return self._current.epoch

    def oscore_id_context(self, epoch: int | None = None) -> bytes:
        """OSCORE id_context: ``group_id || key_epoch`` (u32 big-endian)."""
        e = self._current.epoch if epoch is None else epoch
        return self.group_id + struct.pack(">I", e)

    def validate_epoch(self, message_epoch: int) -> tuple[bool, str]:
        """Validate an incoming message epoch against the current one.

        Returns ``(accept, reason)``; reasons mirror the vector names:
        ``epoch_rollback`` for anything below the current epoch,
        ``future_epoch_unknown`` for anything more than one above.
        """
        if message_epoch < self._current.epoch:
            return False, "epoch_rollback"
        if message_epoch > self._current.epoch + 1:
            return False, "future_epoch_unknown"
        return True, "ok"

    # -- key validity / grace -----------------------------------------------

    def key_valid_at(self, material: GroupKeyMaterial, now_s: float | None = None) -> bool:
        """Whether *material* may still be used at *now_s*.

        The current key is always valid; superseded keys remain valid until
        their grace window expires (strictly, per the 3600001 ms vector).
        """
        if now_s is None:
            now_s = self._time_func()
        if material.epoch == self._current.epoch:
            return True
        return now_s - material.created_s <= GRACE_PERIOD_S

    def key_for_epoch(self, epoch: int) -> GroupKeyMaterial | None:
        """Return key material for *epoch* if we ever held it."""
        if self._current.epoch == epoch:
            return self._current
        for material in reversed(self._previous):
            if material.epoch == epoch:
                return material
        return None

    # -- distribution --------------------------------------------------------

    def distribute_current(self, member_iids: list[str] | None = None) -> dict[str, bytes]:
        """Wrap the current group key pairwise for the given (or all) members."""
        targets = member_iids if member_iids is not None else list(self.members)
        wrapped: dict[str, bytes] = {}
        for iid in targets:
            try:
                pubkey = self.members[iid]
            except KeyError as exc:  # unknown member: no key material
                raise KeyError(f"unknown group member: {iid}") from exc
            wrapped[iid] = pairwise_wrap(self._current.key, pubkey)
        return wrapped

    def rekey(self, new_key: bytes | None = None) -> dict[str, bytes]:
        """Rotate the group key and distribute it to every current member.

        Removed members are excluded automatically (forward secrecy on
        removal); they can still decrypt the previous key during grace.
        """
        if new_key is None:
            new_key = bindings.randombytes(16)
        self._previous.append(self._current)
        self._current = GroupKeyMaterial(
            epoch=(1 if self._current.epoch == EPOCH_WRAP else self._current.epoch + 1),
            key=new_key,
            created_s=self._time_func(),
        )
        return self.distribute_current()

    # -- membership -----------------------------------------------------------

    def add_member(self, iid: str, pubkey: bytes) -> bytes:
        """Admit a member; returns the current key wrapped for them only.

        New members never receive historical key material (no backward
        access).
        """
        self.members[iid] = pubkey
        return pairwise_wrap(self._current.key, pubkey)

    def remove_member(self, iid: str) -> None:
        """Remove a member. They keep access only until the next rekey."""
        self.members.pop(iid, None)


def pairwise_wrap(group_key: bytes, member_ed25519_pubkey: bytes) -> bytes:
    """Wrap *group_key* for one member (unique ciphertext per pubkey).

    Layout: ``ephemeral_x25519_pub (32 B) || ChaCha20-Poly1305-IETF
    ciphertext(group_key)``. The ephemeral scalar is derived deterministically
    from (group_key, member_pubkey) so wrapping is reproducible for testing
    while remaining unique per member. KEK and nonce are derived from the
    ECDH shared secret, so the receiver can recompute both.

    Raises:
        ValueError: If the member key cannot be converted to Curve25519.
    """
    member_x_pub = _to_x25519_public(member_ed25519_pubkey)
    eph_seed = hkdf_sha256(
        group_key, salt=b"LICHEN-GROUP-WRAP-v1", info=_WRAP_INFO + member_x_pub
    )
    eph_pub = bindings.crypto_scalarmult_base(eph_seed)
    shared = bindings.crypto_scalarmult(eph_seed, member_x_pub)
    kek = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_WRAP_INFO)
    nonce = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_NONCE_INFO, length=12)
    ciphertext = bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        group_key, aad=member_x_pub, nonce=nonce, key=kek
    )
    return eph_pub + ciphertext


def pairwise_unwrap(
    wrapped: bytes,
    member_ed25519_seed: bytes,
    member_ed25519_pubkey: bytes,
) -> bytes:
    """Undo :func:`pairwise_wrap`; returns the original group key."""
    if len(wrapped) < 32 + 16:
        raise ValueError("wrapped key too short")
    eph_pub, ciphertext = wrapped[:32], wrapped[32:]
    member_x_pub = _to_x25519_public(member_ed25519_pubkey)
    member_x_priv = _to_x25519_private(member_ed25519_seed)
    shared = bindings.crypto_scalarmult(member_x_priv, eph_pub)
    kek = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_WRAP_INFO)
    nonce = hkdf_sha256(shared, salt=eph_pub + member_x_pub, info=_NONCE_INFO, length=12)
    return bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        ciphertext, aad=member_x_pub, nonce=nonce, key=kek
    )


__all__ = [
    "EPOCH_WRAP",
    "GRACE_PERIOD_S",
    "GroupKeyManager",
    "GroupKeyMaterial",
    "hkdf_sha256",
    "pairwise_unwrap",
    "pairwise_wrap",
]
