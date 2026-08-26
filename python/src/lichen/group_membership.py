# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group invitation and removal domain types (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import cbor2

GroupRoleName = Literal["member", "admin"]
ALLOWED_INVITE_ROLES: frozenset[str] = frozenset({"member", "admin"})


class MembershipError(ValueError):
    """Malformed invitation or removal document."""


@dataclass(frozen=True)
class GroupInvitation:
    group_id: str
    group_name: str
    mcast: str
    inviter: str
    role: GroupRoleName
    expires: int
    signature: bytes

    def to_map(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "mcast": self.mcast,
            "inviter": self.inviter,
            "role": self.role,
            "expires": self.expires,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class GroupRemoval:
    group_id: str
    removed_by: str
    signature: bytes
    reason: str | None = None

    def to_map(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "group_id": self.group_id,
            "removed_by": self.removed_by,
            "signature": self.signature,
        }
        if self.reason is not None:
            document["reason"] = self.reason
        return document


def _require_str(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if type(value) is not str or value == "":
        raise MembershipError(f"{key} must be a non-empty string")
    return value


def parse_invitation(document: dict[str, Any]) -> GroupInvitation:
    if type(document) is not dict:
        raise MembershipError("invitation must be a map")
    role = _require_str(document, "role")
    if role not in ALLOWED_INVITE_ROLES:
        raise MembershipError("role must be member or admin")
    expires = document.get("expires")
    if type(expires) is not int or isinstance(expires, bool) or expires < 0:
        raise MembershipError("expires must be a non-negative integer")
    signature = document.get("signature")
    if type(signature) is not bytes:
        raise MembershipError("signature must be bytes")
    return GroupInvitation(
        group_id=_require_str(document, "group_id"),
        group_name=_require_str(document, "group_name"),
        mcast=_require_str(document, "mcast"),
        inviter=_require_str(document, "inviter"),
        role=role,  # type: ignore[arg-type]
        expires=expires,
        signature=signature,
    )


def invitation_preimage(invitation: GroupInvitation) -> bytes:
    """Canonical CBOR of invitation fields excluding the signature."""
    return cbor2.dumps(
        {
            "expires": invitation.expires,
            "group_id": invitation.group_id,
            "group_name": invitation.group_name,
            "inviter": invitation.inviter,
            "mcast": invitation.mcast,
            "role": invitation.role,
        },
        canonical=True,
    )


def removal_preimage(removal: GroupRemoval) -> bytes:
    """Canonical CBOR of removal fields excluding the signature."""
    document: dict[str, Any] = {
        "group_id": removal.group_id,
        "removed_by": removal.removed_by,
    }
    if removal.reason is not None:
        document["reason"] = removal.reason
    return cbor2.dumps(document, canonical=True)


def verify_invitation_signature(invitation: GroupInvitation, pubkey: bytes) -> bool:
    from lichen.crypto.schnorr48 import verify

    if type(pubkey) is not bytes:
        raise MembershipError("pubkey must be bytes")
    return verify(pubkey, invitation_preimage(invitation), invitation.signature)


def verify_removal_signature(removal: GroupRemoval, pubkey: bytes) -> bool:
    from lichen.crypto.schnorr48 import verify

    if type(pubkey) is not bytes:
        raise MembershipError("pubkey must be bytes")
    return verify(pubkey, removal_preimage(removal), removal.signature)


@dataclass(frozen=True)
class GroupRoster:
    """Authoritative membership used to check invite/remove authority."""

    owner: str
    admins: frozenset[str] = frozenset()
    members: frozenset[str] = frozenset()

    def can_invite(self, inviter: str) -> bool:
        return inviter == self.owner or inviter in self.admins

    def can_remove(self, remover: str, *, target: str) -> bool:
        if remover == self.owner:
            return target != self.owner
        if remover in self.admins:
            return target != self.owner and target not in self.admins
        return False


def parse_removal(document: dict[str, Any]) -> GroupRemoval:
    if type(document) is not dict:
        raise MembershipError("removal must be a map")
    signature = document.get("signature")
    if type(signature) is not bytes:
        raise MembershipError("signature must be bytes")
    reason = document.get("reason")
    if reason is not None and type(reason) is not str:
        raise MembershipError("reason must be a string when present")
    return GroupRemoval(
        group_id=_require_str(document, "group_id"),
        removed_by=_require_str(document, "removed_by"),
        signature=signature,
        reason=reason,
    )
