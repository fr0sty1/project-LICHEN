# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Spec 12 18.8.2 invitation/removal maps vs group_membership types."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.group_membership import (
    ALLOWED_INVITE_ROLES,
    MembershipError,
    parse_invitation,
    parse_removal,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"


def _load() -> dict:
    return json.loads((VECTORS / "groups_membership.json").read_text(encoding="utf-8"))


def test_invitation_and_removal_vectors() -> None:
    document = _load()
    assert set(ALLOWED_INVITE_ROLES) == {"member", "admin"}
    for case in document["vectors"]:
        payload = dict(case["payload"])
        if "signature_hex" in payload:
            payload["signature"] = bytes.fromhex(payload.pop("signature_hex"))
        if case["kind"] == "invitation":
            parsed = parse_invitation(payload)
            assert parsed.group_id == case["payload"]["group_id"]
            assert parsed.role == case["payload"]["role"]
            assert parsed.expires == case["payload"]["expires"]
        else:
            parsed = parse_removal(payload)
            assert parsed.group_id == case["payload"]["group_id"]
            assert parsed.removed_by == case["payload"]["removed_by"]


def test_roster_authority() -> None:
    from lichen.group_membership import GroupRoster

    roster = GroupRoster(
        owner="owner",
        admins=frozenset({"admin"}),
        members=frozenset({"member"}),
    )
    assert roster.can_invite("owner")
    assert roster.can_invite("admin")
    assert not roster.can_invite("member")
    # spec 18.8.2 L1129-1143: promotion/demotion is reserved to the owner,
    # so an admin may mint only member-role invitations.
    assert roster.can_invite("owner", requested_role="admin")
    assert roster.can_invite("owner", requested_role="member")
    assert not roster.can_invite("admin", requested_role="admin")
    assert roster.can_invite("admin", requested_role="member")
    assert not roster.can_invite("member", requested_role="member")
    assert roster.can_remove("owner", target="member")
    assert not roster.can_remove("admin", target="owner")
    assert not roster.can_remove("admin", target="admin")
    assert roster.can_remove("admin", target="member")


def test_invitation_signature_roundtrip() -> None:
    from lichen.crypto.identity import Identity
    from lichen.crypto.schnorr48 import sign
    from lichen.group_membership import (
        invitation_preimage,
        parse_invitation,
        verify_invitation_signature,
    )

    identity = Identity.from_seed(b"\x01" * 32)
    draft = parse_invitation(
        {
            "group_id": "team-alpha",
            "group_name": "Team Alpha",
            "mcast": "ff35::1",
            "inviter": "0200::1",
            "role": "member",
            "expires": 1,
            "signature": b"\x00" * 48,
        }
    )
    sig = sign(identity.privkey, identity.pubkey, invitation_preimage(draft))
    signed = parse_invitation({**draft.to_map(), "signature": sig})
    assert verify_invitation_signature(signed, identity.pubkey) is True
    assert verify_invitation_signature(signed, Identity.from_seed(b"\x02" * 32).pubkey) is False


def test_invitation_rejects_owner_role() -> None:
    with pytest.raises(MembershipError):
        parse_invitation(
            {
                "group_id": "team-alpha",
                "group_name": "Team Alpha",
                "mcast": "ff35::1",
                "inviter": "0200::1",
                "role": "owner",
                "expires": 1,
                "signature": b"\x00",
            }
        )
