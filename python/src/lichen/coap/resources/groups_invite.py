# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /groups/invite`` (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.group_membership import (
    GroupInvitation,
    GroupRoster,
    MembershipError,
    parse_invitation,
    verify_invitation_signature,
)


class GroupsInviteResource(resource.Resource):
    """Accept a signed invitation document. Crypto check is a sibling bead."""

    rt = "groups.invite"

    def __init__(
        self,
        *,
        roster: GroupRoster | None = None,
        pubkeys: dict[str, bytes] | None = None,
    ) -> None:
        super().__init__()
        self.accepted: list[GroupInvitation] = []
        self.roster = roster
        self.pubkeys = pubkeys or {}

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        try:
            invitation = parse_invitation(body)
        except MembershipError:
            return Message(code=BAD_REQUEST)
        if self.roster is not None and not self.roster.can_invite(invitation.inviter):
            return Message(code=FORBIDDEN)
        pubkey = self.pubkeys.get(invitation.inviter)
        if pubkey is not None and not verify_invitation_signature(invitation, pubkey):
            return Message(code=FORBIDDEN)
        self.accepted.append(invitation)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
