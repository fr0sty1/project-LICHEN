# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /groups/remove`` (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.groups_collection import GroupsCollectionResource
from lichen.group_membership import (
    GroupRemoval,
    GroupRoster,
    MembershipError,
    parse_removal,
    verify_removal_signature,
)


class GroupsRemoveResource(resource.Resource):
    """Accept a signed removal document."""

    rt = "groups.remove"

    def __init__(
        self,
        *,
        roster: GroupRoster | None = None,
        pubkeys: dict[str, bytes] | None = None,
        node_id: str | None = None,
        collection: GroupsCollectionResource | None = None,
    ) -> None:
        super().__init__()
        self.accepted: list[GroupRemoval] = []
        self.roster = roster
        self.pubkeys = pubkeys or {}
        self.node_id = node_id
        self.collection = collection

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        try:
            removal = parse_removal(body)
        except MembershipError:
            return Message(code=BAD_REQUEST)
        target = self.node_id if self.node_id is not None else removal.group_id
        if self.roster is not None and not self.roster.can_remove(
            removal.removed_by, target=target
        ):
            return Message(code=FORBIDDEN)
        pubkey = self.pubkeys.get(removal.removed_by)
        if pubkey is not None and not verify_removal_signature(removal, pubkey):
            return Message(code=FORBIDDEN)
        self.accepted.append(removal)
        if self.collection is not None:
            self.collection.rekey(removal.group_id, removed_member=self.node_id)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
