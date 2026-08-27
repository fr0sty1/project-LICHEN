# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /groups/remove`` (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, FORBIDDEN, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    _origin_locally_trusted,
)
from lichen.group_membership import (
    GroupRemoval,
    GroupRoster,
    MembershipError,
    parse_removal,
    removal_preimage,
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
        node_pubkey: bytes | None = None,
    ) -> None:
        super().__init__()
        self.accepted: list[GroupRemoval] = []
        self.roster = roster
        self.pubkeys = dict(pubkeys) if pubkeys else {}
        self.node_id = node_id
        self.collection = collection
        if node_pubkey is not None:
            if type(node_pubkey) is not bytes or len(node_pubkey) != 32:
                raise ValueError("node_pubkey must be a 32-byte Ed25519 public key")
            if self.node_id is None:
                raise ValueError("node_pubkey requires node_id")
            # SECURITY: pin this node's own public key under its id in the
            # same registry used for foreign removers, so a wire delivery
            # claiming removed_by==node_id verifies exactly like any foreign
            # document. An entry already present wins.
            self.pubkeys.setdefault(self.node_id, node_pubkey)
        self._processed_removals: set[bytes] = set()

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
        if removal.removed_by == self.node_id and _origin_locally_trusted(request, self.node_id):
            # Locally authored removal: remote crypto is skipped only for a
            # locally trusted origin (LCI loopback admin, or a pairwise
            # OSCORE identity bound to this node). SECURITY: a wire delivery
            # claiming removed_by==node_id never qualifies -- forced removal
            # burns invitations and rotates the group key, so an unverified
            # path is a repeatable de-enrollment and key-churn primitive.
            pass
        else:
            # SECURITY: fail closed -- an absent public key cannot authorize a
            # membership state change (the inverse of the invite fail-open),
            # and any present authority must carry a valid signature.
            pubkey = self.pubkeys.get(removal.removed_by)
            if pubkey is None or not verify_removal_signature(removal, pubkey):
                return Message(code=FORBIDDEN)

        # A removal document is an authorization to perform one transition,
        # not a reusable rekey command.  Record its canonical signed content
        # before any roster/key mutation.  render_post contains no suspension
        # point, so this check-and-record is atomic on aiocoap's event loop and
        # concurrent delivery of the same document cannot rotate twice.
        replay_key = removal_preimage(removal)
        if replay_key in self._processed_removals:
            return Message(code=FORBIDDEN)
        self._processed_removals.add(replay_key)

        self.accepted.append(removal)
        if self.collection is not None:
            self.collection.rekey(removal.group_id, removed_member=self.node_id)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
