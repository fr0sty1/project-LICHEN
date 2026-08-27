# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /groups/invite`` (spec/12-apps.md 18.8.2)."""

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
    GroupInvitation,
    GroupRoster,
    MembershipError,
    parse_invitation,
    verify_invitation_signature,
)


class GroupsInviteResource(resource.Resource):
    """Accept a signed invitation document (spec 12-apps.md 18.8.2)."""

    rt = "groups.invite"

    def __init__(
        self,
        *,
        roster: GroupRoster | None = None,
        pubkeys: dict[str, bytes] | None = None,
        node_id: str | None = None,
        collection: GroupsCollectionResource | None = None,
        invitee: str | None = None,
        node_pubkey: bytes | None = None,
    ) -> None:
        super().__init__()
        self.accepted: list[GroupInvitation] = []
        self.roster = roster
        self.pubkeys = dict(pubkeys) if pubkeys else {}
        # Identity of the local node: invitations authored by the local node
        # itself are accepted without remote crypto ONLY from a locally
        # trusted origin; every other inviter and every wire delivery MUST
        # carry a verifiable signature.
        self.node_id = node_id
        self.collection = collection
        self.invitee = invitee
        if node_pubkey is not None:
            if type(node_pubkey) is not bytes or len(node_pubkey) != 32:
                raise ValueError("node_pubkey must be a 32-byte Ed25519 public key")
            if self.node_id is None:
                raise ValueError("node_pubkey requires node_id")
            # SECURITY: pin this node's own public key under its id in the
            # same registry used for foreign inviters, so a wire delivery
            # claiming inviter==node_id verifies exactly like any foreign
            # document instead of relying on the trusted-origin carve-out.
            # An entry already present wins: callers may have provisioned a
            # deliberate trust decision that must not be silently clobbered.
            self.pubkeys.setdefault(self.node_id, node_pubkey)

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
        if self.roster is not None and not self.roster.can_invite(
            invitation.inviter, requested_role=invitation.role
        ):
            return Message(code=FORBIDDEN)
        verified: bool | None = None
        if invitation.inviter == self.node_id and _origin_locally_trusted(request, self.node_id):
            # Provisioning carve-out: locally authored invitations skip
            # remote crypto only when the origin is locally trusted (LCI
            # loopback admin, or a pairwise OSCORE identity bound to this
            # node). SECURITY: no unauthenticated, non-local, unverifiable
            # delivery may reach acceptance -- see the fail-closed branch.
            pass
        else:
            # SECURITY: fail closed -- an inviter whose public key is unknown
            # cannot be authenticated (a forged inviter='owner' document would
            # otherwise unlock join_key), and inviter==node_id deliveries from
            # a non-local origin must verify against the node's own pinned
            # public key exactly like foreign inviters.
            pubkey = self.pubkeys.get(invitation.inviter)
            if pubkey is None:
                return Message(code=FORBIDDEN)
            verified = verify_invitation_signature(invitation, pubkey)
        if verified is False:
            return Message(code=FORBIDDEN)
        recorded = True
        if self.collection is not None and self.invitee is not None:
            recorded = self.collection.record_invitation(
                invitation.group_id,
                self.invitee,
                expires=invitation.expires,
                role=invitation.role,
                inviter=invitation.inviter,
            )
        if not recorded:
            # spec 18.8.2 response semantics: an expired, replayed, or revoked
            # document is declined now rather than accepted into a ledger that
            # join_key later refuses as an opaque failure.
            return Message(code=FORBIDDEN)
        self.accepted.append(invitation)
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
