# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``/groups`` collection and ``/groups/{id}`` (spec/12-apps.md 18.8)."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from hashlib import sha256
from threading import Lock
from typing import Any

import cbor2
from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    CREATED,
    DELETED,
    FORBIDDEN,
    INTERNAL_SERVER_ERROR,
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    Message,
    resource,
)

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.messaging import _peer_is_local_admin
from lichen.group_membership import ALLOWED_INVITE_ROLES
from lichen.ipv6.addr import NATIVE_NETWORK, AddrError, group_multicast_from_id, to_ipv6

OSCORE_GROUP_ALG = "AES-CCM-16-64-128"
REKEY_GRACE_S = 3600

# Caps for constrained nodes (spec 18.8)
MAX_GROUPS = 16
MAX_MEMBERS_PER_GROUP = 64
MAX_RETIRED_EPOCHS = 8


def _groups_full_response(reason: str) -> Message:
    """5.03 SERVICE_UNAVAILABLE with CBOR reason, consistent with deaddrop."""
    msg = Message(code=SERVICE_UNAVAILABLE)
    msg.opt.content_format = CBOR
    msg.payload = cbor2.dumps({"reason": reason})
    return msg


def _bound_oscore_identity(value: object) -> str | None:
    """Return a distinct OSCORE identity from a post-unprotect binding, or None.

    SECURITY: Only identities attached after successful unprotect count.
    Strings and non-empty byte strings are accepted. Arbitrary objects are
    not stringified, and CoAP option values are never consulted.

    Note: Context objects with durable_context_id() prove authentication but
    do not provide the peer identity for roster matching. The peer identity
    (typically an IPv6 address) must be set explicitly in oscore_context_id.
    """
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value).hex()
    return None


def _is_group_oscore_context(value: object) -> bool:
    """True when *value* is a group (RFC 9203) OSCORE context, not pairwise."""
    return (
        value == "group"
        or bool(getattr(value, "external_aad_is_group", False))
        or bool(getattr(value, "is_signing", False))
    )


def _request_oscore_values(request: Message) -> list[object]:
    """Return OSCORE binding values from the request and its post-unprotect remote."""
    values: list[object] = []
    for holder in (request, getattr(request, "remote", None)):
        if holder is None:
            continue
        values.append(getattr(holder, "oscore_context", None))
        values.append(getattr(holder, "oscore_context_id", None))
    return values


def _group_oscore_values(request: Message) -> list[object]:
    """Return live RFC 9203 context bindings attached after unprotect."""
    return [value for value in _request_oscore_values(request) if _is_group_oscore_context(value)]


def _group_oscore_value_matches(item: dict[str, Any], value: object) -> bool:
    """Bind a live RFC 9203 context to this exact group and current epoch."""
    if item.get("encrypted") is not True:
        return False
    group_id = item.get("id")
    epoch = item.get("key_epoch")
    if type(group_id) is not str or type(epoch) is not int:
        return False
    try:
        expected_id_context = bytes.fromhex(group_id) + epoch.to_bytes(4, "big")
    except (ValueError, OverflowError):
        return False

    for attribute in ("id_context", "context_id", "kid_context"):
        candidate = getattr(value, attribute, None)
        if isinstance(candidate, (bytes, bytearray)):
            return bytes(candidate) == expected_id_context

    bound_group_id = getattr(value, "group_id", None)
    bound_epoch = getattr(value, "key_epoch", None)
    if type(bound_epoch) is int and bound_epoch == epoch:
        if bound_group_id == group_id:
            return True
        if isinstance(bound_group_id, (bytes, bytearray)):
            return bytes(bound_group_id) == bytes.fromhex(group_id)

    key_id = item.get("key_id")
    return type(key_id) is str and getattr(value, "key_id", None) == key_id


def _group_oscore_context_matches(item: dict[str, Any], request: Message) -> bool:
    """True only when every supplied group context names *item*'s live epoch."""
    values = _group_oscore_values(request)
    return bool(values) and all(_group_oscore_value_matches(item, value) for value in values)


def _pairwise_oscore_identity(request: Message) -> str | None:
    """Return the pairwise OSCORE identity bound after successful unprotect.

    SECURITY: spec 18.8.2 key distribution MUST use the pairwise OSCORE
    context from EDHOC. Never sent in plaintext. Presence of the CoAP
    OSCORE option (``opt.oscore`` / ``object_security``) is not
    authentication: unprotect reconstructs an inner request without that
    option, and an unprotected client can attach option 9 to plaintext.
    A boolean ``oscore_protected`` flag without a distinct identity is
    also not authentication. Group OSCORE contexts are rejected.
    """
    values = _request_oscore_values(request)
    if any(value is not None and _is_group_oscore_context(value) for value in values):
        return None
    identities = {
        identity
        for value in values
        if (identity := _bound_oscore_identity(value)) is not None
    }
    # Multiple post-unprotect identities are an invalid/ambiguous binding.
    return next(iter(identities)) if len(identities) == 1 else None


def _oscore_required_response() -> Message:
    """4.01 with no key material (spec 18.8.2: never sent in plaintext)."""
    msg = _cbor_response({"error": "oscore_required"})
    msg.code = UNAUTHORIZED
    return msg


def _origin_locally_trusted(request: Message, node_id: str | None) -> bool:
    """True when *request* originates from a locally trusted authority.

    SECURITY: membership documents claiming local authorship (inviter or
    removed_by equal to ``node_id``) may only skip remote signature
    verification when the transport origin itself is trusted: an LCI
    loopback admin peer, or a pairwise OSCORE identity bound after unprotect
    to this node's own id. A peer's own pairwise context does not qualify --
    a wire delivery claiming local authorship must verify against the
    node's pinned public key exactly like any foreign document.
    """
    if _peer_is_local_admin(getattr(request, "remote", None)):
        return True
    return node_id is not None and _pairwise_oscore_identity(request) == node_id


def group_id_from_name(name: str) -> str:
    """Stable group id: spec allows name hash."""
    return sha256(name.encode("utf-8")).hexdigest()[:12]


def mcast_from_id(group_id: str, prefix: str | None = None) -> str:
    """RFC 3306 ``ff35:0040:<02xx /64>::<16-bit SHA-256(id)>`` (spec 18.8.3)."""
    return str(group_multicast_from_id(group_id, prefix=prefix))


def _owner_mcast_prefix(owner: str) -> str | None:
    """Use the owner's 0200::/8 /64 when owner is a native unicast address."""
    try:
        addr = to_ipv6(owner)
    except AddrError:
        return None
    if addr not in NATIVE_NETWORK:
        return None
    return owner


def _invitation_identity(
    inviter: str, node: str, *, expires: int | None, role: str
) -> str:
    """Stable invitation document identity: hash of inviter+node+role+expires.

    SECURITY: two documents over the same (inviter, invitee, role, expiry)
    are indistinguishable replays of one enrollment grant, so consumption
    markers keyed by this identity survive ledger pops during rekey.
    """
    document = {
        "expires": expires,
        "inviter": inviter,
        "node": node,
        "role": role,
    }
    return sha256(cbor2.dumps(document, canonical=True)).hexdigest()


def public_group_document(item: dict[str, Any]) -> dict[str, Any]:
    """18.8.1 group document without key material or roster arrays.

    SECURITY: spec 18.8.2 -- the full membership list is NOT broadcast.
    ``admins``/``members`` are only served over the protected resources to
    requesters authorized per 18.8.2.
    """
    document: dict[str, Any] = {
        "id": item["id"],
        "name": item["name"],
        "mcast": item["mcast"],
        "owner": item["owner"],
        "created": item["created"],
        "key_epoch": item.get("key_epoch", 1),
    }
    if item.get("key_id") is not None:
        document["key_id"] = item["key_id"]
    return document


class GroupsCollectionResource(resource.Resource):
    """List and create groups at ``/groups`` (spec 18.8.4)."""

    rt = "groups"

    def __init__(
        self,
        *,
        owner: str = "local",
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__()
        self.owner = owner
        self._clock = clock or time.time
        self.groups: dict[str, dict[str, Any]] = {}
        self._mutation_lock = Lock()

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}

    async def render_get(self, request: Message) -> Message:
        del request
        listing = [
            {
                "id": item["id"],
                "name": item["name"],
                "members": len(item.get("members") or []),
            }
            for item in self.groups.values()
        ]
        return _cbor_response({"groups": listing})

    async def render_post(self, request: Message) -> Message:
        return await self._create(request)

    async def _create(self, request: Message) -> Message:
        creator = _pairwise_oscore_identity(request)
        if creator is None:
            return _oscore_required_response()
        if creator != self.owner:
            return Message(code=FORBIDDEN)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        name = body.get("name")
        encrypted = body.get("encrypted", False)
        if type(name) is not str or name == "":
            return Message(code=BAD_REQUEST)
        if type(encrypted) is not bool:
            return Message(code=BAD_REQUEST)
        group_id = group_id_from_name(name)
        with self._mutation_lock:
            if group_id in self.groups:
                return Message(code=BAD_REQUEST)
            if len(self.groups) >= MAX_GROUPS:
                return _groups_full_response("groups_full")
            stamp = int(self._clock())
            record: dict[str, Any] = {
                "id": group_id,
                "name": name,
                "mcast": mcast_from_id(group_id, prefix=_owner_mcast_prefix(creator)),
                "encrypted": encrypted,
                "owner": creator,
                "admins": [],
                "members": [creator],
                "created": stamp,
                "key_epoch": 1,
            }
            response: dict[str, Any] = {
                "id": group_id,
                "mcast": record["mcast"],
            }
            if encrypted:
                try:
                    master_secret = os.urandom(32)
                    master_salt = os.urandom(8)
                except OSError:
                    return Message(code=INTERNAL_SERVER_ERROR)
                record["key_id"] = f"key-{group_id}-001"
                record["master_secret"] = master_secret
                record["master_salt"] = master_salt
                record["key_expires"] = stamp + 86400
                response["key_id"] = record["key_id"]
                response["master_secret"] = master_secret
                response["master_salt"] = master_salt
            self.groups[group_id] = record
        msg = _cbor_response(response)
        msg.code = CREATED
        msg.opt.location_path = ("groups", group_id)
        return msg

    def rekey(self, group_id: str, *, removed_member: str | None = None) -> dict[str, Any] | None:
        """Rotate group key after member removal (spec 18.8.2).

        SECURITY: the retired (master_secret, master_salt, key_id, key_epoch)
        stay available for unprotect until REKEY_GRACE_S elapses; the owner is
        never stripped from members (spec 18.8.2: Owner is always a member);
        the removed member's invitation is revoked.
        """
        # Rekey is also the authoritative roster transition. Serialize it so
        # concurrent removals cannot rotate from the same epoch, and prepare
        # every fallible value before committing any membership or key state.
        with self._mutation_lock:
            item = self.groups.get(group_id)
            if item is None or not item.get("encrypted"):
                return None

            stamp = int(self._clock())
            old_epoch = int(item["key_epoch"])
            new_epoch = old_epoch + 1
            new_secret = os.urandom(32)
            new_salt = os.urandom(8)

            members = list(item.get("members") or [])
            admins = list(item.get("admins") or [])
            burned = dict(item.get("consumed_invitations") or {})
            invitations_value = item.get("invitations")
            invitations = (
                dict(invitations_value) if isinstance(invitations_value, dict) else None
            )
            if removed_member is not None and removed_member != item.get("owner"):
                members = [member for member in members if member != removed_member]
                admins = [admin for admin in admins if admin != removed_member]
                if invitations is not None:
                    popped = invitations.pop(removed_member, None)
                    if isinstance(popped, dict):
                        # SECURITY: forced removal burns the invitation
                        # identity so replaying the still-signed document can
                        # never resurrect the revoked enrollment.
                        identity = popped.get("identity")
                        if type(identity) is str and identity:
                            burned[identity] = True

            retired = list(self._live_retired(item, stamp))
            retired.append(
                {
                    "key_epoch": old_epoch,
                    "master_secret": item.get("master_secret"),
                    "master_salt": item.get("master_salt"),
                    "key_id": item.get("key_id"),
                    "expires": stamp + REKEY_GRACE_S,
                }
            )
            # Cap retired epochs to prevent unbounded growth
            if len(retired) > MAX_RETIRED_EPOCHS:
                retired = retired[-MAX_RETIRED_EPOCHS:]
            updated: dict[str, Any] = {
                "members": members,
                "admins": admins,
                "consumed_invitations": burned,
                "retired_epochs": retired,
                "key_epoch": new_epoch,
                "master_secret": new_secret,
                "master_salt": new_salt,
                "key_id": f"key-{group_id}-{new_epoch:03d}",
                "key_expires": stamp + 86400,
            }
            if invitations is not None:
                updated["invitations"] = invitations
            item.update(updated)
            return {"key_id": item["key_id"], "key_epoch": new_epoch}

    def _live_retired(
        self, item: dict[str, Any], stamp: int, *, mutate: bool = False
    ) -> list[dict[str, Any]]:
        """Retired key entries still inside their grace window at *stamp*."""
        live = [
            entry for entry in item.get("retired_epochs") or [] if stamp < int(entry["expires"])
        ]
        if mutate:
            item["retired_epochs"] = live
        return live

    def epoch_accepted(self, group_id: str, epoch: int, *, now: int | None = None) -> bool:
        """Current epoch always; retired epochs only until grace expiry."""
        item = self.groups.get(group_id)
        if item is None:
            return False
        if epoch == item.get("key_epoch"):
            return True
        stamp = int(self._clock() if now is None else now)
        return any(int(entry["key_epoch"]) == epoch for entry in self._live_retired(item, stamp))

    def group_key_for_epoch(
        self, group_id: str, epoch: int, *, now: int | None = None
    ) -> dict[str, Any] | None:
        """Unprotect-capable key material for *epoch* during the rekey grace (18.8.2).

        The grace prune writes ``retired_epochs`` back, so the read-and-prune
        runs under ``_mutation_lock``: an unlocked prune could clobber retired
        entries a locked rekey appended concurrently, losing grace-window
        unprotect material. ``_mutation_lock`` is not reentrant -- callers
        already inside a locked section must not invoke this method.
        """
        with self._mutation_lock:
            item = self.groups.get(group_id)
            if item is None:
                return None
            stamp = int(self._clock() if now is None else now)
            current = {
                "key_epoch": item.get("key_epoch"),
                "master_secret": item.get("master_secret"),
                "master_salt": item.get("master_salt"),
                "key_id": item.get("key_id"),
            }
            if epoch == item.get("key_epoch"):
                return current
            for entry in self._live_retired(item, stamp, mutate=now is None):
                if int(entry["key_epoch"]) == epoch:
                    return {
                        "key_epoch": entry["key_epoch"],
                        "master_secret": entry["master_secret"],
                        "master_salt": entry["master_salt"],
                        "key_id": entry["key_id"],
                    }
            return None

    def record_invitation(
        self,
        group_id: str,
        node: str,
        *,
        expires: int | None = None,
        role: str = "member",
        inviter: str | None = None,
    ) -> bool:
        """Record an accepted invitation held by *node* (spec 18.8.2 invitations).

        With *inviter* supplied the document identity is tracked, and a
        document whose identity was already consumed by join_key (or burned
        by forced removal) is refused: replaying a signed invitation cannot
        resurrect a revoked enrollment.
        """
        # The burned-identity check and the invitations write are one
        # transition; serialize against rekey's locked snapshot/rebuild.
        with self._mutation_lock:
            item = self.groups.get(group_id)
            if item is None:
                return False
            if type(node) is not str or node == "":
                return False
            if role not in ALLOWED_INVITE_ROLES:
                return False
            if expires is not None and (type(expires) is not int or expires <= int(self._clock())):
                return False
            identity: str | None = None
            if type(inviter) is str and inviter != "":
                identity = _invitation_identity(inviter, node, expires=expires, role=role)
                burned = item.setdefault("consumed_invitations", {})
                if identity in burned:
                    return False
            invited = item.setdefault("invitations", {})
            entry: dict[str, Any] = {"expires": expires, "role": role}
            if identity is not None:
                entry["identity"] = identity
            invited[node] = entry
            return True

    def invitation_consumed(self, group_id: str, node: str) -> bool:
        """True when *node*'s live invitation has already been spent once."""
        entry = self._invitation_entry(group_id, node)
        if entry is None:
            return False
        return bool(entry.get("consumed"))

    def consume_invitation(self, group_id: str, node: str) -> None:
        """Spend *node*'s invitation with a one-time enrollment marker."""
        with self._mutation_lock:
            self._consume_invitation_unlocked(group_id, node)

    def _consume_invitation_unlocked(self, group_id: str, node: str) -> None:
        """Consume without acquiring the mutation lock (caller holds it).

        ``_mutation_lock`` is not reentrant, so callers already inside a
        locked section (``_join_key``) must use this variant instead of the
        public wrapper to avoid deadlocking the event loop.
        """
        item = self.groups.get(group_id)
        if item is None:
            return
        entry = self._invitation_entry(group_id, node)
        if entry is None:
            return
        invited = item.get("invitations")
        if isinstance(invited, dict) and not isinstance(invited.get(node), dict):
            # SECURITY: legacy scalar entries (pre-normalization persisted
            # shape) synthesize a throwaway dict in _invitation_entry; the
            # burn marker below would land on that copy and the one-time
            # spend would be silently lost. Persist the normalized dict so
            # the consumed marker survives.
            invited[node] = entry
        entry["consumed"] = True
        identity = entry.get("identity")
        if type(identity) is str and identity:
            item.setdefault("consumed_invitations", {})[identity] = True

    def _invitation_entry(self, group_id: str, node: str) -> dict[str, Any] | None:
        item = self.groups.get(group_id)
        if item is None:
            return None
        invited = item.get("invitations")
        if not isinstance(invited, dict) or node not in invited:
            return None
        entry = invited[node]
        if isinstance(entry, dict):
            return entry
        return {"expires": entry, "role": "member"}

    def invitation_valid(self, group_id: str, node: str, *, now: int | None = None) -> bool:
        """True while *node* holds an unexpired invitation for *group_id*."""
        entry = self._invitation_entry(group_id, node)
        if entry is None:
            return False
        expires = entry.get("expires")
        if expires is None:
            return True
        stamp = int(self._clock() if now is None else now)
        return stamp < int(expires)

    def invitation_role(self, group_id: str, node: str, *, now: int | None = None) -> str | None:
        """Invited 18.8.2 role for *node*, or None when the invitation is absent/expired."""
        if not self.invitation_valid(group_id, node, now=now):
            return None
        entry = self._invitation_entry(group_id, node)
        if entry is None:
            return None
        role = entry.get("role", "member")
        if role not in ALLOWED_INVITE_ROLES:
            return "member"
        return str(role)

    def requester_role(self, group_id: str, peer: str | None) -> str | None:
        """18.8.2 role of peer: 'owner', 'admin', 'member', or None."""
        item = self.groups.get(group_id)
        if item is None or peer is None:
            return None
        if peer == item.get("owner"):
            return "owner"
        members = item.get("members") or []
        # Admins are always members (18.8.2). Fail closed for stale persisted
        # rosters rather than granting authority from an orphaned admin entry.
        if peer in members and peer in (item.get("admins") or []):
            return "admin"
        if peer in members:
            return "member"
        return None


class GroupsItemResource(resource.Resource, resource.PathCapable):
    """``/groups/{id}`` GET/PUT/DELETE and ``/groups/{id}/key`` (spec 18.8)."""

    rt = "groups.item"

    def __init__(self, collection: GroupsCollectionResource) -> None:
        super().__init__()
        self.collection = collection

    def _rest(self, request: Message) -> tuple[str, ...]:
        path = tuple(request.opt.uri_path or ())
        if path and path[0] == "groups":
            path = path[1:]
        return path

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}

    def _roster_view_authorized(self, item: dict[str, Any], request: Message) -> bool:
        """18.8.2: group OSCORE context, or a roster-affiliated pairwise peer."""
        if _group_oscore_context_matches(item, request):
            return True
        peer = _pairwise_oscore_identity(request)
        return peer is not None and (self.collection.requester_role(item["id"], peer) is not None)

    async def render_get(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) == 1:
            item = self.collection.groups.get(rest[0])
            if item is None:
                return Message(code=NOT_FOUND)
            if _group_oscore_values(request) and not _group_oscore_context_matches(item, request):
                return Message(code=FORBIDDEN)
            document = public_group_document(item)
            if self._roster_view_authorized(item, request):
                document["admins"] = list(item.get("admins") or [])
                document["members"] = list(item.get("members") or [])
            return _cbor_response(document)
        if len(rest) == 2 and rest[1] == "key":
            item = self.collection.groups.get(rest[0])
            if item is None or not item.get("encrypted"):
                return Message(code=NOT_FOUND)
            return _cbor_response(
                {
                    "key_id": item["key_id"],
                    "algorithm": OSCORE_GROUP_ALG,
                    "expires": item.get("key_expires"),
                }
            )
        if len(rest) == 2 and rest[1] == "members":
            item = self.collection.groups.get(rest[0])
            if item is None:
                return Message(code=NOT_FOUND)
            if not _group_oscore_values(request) and _pairwise_oscore_identity(request) is None:
                return _oscore_required_response()
            if not self._roster_view_authorized(item, request):
                return Message(code=FORBIDDEN)
            return _cbor_response(
                {
                    "owner": item["owner"],
                    "admins": list(item.get("admins") or []),
                    "members": list(item.get("members") or []),
                }
            )
        return Message(code=NOT_FOUND)

    async def render_put(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) != 1:
            return Message(code=METHOD_NOT_ALLOWED)
        peer = _pairwise_oscore_identity(request)
        if peer is None:
            return _oscore_required_response()
        item = self.collection.groups.get(rest[0])
        if item is None:
            return Message(code=NOT_FOUND)
        # spec 18.8.2 roles: rename is full control, reserved to the owner.
        # Admin/member pairwise identities are authenticated but not authorized.
        if self.collection.requester_role(rest[0], peer) != "owner":
            return Message(code=FORBIDDEN)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        unknown = set(body) - {"name"}
        if unknown:
            return Message(code=BAD_REQUEST)
        name = body.get("name")
        if type(name) is not str or name == "":
            return Message(code=BAD_REQUEST)
        # SECURITY: group id is derived from name hash; changing the name would
        # leave a stale id that no longer matches, breaking client lookups.
        # Names are immutable after creation (spec 18.8.2 option a).
        if name != item["name"]:
            return Message(code=BAD_REQUEST)
        return Message(code=CHANGED)

    async def render_delete(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) != 1:
            return Message(code=METHOD_NOT_ALLOWED)
        peer = _pairwise_oscore_identity(request)
        if peer is None:
            return _oscore_required_response()
        # spec 18.8.2 roles: delete is owner capability; this is the
        # authoritative record, not a local leave. Existence check, role
        # check, and removal are one transition under the mutation lock:
        # unlocked check-then-del lets a concurrent join mutate a detached
        # record and hand out key material for a deleted group.
        with self.collection._mutation_lock:
            if rest[0] not in self.collection.groups:
                return Message(code=NOT_FOUND)
            if self.collection.requester_role(rest[0], peer) != "owner":
                return Message(code=FORBIDDEN)
            del self.collection.groups[rest[0]]
        return Message(code=DELETED)

    async def render_post(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) == 2 and rest[1] == "key":
            return await self._join_key(rest[0], request)
        return Message(code=METHOD_NOT_ALLOWED)

    async def _join_key(self, group_id: str, request: Message) -> Message:
        # SECURITY: spec 18.8.2 -- group OSCORE keys travel only over the
        # pairwise OSCORE context from EDHOC. Never sent in plaintext. Joining
        # requires a prior accepted invitation, and body['node'] MUST be the
        # authenticated peer itself.
        peer = _pairwise_oscore_identity(request)
        if peer is None:
            return _oscore_required_response()
        item = self.collection.groups.get(group_id)
        if item is None or not item.get("encrypted"):
            return Message(code=NOT_FOUND)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        if body.get("request") != "join_key":
            return Message(code=BAD_REQUEST)
        node = body.get("node")
        if type(node) is not str or node == "":
            return Message(code=BAD_REQUEST)
        # SECURITY: body['node'] is a claim; only the pairwise identity bound
        # after unprotect is the peer. Check the bind before invitation so a
        # mismatch cannot distinguish "invited" from "unknown".
        if node != peer:
            return Message(code=FORBIDDEN)
        # SECURITY: invitation check, roster append, and burn marker are one
        # check-and-use transition. Serialize against rekey's locked roster
        # rebuild so a concurrent rotation cannot drop the membership append
        # or resurrect a removed member. The consume goes through the unlocked
        # variant because _mutation_lock is already held here (not reentrant).
        with self.collection._mutation_lock:
            # SECURITY: re-fetch under the lock. A concurrent render_delete
            # can remove the record captured before the lock was acquired;
            # joining into that detached record would mutate orphaned state
            # and hand out key material for a deleted group.
            item = self.collection.groups.get(group_id)
            if item is None or not item.get("encrypted"):
                return Message(code=NOT_FOUND)
            invited_role = self.collection.invitation_role(group_id, node)
            if invited_role is None:
                return Message(code=FORBIDDEN)
            members = item.setdefault("members", [])
            if self.collection.invitation_consumed(group_id, node) and node not in members:
                # SECURITY: a consumed invitation cannot resurrect enrollment;
                # membership loss after the single spend is authoritative.
                return Message(code=FORBIDDEN)
            if node not in members:
                if len(members) >= MAX_MEMBERS_PER_GROUP:
                    return _groups_full_response("members_full")
                members.append(node)
            if invited_role == "admin":
                admins = item.setdefault("admins", [])
                if node not in admins:
                    admins.append(node)
            self.collection._consume_invitation_unlocked(group_id, node)
            # SECURITY: capture the epoch tuple inside the locked span. Reading
            # these after release lets a locked rekey commit item.update() in
            # between, handing the joiner a torn (old-epoch id + new-epoch
            # secret) context instead of the epoch their enrollment used.
            response = {
                "key_id": item["key_id"],
                "key_epoch": item["key_epoch"],
                "master_secret": item["master_secret"],
                "master_salt": item["master_salt"],
                "algorithm": OSCORE_GROUP_ALG,
            }
        return _cbor_response(response)
