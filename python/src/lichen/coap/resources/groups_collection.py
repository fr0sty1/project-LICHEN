# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``/groups`` collection and ``/groups/{id}`` (spec/12-apps.md 18.8)."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from hashlib import sha256
from typing import Any

from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    CREATED,
    DELETED,
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    Message,
    resource,
)

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor

OSCORE_GROUP_ALG = "AES-CCM-16-64-128"
REKEY_GRACE_S = 3600


def group_id_from_name(name: str) -> str:
    """Stable group id: spec allows name hash."""
    return sha256(name.encode("utf-8")).hexdigest()[:12]


def mcast_from_id(group_id: str) -> str:
    """Unicast-prefix-based multicast example prefix ff35:0040::/96 plus id bits."""
    digest = sha256(group_id.encode("utf-8")).digest()
    tail = digest[-4:].hex()
    return f"ff35:0040:0000:0000:0000:0000:0000:{tail[:4]}"


def public_group_document(item: dict[str, Any]) -> dict[str, Any]:
    """18.8.1 group document without key material."""
    document: dict[str, Any] = {
        "id": item["id"],
        "name": item["name"],
        "mcast": item["mcast"],
        "owner": item["owner"],
        "admins": list(item.get("admins") or []),
        "members": list(item.get("members") or []),
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
        if group_id in self.groups:
            return Message(code=BAD_REQUEST)
        record: dict[str, Any] = {
            "id": group_id,
            "name": name,
            "mcast": mcast_from_id(group_id),
            "encrypted": encrypted,
            "owner": self.owner,
            "admins": [],
            "members": [self.owner],
            "created": int(self._clock()),
            "key_epoch": 1,
        }
        response: dict[str, Any] = {
            "id": group_id,
            "mcast": record["mcast"],
        }
        if encrypted:
            record["key_id"] = f"key-{group_id}-001"
            record["master_secret"] = os.urandom(32)
            record["master_salt"] = os.urandom(8)
            record["key_expires"] = int(self._clock()) + 86400
            response["key_id"] = record["key_id"]
            response["master_secret"] = record["master_secret"]
        self.groups[group_id] = record
        msg = _cbor_response(response)
        msg.code = CREATED
        msg.opt.location_path = ("groups", group_id)
        return msg

    def rekey(self, group_id: str, *, removed_member: str | None = None) -> dict[str, Any] | None:
        """Rotate group key after member removal (spec 18.8.2)."""
        item = self.groups.get(group_id)
        if item is None or not item.get("encrypted"):
            return None
        if removed_member is not None:
            members = [m for m in (item.get("members") or []) if m != removed_member]
            item["members"] = members
        retired = item.setdefault("retired_epochs", [])
        retired.append(
            {
                "key_epoch": item["key_epoch"],
                "expires": int(self._clock()) + REKEY_GRACE_S,
            }
        )
        item["key_epoch"] = int(item["key_epoch"]) + 1
        item["master_secret"] = os.urandom(32)
        item["master_salt"] = os.urandom(8)
        item["key_id"] = f"key-{group_id}-{item['key_epoch']:03d}"
        item["key_expires"] = int(self._clock()) + 86400
        return {"key_id": item["key_id"], "key_epoch": item["key_epoch"]}

    def epoch_accepted(self, group_id: str, epoch: int, *, now: int | None = None) -> bool:
        """Current epoch always; retired epochs only until grace expiry."""
        item = self.groups.get(group_id)
        if item is None:
            return False
        if epoch == item.get("key_epoch"):
            return True
        stamp = int(self._clock() if now is None else now)
        for retired in item.get("retired_epochs") or []:
            if retired["key_epoch"] == epoch and stamp < int(retired["expires"]):
                return True
        return False


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

    async def render_get(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) == 1:
            item = self.collection.groups.get(rest[0])
            if item is None:
                return Message(code=NOT_FOUND)
            return _cbor_response(public_group_document(item))
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
        item = self.collection.groups.get(rest[0])
        if item is None:
            return Message(code=NOT_FOUND)
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
        item["name"] = name
        return Message(code=CHANGED)

    async def render_delete(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) != 1:
            return Message(code=METHOD_NOT_ALLOWED)
        if rest[0] not in self.collection.groups:
            return Message(code=NOT_FOUND)
        del self.collection.groups[rest[0]]
        return Message(code=DELETED)

    async def render_post(self, request: Message) -> Message:
        rest = self._rest(request)
        if len(rest) == 2 and rest[1] == "key":
            return await self._join_key(rest[0], request)
        return Message(code=METHOD_NOT_ALLOWED)

    async def _join_key(self, group_id: str, request: Message) -> Message:
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
        members = item.setdefault("members", [])
        if node not in members:
            members.append(node)
        return _cbor_response(
            {
                "key_id": item["key_id"],
                "key_epoch": item["key_epoch"],
                "master_secret": item["master_secret"],
                "master_salt": item["master_salt"],
                "algorithm": OSCORE_GROUP_ALG,
            }
        )

