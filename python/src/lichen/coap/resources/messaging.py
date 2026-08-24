# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Messaging resources: /msg/inbox, /msg/sent, /msg/ack, /messages."""

from __future__ import annotations

import copy
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import Any

import aiocoap
import cbor2
from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    CONTENT,
    INTERNAL_SERVER_ERROR,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    Message,
    resource,
)

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor

_MESSAGES_MAX = 100  # maximum inbox and receipts depth
_MESSAGE_ID_MAX = (1 << 64) - 1  # u64 bound for LCI message IDs (spec 17.5.7)


def _is_u64(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MESSAGE_ID_MAX


def _peer_is_local_admin(remote: Any) -> bool:
    """Return True when the request peer holds LCI admin rights.

    Mirrors the firmware ``lichen_coap_is_local_admin()`` contract validated
    by test/vectors/coap_lci_auth.json: loopback peers are always admin.
    Link-local admin trust is bound to the SLIP LCI transport interface in
    the C firmware; the Python reference stack has no equivalent transport
    identity, so every other source is treated as untrusted.
    """
    hostinfo = getattr(remote, "hostinfo", None)
    if not isinstance(hostinfo, str):
        return False
    host = hostinfo.rsplit(":", 1)[0] if hostinfo.count(":") == 1 else hostinfo
    host = host.strip("[]")
    try:
        return IPv6Address(host).is_loopback
    except ValueError:
        return False


def _legacy_message_view(message: dict[str, Any]) -> dict[str, Any]:
    legacy = dict(message)
    if "text" not in legacy and isinstance(legacy.get("body"), str):
        legacy["text"] = legacy["body"]
    return legacy


class MessagesResource(resource.ObservableResource):
    """Observable ``/msg/inbox`` — CBOR inbox with POST-to-send.

    Each message is a CBOR map::

        {"from": "<addr>", "to": "<addr> | all", "body": "...", "ts": <timestamp>}

    **GET** returns the inbox (most recent :data:`_MESSAGES_MAX` messages, oldest
    first).  **POST** delivers a new message and notifies all observers;
    the body must be a valid CBOR map with a message body. Local LCI submits
    include ``to``; direct POSTs to a destination inbox MAY omit it. Legacy
    ``text``/``t`` fields are accepted and preserved for simulator compatibility.

    Callers can also inject received messages directly via :meth:`deliver`
    (used when a message arrives over the mesh rather than via CoAP POST).

    Example::

        msgs = MessagesResource()
        site = build_site(info, messages_resource=msgs)
        # A peer message arrives over the mesh:
        msgs.deliver({"from": "aabb...", "to": "all", "body": "hello", "ts": 1700000000})
    """

    def __init__(self, *, max_messages: int = _MESSAGES_MAX) -> None:
        super().__init__()
        if isinstance(max_messages, bool) or not isinstance(max_messages, int) or max_messages <= 0:
            raise ValueError("max_messages must be a positive integer")
        self._max_messages = max_messages
        self._inbox: list[dict[str, Any]] = []
        self._sent: dict[str, dict[str, Any]] = {}
        self._sent_order: list[str] = []
        self._legacy_aliases: list[LegacyMessagesAliasResource] = []
        self._next_id = 1
        self._sent_detail_registrar: Callable[[str, dict[str, Any]], None] | None = None

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.inbox", "ct": str(int(CBOR)), "obs": None}

    def deliver(self, message: dict[str, Any]) -> None:
        """Append *message* to the inbox and notify observers.

        Trims the inbox to :data:`_MESSAGES_MAX` entries (oldest dropped).
        """
        self._inbox.append(message)
        if len(self._inbox) > self._max_messages:
            self._inbox = self._inbox[-self._max_messages:]
        self.updated_state()
        for alias in self._legacy_aliases:
            alias.updated_state()

    def sent_messages(self) -> list[dict[str, Any]]:
        """Return sent messages in creation order."""
        return [self._sent[msg_id] for msg_id in self._sent_order]

    def inbox(self) -> list[dict[str, Any]]:
        """Return inbox messages in delivery order."""
        return [dict(message) for message in self._inbox]

    def sent_message(self, msg_id: str) -> dict[str, Any] | None:
        """Return one sent message by ID."""
        return self._sent.get(msg_id)

    def register_legacy_alias(self, alias: LegacyMessagesAliasResource) -> None:
        """Register a legacy observable alias that mirrors inbox updates."""
        self._legacy_aliases.append(alias)

    def set_sent_detail_registrar(
        self, registrar: Callable[[str, dict[str, Any]], None] | None
    ) -> None:
        """Register callback for per-message sent detail resources (used by build_site)."""
        self._sent_detail_registrar = registrar

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=cbor2.dumps({"messages": self._inbox}))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        if not (isinstance(body.get("body"), str) or isinstance(body.get("text"), str)):
            return Message(code=aiocoap.BAD_REQUEST)
        if "id" in body and (
            type(body["id"]) is not int
            or body["id"] < 0
            or body["id"] > _MESSAGE_ID_MAX
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        body = dict(body)
        candidate_next_id = self._next_id
        if "id" not in body:
            if candidate_next_id > _MESSAGE_ID_MAX:
                return Message(code=SERVICE_UNAVAILABLE)
            body["id"] = candidate_next_id
            candidate_next_id += 1
        else:
            candidate_next_id = max(candidate_next_id, body["id"] + 1)
        if "body" not in body and "text" in body:
            body["body"] = body["text"]

        msg_id = str(body["id"])
        self._sent[msg_id] = copy.deepcopy(body)
        if msg_id not in self._sent_order:
            self._sent_order.append(msg_id)
        if len(self._sent_order) > self._max_messages:
            oldest = self._sent_order[: len(self._sent_order) - self._max_messages]
            self._sent_order = self._sent_order[-self._max_messages:]
            for old_id in oldest:
                self._sent.pop(old_id, None)
        if self._sent_detail_registrar is not None:
            self._sent_detail_registrar(msg_id, body)
        self._next_id = candidate_next_id
        # Deliver to inbox and notify observers (per docstring contract).
        self.deliver(body)
        msg = Message(code=aiocoap.CREATED)
        msg.opt.location_path = ("msg", "sent", msg_id)
        return msg


class SentMessagesResource(resource.Resource):
    """``/msg/sent`` collection for messages accepted through LCI."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.sent", "ct": str(int(CBOR))}

    async def render_get(self, request: Message) -> Message:
        return _cbor_response({"messages": self._messages.sent_messages()})

    async def render_post(self, request: Message) -> Message:
        # SECURITY: Writing to the sent archive is an admin operation
        # (spec/11-lci.md §17.6.3; vectors msg_sent_mesh_forbidden /
        # msg_sent_local_admin). Non-admin peers get 4.01 Unauthorized.
        if not _peer_is_local_admin(getattr(request, "remote", None)):
            return Message(code=UNAUTHORIZED)
        return await self._messages.render_post(request)


class SentMessageDetailsResource(resource.Resource, resource.PathCapable):
    """Stable dynamic router for retained ``/msg/sent/{id}`` records."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    async def render_get(self, request: Message) -> Message:
        if len(request.opt.uri_path) != 1:
            return Message(code=aiocoap.NOT_FOUND)
        msg_id = request.opt.uri_path[0]
        if not msg_id or not msg_id.isascii() or not msg_id.isdecimal():
            return Message(code=aiocoap.NOT_FOUND)
        value = int(msg_id)
        if value > _MESSAGE_ID_MAX or str(value) != msg_id:
            return Message(code=aiocoap.NOT_FOUND)
        message = self._messages.sent_message(msg_id)
        if message is None:
            return Message(code=aiocoap.NOT_FOUND)
        return _cbor_response(dict(message))

    def get_resources_as_linkheader(self) -> Any:
        return resource.LinkFormat([
            resource.Link(f"/{msg_id}", ct=str(int(CBOR)))
            for msg_id in self._messages._sent_order
        ])


class MessageReceiptsResource(resource.Resource):
    """``/msg/ack`` collection for delivery/read/failure receipts.

    Stored receipts are capped at :data:`_MESSAGES_MAX` entries (oldest dropped).
    """

    VALID_STATUSES = frozenset({"delivered", "read", "failed"})

    def __init__(
        self,
        *,
        handler: Callable[[dict[str, Any]], None] | None = None,
        max_receipts: int = _MESSAGES_MAX,
    ) -> None:
        super().__init__()
        if isinstance(max_receipts, bool) or not isinstance(max_receipts, int) or max_receipts <= 0:
            raise ValueError("max_receipts must be a positive integer")
        self._handler = handler
        self._max_receipts = max_receipts
        self._receipts: list[dict[str, Any]] = []

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.ack", "ct": str(int(CBOR))}

    def receipts(self) -> list[dict[str, Any]]:
        """Return stored receipts in POST order."""
        return [dict(receipt) for receipt in self._receipts]

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            payload = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        receipt = self._normalize(payload)
        if receipt is None:
            return Message(code=BAD_REQUEST)
        if self._handler is not None:
            try:
                # Handlers should raise before external commit; side effects
                # performed before raising cannot be rolled back here.
                self._handler(dict(receipt))
            except Exception:
                return Message(code=INTERNAL_SERVER_ERROR)
        self._receipts.append(receipt)
        if len(self._receipts) > self._max_receipts:
            self._receipts = self._receipts[-self._max_receipts:]
        return Message(code=CHANGED)

    @classmethod
    def _normalize(cls, payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        receipt_id = payload.get("id")
        status = payload.get("status")
        timestamp = payload.get("ts")
        if not _is_u64(receipt_id):
            return None
        if status not in cls.VALID_STATUSES:
            return None
        if not _is_u64(timestamp):
            return None
        return {
            "id": receipt_id,
            "status": status,
            "ts": timestamp,
        }


class LegacyMessagesAliasResource(resource.ObservableResource):
    """Legacy/demo ``/messages`` alias for older Python simulator clients."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "legacy.messages", "ct": str(int(CBOR)), "title": "legacy demo alias"}

    async def render_get(self, request: Message) -> Message:
        payload = {"messages": [_legacy_message_view(msg) for msg in self._messages.inbox()]}
        return _cbor_response(payload)

    async def render_post(self, request: Message) -> Message:
        return await self._messages.render_post(request)
