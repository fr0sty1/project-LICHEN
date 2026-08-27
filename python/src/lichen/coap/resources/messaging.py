# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Messaging resources: /msg/inbox, /msg/sent, /msg/ack, /msg/canned, /messages."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, Sequence
from ipaddress import IPv4Address, IPv6Address
from typing import Any

import aiocoap
from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    INTERNAL_SERVER_ERROR,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    Message,
    resource,
)

from lichen.coap.resources.base import CBOR, _cbor_response
from lichen.coap.resources.cbor_validation import _decode_single_cbor

_MESSAGES_MAX = 100  # maximum inbox and receipts depth
MESSAGES_MAX_BODY_SIZE = 1024  # max message body/text size in bytes
_MESSAGE_ID_MAX = (1 << 64) - 1  # u64 bound for LCI message IDs (spec 17.5.7)

# Spec 18.1.3 default canned catalog. Ids are uints; text is the expanded body.
DEFAULT_CANNED_MESSAGES: tuple[dict[str, Any], ...] = (
    {"id": 0, "text": "I'm OK"},
    {"id": 1, "text": "Need assistance"},
    {"id": 2, "text": "At checkpoint"},
    {"id": 3, "text": "Returning to base"},
    {"id": 4, "text": "Emergency - send help"},
)


def _is_u64(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MESSAGE_ID_MAX


def _peer_is_local_admin(remote: Any) -> bool:
    """Return True when the request peer holds LCI admin rights.

    Mirrors the firmware ``lichen_coap_is_local_admin()`` contract validated
    by test/vectors/coap_lci_auth.json: loopback peers are always admin.
    Link-local admin trust is bound to the SLIP LCI transport interface in
    the C firmware; the Python reference stack has no equivalent transport
    identity, so every other source is treated as untrusted.

    The hostinfo authority parses per RFC 3986: a bracketed IPv6 literal may
    carry a ``[host]:port`` suffix; any other host strips at most one
    ``:port`` suffix. Both address families classify loopback with
    ``ipaddress`` semantics, so native IPv4 loopback peers (``127.0.0.1``
    with or without port) are admin here; the C server binds IPv6-only
    sockets and structurally never sees a native IPv4 peer, so this is not
    a firmware divergence beyond host-family availability.

    IPv4-mapped forms stay denied even though plain ``ipaddress`` semantics
    report ``IPv6Address("::ffff:127.0.0.1").is_loopback == True`` (Python
    unwraps mapped addresses before testing): Zephyr's
    ``net_ipv6_is_addr_loopback()`` matches exactly ``::1``/128, so matching
    the firmware means a v4-mapped peer is never loopback admin on either
    implementation. Genuine dual-stack clients appear under their native
    family authority (``127.0.0.1``), which this parser grants as admin.
    """
    hostinfo = getattr(remote, "hostinfo", None)
    if not isinstance(hostinfo, str) or not hostinfo:
        return False
    if hostinfo.startswith("["):
        closing = hostinfo.find("]")
        if closing < 0:
            return False
        host = hostinfo[1:closing]
    elif hostinfo.count(":") == 1:
        host = hostinfo.rsplit(":", 1)[0]
    else:
        host = hostinfo
    try:
        addr = IPv6Address(host)
    except ValueError:
        pass
    else:
        if addr.ipv4_mapped is not None:
            return False
        return addr.is_loopback
    try:
        addr4 = IPv4Address(host)
    except ValueError:
        return False
    return addr4.is_loopback


def _bound_oscore_identity(value: object) -> str | None:
    """Return a distinct OSCORE identity bound after unprotect, or None.

    SECURITY: Only identities attached after successful unprotect count.
    Strings and non-empty byte strings are accepted; context objects may
    expose ``durable_context_id()``. Arbitrary objects are not stringified,
    and CoAP option 9 is never consulted.
    """
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (bytes, bytearray)) and value:
        return bytes(value).hex()
    durable = getattr(value, "durable_context_id", None)
    if callable(durable):
        return _bound_oscore_identity(durable())
    return None


def _request_is_oscore_protected(request: Message) -> bool:
    """Return True when OSCORE identity was bound after successful unprotect.

    Firmware ``oscore.is_protected`` is the post-unprotect flag. Python
    resources see the inner request, so a spoofed CoAP OSCORE option or a
    bare ``oscore_protected`` boolean is not authentication. Match the
    dead-drop bound-identity rule (``_request_context_id``).
    """
    for holder in (request, getattr(request, "remote", None)):
        if holder is None:
            continue
        if _bound_oscore_identity(getattr(holder, "oscore_context", None)) is not None:
            return True
        if _bound_oscore_identity(getattr(holder, "oscore_context_id", None)) is not None:
            return True
    return False


def _request_remote_hostinfo(request: Message) -> str | None:
    """Return the transport-bound peer authority string, or None."""
    hostinfo = getattr(getattr(request, "remote", None), "hostinfo", None)
    if isinstance(hostinfo, str) and hostinfo:
        return hostinfo
    return None


def _host_from_hostinfo(hostinfo: str) -> str:
    """Return the host portion of an aiocoap hostinfo string.

    Strips brackets and port suffix per RFC 3986 authority rules.
    """
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        end = hostinfo.find("]")
        if end > 0:
            return hostinfo[1:end]
        return hostinfo
    # hostname:port or IPv4:port. Unbracketed IPv6 cannot carry a port.
    if hostinfo.count(":") == 1:
        return hostinfo.rsplit(":", 1)[0]
    return hostinfo


def _ipv6_from_remote(request: Message) -> str | None:
    """Return the peer IPv6 address as an RFC 5952 tstr, or None.

    Spec 18.1.1 requires ``from`` as an IPv6 tstr with no brackets or port.
    Firmware formats with ``lichen_coap_format_ipv6`` on the sockaddr.
    """
    hostinfo = _request_remote_hostinfo(request)
    if hostinfo is None:
        return None
    host = _host_from_hostinfo(hostinfo)
    try:
        addr = IPv6Address(host)
    except ValueError:
        return None
    return str(addr)


def _request_is_oscore_or_admin(request: Message) -> bool:
    """Firmware write gate: ``oscore.is_protected || is_local_admin``.

    SECURITY: Both acceptance paths additionally require a
    transport-identified remote carrying ``hostinfo``; inbound sender
    binding stores exactly that attribute as ``from``, so accepting an
    identity without it would let render-level callers create sender-less
    records no transport could ever produce.
    """
    if _request_remote_hostinfo(request) is None:
        return False
    return _request_is_oscore_protected(request) or _peer_is_local_admin(
        getattr(request, "remote", None)
    )


def _legacy_message_view(message: dict[str, Any]) -> dict[str, Any]:
    legacy = dict(message)
    if "text" not in legacy and isinstance(legacy.get("body"), str):
        legacy["text"] = legacy["body"]
    return legacy


def _normalize_canned_catalog(
    entries: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Return a validated canned catalog with unique uint ids and string text."""
    normalized: list[dict[str, Any]] = []
    seen: set[int] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("canned message must be a map")
        canned_id = entry.get("id")
        text = entry.get("text")
        if not _is_u64(canned_id):
            raise ValueError("canned message id must be a uint")
        if not isinstance(text, str):
            raise ValueError("canned message text must be a string")
        if canned_id in seen:
            raise ValueError("canned message ids must be unique")
        seen.add(canned_id)
        normalized.append({"id": canned_id, "text": text})
    return tuple(normalized)


class MessagesResource(resource.ObservableResource):
    """Observable ``/msg/inbox`` — CBOR inbox with POST-to-send.

    Each message is a CBOR map::

        {"from": "<addr>", "to": "<addr> | all", "body": "...", "ts": <timestamp>}

    **GET** returns the inbox (most recent :data:`_MESSAGES_MAX` messages, oldest
    first) plus an ``unread`` count (spec 18.1.2).  **POST** delivers a new
    message and notifies all observers; the body must be a valid CBOR map with
    a message body, a legacy ``text`` field, or a ``canned`` catalog id
    (spec 18.1.3). Local LCI submits include ``to``; direct POSTs to a
    destination inbox MAY omit it. Legacy ``text``/``t`` fields are accepted
    and preserved for simulator compatibility.

    Callers can also inject received messages directly via :meth:`deliver`
    (used when a message arrives over the mesh rather than via CoAP POST).

    Example::

        msgs = MessagesResource()
        site = build_site(info, messages_resource=msgs)
        # A peer message arrives over the mesh:
        msgs.deliver({"from": "aabb...", "to": "all", "body": "hello", "ts": 1700000000})
    """

    def __init__(
        self,
        *,
        max_messages: int = _MESSAGES_MAX,
        canned_messages: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
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
        catalog = DEFAULT_CANNED_MESSAGES if canned_messages is None else canned_messages
        self._canned: tuple[dict[str, Any], ...] = _normalize_canned_catalog(catalog)
        self._canned_text: dict[int, str] = {item["id"]: item["text"] for item in self._canned}

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.inbox", "ct": str(int(CBOR)), "obs": None}

    def deliver(self, message: dict[str, Any]) -> None:
        """Append *message* to the inbox and notify observers.

        Trims the inbox to :data:`_MESSAGES_MAX` entries (oldest dropped).
        """
        self._inbox.append(copy.deepcopy(message))
        if len(self._inbox) > self._max_messages:
            self._inbox = self._inbox[-self._max_messages :]
        self.updated_state()
        for alias in self._legacy_aliases:
            alias.updated_state()

    def sent_messages(self) -> list[dict[str, Any]]:
        """Return sent messages in creation order."""
        return [self._sent[msg_id] for msg_id in self._sent_order]

    def inbox(self) -> list[dict[str, Any]]:
        """Return inbox messages in delivery order."""
        return [dict(message) for message in self._inbox]

    def unread_count(self) -> int:
        """Return the number of inbox messages not marked ``read`` (spec 18.1.2)."""
        return sum(1 for message in self._inbox if not message.get("read"))

    def canned_messages(self) -> list[dict[str, Any]]:
        """Return the canned catalog as ``{id, text}`` maps (spec 18.1.3)."""
        return [dict(item) for item in self._canned]

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
        return _cbor_response(
            {
                "messages": [dict(message) for message in self._inbox],
                "unread": self.unread_count(),
            }
        )

    def _accept_outbound(self, request: Message) -> Message | dict[str, Any]:
        """Validate and store an outbound message in the sent archive.

        Returns either an error Message (4.xx/5.xx) or the validated body dict
        on success. Callers decide whether to also deliver() to inbox.
        """
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        if len(request.payload) > MESSAGES_MAX_BODY_SIZE:
            return Message(code=aiocoap.REQUEST_ENTITY_TOO_LARGE)
        try:
            decoded = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(decoded, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        body = dict(decoded)
        # SECURITY: Set 'from' from transport identity, not client payload.
        # Spec 18.1.1: from is an IPv6 tstr (no brackets/port).
        body.pop("from", None)
        sender_ipv6 = _ipv6_from_remote(request)
        if sender_ipv6 is not None:
            body["from"] = sender_ipv6
        # Spec 18.1.1: 'from' is mandatory. Reject requests from peers that
        # cannot produce a valid IPv6 sender (e.g., IPv4 local admin).
        if "from" not in body:
            return Message(code=aiocoap.BAD_REQUEST)
        if "canned" in body:
            canned_id = body["canned"]
            if not _is_u64(canned_id) or canned_id not in self._canned_text:
                return Message(code=aiocoap.BAD_REQUEST)
        if "body" in body and not isinstance(body["body"], str):
            return Message(code=aiocoap.BAD_REQUEST)
        if "text" in body and not isinstance(body["text"], str):
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body.get("body"), str) and not isinstance(body.get("text"), str):
            if "canned" not in body:
                return Message(code=aiocoap.BAD_REQUEST)
            body["body"] = self._canned_text[body["canned"]]
        if "id" in body and (
            type(body["id"]) is not int or body["id"] < 0 or body["id"] > _MESSAGE_ID_MAX
        ):
            return Message(code=aiocoap.BAD_REQUEST)
        # Validate spec 18.1.1 optional field types before mutation.
        if "to" in body and not isinstance(body["to"], str):
            return Message(code=aiocoap.BAD_REQUEST)
        if "ack" in body and not isinstance(body["ack"], bool):
            return Message(code=aiocoap.BAD_REQUEST)
        if "priority" in body:
            if type(body["priority"]) is not int or body["priority"] not in (0, 1, 2):
                return Message(code=aiocoap.BAD_REQUEST)
        if "ts" in body and not _is_u64(body["ts"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "ttl" in body and not _is_u64(body["ttl"]):
            return Message(code=aiocoap.BAD_REQUEST)
        if "reply_to" in body and not _is_u64(body["reply_to"]):
            return Message(code=aiocoap.BAD_REQUEST)
        # Filter to spec 18.1.1 keys only; drop client-supplied 'read' and other non-spec keys.
        allowed_keys = {"from", "to", "body", "text", "ts", "ack", "priority", "reply_to", "ttl", "canned", "id"}
        body = {k: v for k, v in body.items() if k in allowed_keys}
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
        if len(body["body"]) > MESSAGES_MAX_BODY_SIZE:
            return Message(code=aiocoap.BAD_REQUEST)

        msg_id = str(body["id"])
        self._sent[msg_id] = copy.deepcopy(body)
        if msg_id not in self._sent_order:
            self._sent_order.append(msg_id)
        if len(self._sent_order) > self._max_messages:
            oldest = self._sent_order[: len(self._sent_order) - self._max_messages]
            self._sent_order = self._sent_order[-self._max_messages :]
            for old_id in oldest:
                self._sent.pop(old_id, None)
        if self._sent_detail_registrar is not None:
            self._sent_detail_registrar(msg_id, copy.deepcopy(body))
        self._next_id = candidate_next_id
        return body

    async def render_post(self, request: Message) -> Message:
        # SECURITY: Unauthenticated POSTs must not mutate inbox, sent, or
        # _next_id. Firmware msg_inbox_post: oscore.is_protected ||
        # lichen_coap_is_local_admin, else 4.01 (coap_server.c).
        if not _request_is_oscore_or_admin(request):
            return Message(code=UNAUTHORIZED)
        result = self._accept_outbound(request)
        if isinstance(result, Message):
            return result
        body = result
        # Deliver to inbox and notify observers (per docstring contract).
        self.deliver(body)
        msg = Message(code=aiocoap.CREATED)
        msg.opt.location_path = ("msg", "sent", str(body["id"]))
        return msg


class CannedMessagesResource(resource.Resource):
    """``/msg/canned`` catalog of pre-defined messages (spec 18.1.3)."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.canned", "ct": str(int(CBOR))}

    async def render_get(self, request: Message) -> Message:
        return _cbor_response({"messages": self._messages.canned_messages()})


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
        # POLICY: Direct archive-write to /msg/sent is loopback-admin only,
        # so mesh peers cannot fabricate archive history out of band
        # (spec/11-lci.md SS17.6.3; vectors msg_sent_mesh_forbidden /
        # msg_sent_local_admin). Non-admin peers get 4.01 Unauthorized.
        # Unlike POST /msg/inbox, this does NOT deliver to inbox or notify
        # observers -- it only archives the outbound record (firmware
        # lichen_msg_sent_post / lichen_msg_send contract).
        if not _peer_is_local_admin(getattr(request, "remote", None)):
            return Message(code=UNAUTHORIZED)
        result = self._messages._accept_outbound(request)
        if isinstance(result, Message):
            return result
        body = result
        msg = Message(code=aiocoap.CREATED)
        msg.opt.location_path = ("msg", "sent", str(body["id"]))
        return msg


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
        return resource.LinkFormat(
            [
                resource.Link(f"/{msg_id}", ct=str(int(CBOR)))
                for msg_id in self._messages._sent_order
            ]
        )


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
        # SECURITY: Unauthenticated POSTs must not append receipts. Firmware
        # lichen_msg_ack_post: oscore.is_protected || is_local_admin, else 4.01.
        if not _request_is_oscore_or_admin(request):
            return Message(code=UNAUTHORIZED)
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
            self._receipts = self._receipts[-self._max_receipts :]
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
