# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Resource Directory resource (simplified RFC 9176)."""

from __future__ import annotations

import itertools
import string
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import cbor2
from aiocoap import (
    BAD_REQUEST,
    CONTENT,
    CREATED,
    DELETED,
    INTERNAL_SERVER_ERROR,
    NOT_FOUND,
    Message,
    resource,
)

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor

_RD_DEFAULT_LIFETIME = 86400  # seconds (RFC 9176 7.3.1)
_rd_id_counter = itertools.count(1)
_RD_PATH_CHARS = frozenset(string.ascii_letters + string.digits + "-._~")
_LOOKUP_PAGINATION = frozenset({"page", "count"})


def _rfc6690_match(value: object, query: str, *, tokenize: bool) -> bool:
    """RFC 6690 §4.1 / RFC 9176 §6.2: exact value, or prefix when query ends with *."""
    if not isinstance(value, str):
        return False
    candidates = [token for token in value.split() if token] if tokenize else [value]
    if query.endswith("*"):
        prefix = query[:-1]
        return any(candidate.startswith(prefix) for candidate in candidates)
    return query in candidates


def _parse_lookup_query(request: Message) -> dict[str, list[str]]:
    filters: dict[str, list[str]] = {}
    for item in request.opt.uri_query or []:
        name, sep, raw = item.partition("=")
        if not name or name in _LOOKUP_PAGINATION:
            continue
        filters.setdefault(name, []).append(raw if sep else "")
    return filters


def _link_matches(
    entry: _RdEntry, link: dict[str, Any], filters: dict[str, list[str]]
) -> bool:
    for name, values in filters.items():
        if name == "ep":
            haystack: object = entry.ep
            tokenize = False
        elif name == "base":
            haystack = entry.base
            tokenize = False
        elif name == "d":
            return False
        elif name == "href":
            haystack = link.get("href")
            tokenize = False
        else:
            haystack = link.get(name)
            tokenize = True
        for value in values:
            if not _rfc6690_match(haystack, value, tokenize=tokenize):
                return False
    return True


@dataclass
class _RdEntry:
    """One endpoint registration in the Resource Directory."""

    reg_id: str
    ep: str  # endpoint name (RFC 9176 7.3.1, mandatory)
    lt: int  # lifetime in seconds
    base: str | None
    links: list[dict[str, Any]]  # decoded link descriptors


class ResourceDirectoryResource(resource.Resource):
    """``/rd`` — CoAP Resource Directory (simplified RFC 9176).

    **POST** registers an endpoint; query parameters ``ep`` (required),
    ``lt`` (optional, default 86400), ``base`` (optional), body is a CBOR
    list of link descriptor maps ``[{"href": "/sensors", "rt": "..."}]``.
    Returns ``2.01 Created`` with ``Location-Path: /rd/<id>``.

    **GET** returns all active registrations as a CBOR list.

    Resource lookup lives at ``/rd-lookup/res`` (RFC 9176 §8.3) and is mounted
    on ``site`` during construction so ``build_site`` does not have to know
    the extra path.

    Individual registrations are managed via :class:`_RdRegistrationResource`
    mounted at ``/rd/<id>``; those resources are added dynamically to the site
    when a node registers.

    Example registration::

        POST coap://rd/rd?ep=node-01&lt=3600
        CBOR body: [{"href": "/sensors", "rt": "lichen.sensors"},
                    {"href": "/status",  "rt": "lichen.status"}]
    """

    def __init__(
        self,
        site: resource.Site,
        *,
        route_remover: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__()
        self._site = site
        self._route_remover = route_remover or (
            lambda reg_id: site.remove_resource(["rd", reg_id])
        )
        self._entries: dict[str, _RdEntry] = {}  # keyed by reg_id
        _ensure_rd_lookup_mounted(site)

    def _lookup(self, ep: str | None = None) -> list[dict[str, Any]]:
        """Return registrations, optionally filtered by endpoint name."""
        rows = list(self._entries.values())
        if ep is not None:
            rows = [r for r in rows if r.ep == ep]
        return [
            {
                "id": r.reg_id,
                "ep": r.ep,
                "lt": r.lt,
                "base": r.base,
                "links": r.links,
            }
            for r in rows
        ]

    def lookup_resources(self, filters: dict[str, list[str]]) -> list[dict[str, Any]]:
        """Return matching link descriptors for RFC 9176 resource lookup.

        Every query criterion is AND-combined, including duplicate keys.
        ``rt`` (and other link attributes) match a space-separated token, or a
        prefix when the query ends with ``*``. ``href`` and ``ep`` match the
        whole string the same way. Unknown attributes fail the AND.
        """
        hits: list[dict[str, Any]] = []
        for entry in self._entries.values():
            for link in entry.links:
                if not _link_matches(entry, link, filters):
                    continue
                item: dict[str, Any] = {"href": link.get("href"), "ep": entry.ep}
                if link.get("rt") is not None:
                    item["rt"] = link["rt"]
                if entry.base is not None:
                    item["base"] = entry.base
                hits.append(item)
        return hits

    def remove_entry(self, reg_id: str) -> bool:
        """Atomically remove a registration route and entry."""
        if reg_id not in self._entries:
            return False
        self._route_remover(reg_id)
        del self._entries[reg_id]
        return True

    @staticmethod
    def _normalize_links(body: Any) -> list[dict[str, Any]] | None:
        if not isinstance(body, list):
            return None
        normalized: list[dict[str, Any]] = []
        for descriptor in body:
            if not isinstance(descriptor, dict) or set(descriptor) - {"href", "rt"}:
                return None
            href = descriptor.get("href")
            if not isinstance(href, str) or not href.startswith("/"):
                return None
            segments = href.split("/")[1:]
            if not segments or any(
                not segment
                or segment in {".", ".."}
                or any(char not in _RD_PATH_CHARS for char in segment)
                for segment in segments
            ):
                return None
            rt = descriptor.get("rt")
            if rt is not None and (not isinstance(rt, str) or not rt):
                return None
            normalized.append(dict(descriptor))
        return normalized

    async def render_get(self, request: Message) -> Message:
        ep_filter: str | None = None
        if request.opt.uri_query:
            for q in request.opt.uri_query:
                if q.startswith("ep="):
                    ep_filter = q[3:]
        msg = Message(code=CONTENT, payload=cbor2.dumps(self._lookup(ep_filter)))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        # Parse query parameters
        ep: str | None = None
        lt: int = _RD_DEFAULT_LIFETIME
        base: str | None = None
        for q in request.opt.uri_query or []:
            if q.startswith("ep="):
                ep = q[3:]
            elif q.startswith("lt="):
                raw_lifetime = q[3:]
                if (
                    not raw_lifetime
                    or not raw_lifetime.isascii()
                    or not raw_lifetime.isdecimal()
                ):
                    return Message(code=BAD_REQUEST)
                lt = int(raw_lifetime)
                if not 1 <= lt <= (1 << 32) - 1:
                    return Message(code=BAD_REQUEST)
            elif q.startswith("base="):
                base = q[5:]

        if not ep:
            return Message(code=BAD_REQUEST)  # RFC 9176 7.3.1: ep is mandatory

        links: list[dict[str, Any]] = []
        if request.payload:
            try:
                body = _decode_single_cbor(request.payload)
            except Exception:
                return Message(code=BAD_REQUEST)
            normalized_links = self._normalize_links(body)
            if normalized_links is None:
                return Message(code=BAD_REQUEST)
            links = normalized_links

        reg_id = str(next(_rd_id_counter))
        entry = _RdEntry(reg_id=reg_id, ep=ep, lt=lt, base=base, links=links)

        # Mount a deletion endpoint at /rd/<id>
        self._site.add_resource(
            ["rd", reg_id],
            _RdRegistrationResource(self, reg_id),
        )
        self._entries[reg_id] = entry

        resp = Message(code=CREATED)
        resp.opt.location_path = ("rd", reg_id)
        return resp


class _RdRegistrationResource(resource.Resource):
    """``/rd/<id>`` — per-registration management (DELETE to remove)."""

    def __init__(self, rd: ResourceDirectoryResource, reg_id: str) -> None:
        super().__init__()
        self._rd = rd
        self._reg_id = reg_id

    async def render_delete(self, request: Message) -> Message:
        try:
            removed = self._rd.remove_entry(self._reg_id)
        except Exception:
            return Message(code=INTERNAL_SERVER_ERROR)
        return Message(code=DELETED if removed else NOT_FOUND)


def _mounted(site: resource.Site, path: tuple[str, ...]) -> resource.Resource | None:
    """Return the resource aiocoap has at ``path``, if any."""
    return site._resources.get(path)


def _ensure_rd_lookup_mounted(site: resource.Site) -> None:
    """Mount ``/rd-lookup/res`` once. Later RD instances must not steal it."""
    existing = _mounted(site, ("rd-lookup", "res"))
    if isinstance(existing, _RdLookupResource):
        return
    site.add_resource(["rd-lookup", "res"], _RdLookupResource(site))


class _RdLookupResource(resource.Resource):
    """``/rd-lookup/res`` — RFC 9176 §8.3 resource lookup.

    Resolves the directory currently mounted at ``/rd`` so a second
    ``ResourceDirectoryResource`` cannot desync lookup from registration.
    """

    def __init__(self, site: resource.Site) -> None:
        super().__init__()
        self._site = site

    def _directory(self) -> ResourceDirectoryResource | None:
        mounted = _mounted(self._site, ("rd",))
        if isinstance(mounted, ResourceDirectoryResource):
            return mounted
        return None

    async def render_get(self, request: Message) -> Message:
        rd = self._directory()
        if rd is None:
            return Message(code=NOT_FOUND)
        hits = rd.lookup_resources(_parse_lookup_query(request))
        # RFC 9176 §6.2: no matches is still 2.05 with an empty payload (`[]`).
        msg = Message(code=CONTENT, payload=cbor2.dumps(hits))
        msg.opt.content_format = CBOR
        return msg
