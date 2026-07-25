# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Key resource for public key exposure."""

from __future__ import annotations

from typing import Any

from aiocoap import Message, resource

from lichen.coap.resources.base import CBOR, _cbor_response


class KeyResource(resource.Resource):
    """GET /keys (rt="keystore" per spec/11-lci.md).

    Response map keys:
    - ``"fingerprint"``: hex string of the first 8 bytes of the public key.
    - ``"pubkey"``: raw 32-byte public key.
    """

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "keystore", "ct": str(int(CBOR))}

    def __init__(self, pubkey: bytes) -> None:
        super().__init__()
        self._pubkey = pubkey

    async def render_get(self, request: Message) -> Message:
        data = {
            "fingerprint": self._pubkey[:8].hex(),
            "pubkey": self._pubkey,
        }
        return _cbor_response(data)
