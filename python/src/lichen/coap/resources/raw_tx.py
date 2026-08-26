# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP ``POST /diag/raw/tx`` (spec/11-lci.md 17.5.4)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from aiocoap import BAD_REQUEST, CHANGED, Message, resource

from lichen.coap.resources.base import CBOR
from lichen.coap.resources.cbor_validation import _decode_single_cbor
from lichen.coap.resources.raw_rx import SPEC_MAX_FRAME_LEN

# Spec: implementations MUST rate-limit raw TX.
MIN_INTERVAL_S = 1.0


class RawTxResource(resource.Resource):
    """Accept one diagnostic frame; does not transmit on a radio."""

    rt = "diag.raw.tx"

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        min_interval_s: float = MIN_INTERVAL_S,
        max_frame_len: int = SPEC_MAX_FRAME_LEN,
    ) -> None:
        super().__init__()
        self._clock = clock or time.monotonic
        self._min_interval_s = min_interval_s
        self._max_frame_len = max_frame_len
        self._last_tx_at: float | None = None
        self.last_frame: bytes | None = None
        self.last_wait: bool | None = None

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            body = _decode_single_cbor(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if type(body) is not dict:
            return Message(code=BAD_REQUEST)
        frame = body.get("frame")
        if type(frame) is not bytes or len(frame) == 0 or len(frame) > self._max_frame_len:
            return Message(code=BAD_REQUEST)
        wait = body.get("wait", True)
        if type(wait) is not bool:
            return Message(code=BAD_REQUEST)
        now = self._clock()
        if self._last_tx_at is not None and (now - self._last_tx_at) < self._min_interval_s:
            return Message(code=BAD_REQUEST)
        self._last_tx_at = now
        self.last_frame = frame
        self.last_wait = wait
        return Message(code=CHANGED)

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": self.rt, "ct": str(int(CBOR))}
