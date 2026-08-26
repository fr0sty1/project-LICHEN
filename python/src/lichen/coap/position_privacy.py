# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Position-sharing privacy modes (spec 12-apps.md section 18.1).

Three modes govern who may read the node's position:

* ``public``  — anyone; beacons also carry position
* ``group``   — group-OSCORE members only
* ``private`` — one specific peer over pairwise OSCORE only

Reject codes pinned by ``test/vectors/position_privacy_auth.json``:
missing authentication is ``4.01 Unauthorized``; authenticated but
not entitled (non-member or wrong peer) is ``4.03 Forbidden``. Mode
changes take effect immediately for subsequent requests, and beacons
include position only in public mode (beacons are public broadcast).
"""

from __future__ import annotations

import enum


class PositionPrivacyMode(enum.Enum):
    """Position visibility mode."""

    PUBLIC = "public"
    GROUP = "group"
    PRIVATE = "private"


CODE_OK = "2.05 Content"
CODE_UNAUTHORIZED = "4.01 Unauthorized"
CODE_FORBIDDEN = "4.03 Forbidden"


class PositionPrivacyPolicy:
    """Mode-aware gate for position reads and beacon inclusion."""

    def __init__(
        self,
        mode: PositionPrivacyMode | str = PositionPrivacyMode.PUBLIC,
        *,
        member_groups: set[str] | None = None,
        allowed_peer_iid: str | None = None,
    ) -> None:
        if isinstance(mode, str):
            mode = PositionPrivacyMode(mode)
        self._mode = mode
        self.member_groups = member_groups or set()
        self.allowed_peer_iid = allowed_peer_iid

    @property
    def mode(self) -> PositionPrivacyMode:
        return self._mode

    @mode.setter
    def mode(self, value: PositionPrivacyMode | str) -> None:
        if isinstance(value, str):
            value = PositionPrivacyMode(value)
        self._mode = value

    def check_read(
        self,
        *,
        oscore: bool = False,
        oscore_context: str | None = None,
        requester_iid: str | None = None,
    ) -> tuple[bool, str]:
        """Authorize one GET /position against the current mode.

        Returns ``(accept, response_code)``.
        """
        if self._mode is PositionPrivacyMode.PUBLIC:
            return (True, CODE_OK)

        if self._mode is PositionPrivacyMode.GROUP:
            if not oscore:
                return (False, CODE_UNAUTHORIZED)
            if (
                requester_iid is not None
                and self.allowed_peer_iid is not None
                and requester_iid == self.allowed_peer_iid
            ):
                return (True, CODE_OK)
            if oscore_context == "group":
                return (True, CODE_OK)
            return (False, CODE_FORBIDDEN)

        # PRIVATE
        if not oscore:
            return (False, CODE_UNAUTHORIZED)
        if self.allowed_peer_iid is not None and requester_iid == self.allowed_peer_iid:
            return (True, CODE_OK)
        return (False, CODE_FORBIDDEN)

    def include_position_in_beacon(self) -> bool:
        """Beacons are public broadcast; only public mode carries position."""
        return self._mode is PositionPrivacyMode.PUBLIC
