# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LCI access-control oracle (spec/11-lci.md section 17.6.3).

Three access levels (read_only, standard, admin) bound what a local
client may do over each transport binding:

* ``usb`` / ``serial`` / ``ipc`` grant *admin*
* ``ble`` / ``wifi`` grant *standard*

Authorization is decided against an ordered longest-prefix resource
table. Error-code conventions pinned by
``test/vectors/access_levels.json``:

* unknown resource -> ``4.04`` regardless of level
* method not offered by the resource -> ``4.05`` regardless of level
* underprivileged mutation (or Observe below standard) -> ``4.01``
* underprivileged sensitive read (``/diag/raw/*``) -> ``4.03``
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class AccessLevel(enum.Enum):
    """LCI client privilege tier; ordering is escalation order."""

    READ_ONLY = "read_only"
    STANDARD = "standard"
    ADMIN = "admin"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, AccessLevel):
            return NotImplemented
        order = [self.READ_ONLY, self.STANDARD, self.ADMIN]
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        return self == other or self < other  # type: ignore[operator]


TRANSPORT_LEVELS: dict[str, AccessLevel] = {
    "usb": AccessLevel.ADMIN,
    "serial": AccessLevel.ADMIN,
    "ipc": AccessLevel.ADMIN,
    "ble": AccessLevel.STANDARD,
    "wifi": AccessLevel.STANDARD,
}

_CODE_UNAUTHORIZED = "4.01"
CODE_FORBIDDEN = "4.03"
CODE_NOT_FOUND = "4.04"
CODE_METHOD_NOT_ALLOWED = "4.05"


@dataclass(frozen=True)
class _Rule:
    """One longest-prefix resource entry."""

    prefix: str
    # method -> (minimum level, code when the caller's level is too low)
    methods: dict[str, tuple[AccessLevel, str]] = field(default_factory=dict)


def _m(min_level: AccessLevel, code: str = _CODE_UNAUTHORIZED) -> tuple[AccessLevel, str]:
    return (min_level, code)


# Longest prefix wins; a method missing from the matched rule's map is 4.05.
_RULES: tuple[_Rule, ...] = (
    _Rule(
        "/diag/raw/",
        {
            "GET": _m(AccessLevel.ADMIN, CODE_FORBIDDEN),
            "POST": _m(AccessLevel.ADMIN),
        },
    ),
    _Rule("/diag/", {"GET": _m(AccessLevel.READ_ONLY)}),
    _Rule(
        "/config",
        {"GET": _m(AccessLevel.READ_ONLY), "PUT": _m(AccessLevel.ADMIN)},
    ),
    _Rule("/status", {"GET": _m(AccessLevel.READ_ONLY)}),
    _Rule("/mesh/", {"GET": _m(AccessLevel.READ_ONLY)}),
    _Rule(
        "/keys/",
        {"GET": _m(AccessLevel.READ_ONLY), "DELETE": _m(AccessLevel.ADMIN)},
    ),
    _Rule("/keys", {"GET": _m(AccessLevel.READ_ONLY), "DELETE": _m(AccessLevel.ADMIN)}),
    _Rule("/proxy", {"GET": _m(AccessLevel.READ_ONLY)}),
    _Rule("/.well-known/", {"GET": _m(AccessLevel.READ_ONLY)}),
)


def level_for_transport(transport: str) -> AccessLevel:
    """Access level implied by a local transport binding."""
    try:
        return TRANSPORT_LEVELS[transport]
    except KeyError as exc:
        raise ValueError(f"unknown transport binding: {transport}") from exc


def can_access(
    level: AccessLevel,
    method: str,
    resource: str,
    *,
    observe: bool = False,
) -> tuple[bool, str | None]:
    """Authorize one LCI request.

    Returns ``(allowed, error_code)``; ``error_code`` is ``None`` when
    allowed.
    """
    rule = max(
        (r for r in _RULES if resource.startswith(r.prefix)),
        key=lambda r: len(r.prefix),
        default=None,
    )
    if rule is None:
        return (False, CODE_NOT_FOUND)

    entry = rule.methods.get(method)
    if entry is None:
        return (False, CODE_METHOD_NOT_ALLOWED)

    required, insufficient_code = entry
    if observe and required < AccessLevel.STANDARD:
        required = AccessLevel.STANDARD
        insufficient_code = _CODE_UNAUTHORIZED

    if level < required:
        return (False, insufficient_code)
    return (True, None)
