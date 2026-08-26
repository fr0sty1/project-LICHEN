# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Authenticated DIS solicitation handling (RFC 6550 Sections 6.7.9 and 8.3)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address

from lichen.rpl.messages import DIS, RplError, RplOption, RplOptionType
from lichen.rpl.trickle import TrickleTimer

_VERSION_PREDICATE = 0x80
_INSTANCE_PREDICATE = 0x40
_DODAG_PREDICATE = 0x20
_SOLICITED_INFORMATION_LENGTH = 19


class DisAction(Enum):
    """Action selected after a link-authenticated, replay-admitted DIS."""

    IGNORE = "ignore"
    RESET_TRICKLE = "reset_trickle"
    UNICAST_DIO_WITH_CONFIGURATION = "unicast_dio_with_configuration"


@dataclass(frozen=True)
class SolicitedInformation:
    """Predicates carried by the RFC 6550 Solicited Information option."""

    rpl_instance_id: int
    flags: int
    dodag_id: IPv6Address
    version: int

    @classmethod
    def from_option(cls, option: RplOption) -> SolicitedInformation:
        if option.type != RplOptionType.SOLICITED_INFORMATION:
            raise RplError("not a Solicited Information option")
        if len(option.data) != _SOLICITED_INFORMATION_LENGTH:
            raise RplError(
                "Solicited Information option data must be exactly 19 bytes"
            )
        return cls(
            rpl_instance_id=option.data[0],
            flags=option.data[1],
            dodag_id=IPv6Address(option.data[2:18]),
            version=option.data[18],
        )

    def matches(self, rpl_instance_id: int, dodag_id: IPv6Address, version: int) -> bool:
        """Return true when every enabled predicate matches local state."""
        return (
            not self.flags & _INSTANCE_PREDICATE
            or self.rpl_instance_id == rpl_instance_id
        ) and (
            not self.flags & _DODAG_PREDICATE or self.dodag_id == dodag_id
        ) and (not self.flags & _VERSION_PREDICATE or self.version == version)


def handle_authenticated_dis(
    dis_wire: bytes,
    *,
    destination_is_multicast: bool,
    rpl_instance_id: int,
    dodag_id: IPv6Address,
    version: int,
    trickle: TrickleTimer,
    now_ms: int,
) -> DisAction:
    """Handle one DIS after link signature and replay admission.

    Multicast solicitations that match reset the DIO Trickle timer. Unicast
    solicitations that match request an immediate unicast DIO containing the
    DODAG Configuration option; they do not reset Trickle. The caller owns DIO
    construction/transmission and MUST invoke this function only with an
    authenticated, replay-admitted DIS.
    """
    if type(dis_wire) is not bytes:
        raise TypeError("DIS wire image must be exact bytes")
    if type(destination_is_multicast) is not bool:
        raise TypeError("destination_is_multicast must be bool")
    if type(rpl_instance_id) is not int or not 0 <= rpl_instance_id <= 0xFF:
        raise ValueError("RPLInstanceID must be an exact u8")
    if type(dodag_id) is not IPv6Address:
        raise TypeError("DODAGID must be an IPv6Address")
    if type(version) is not int or not 0 <= version <= 0xFF:
        raise ValueError("DODAGVersionNumber must be an exact u8")
    if type(trickle) is not TrickleTimer:
        raise TypeError("trickle must be an exact TrickleTimer")

    dis = DIS.from_bytes(dis_wire)
    solicited: SolicitedInformation | None = None
    for option in dis.options:
        if option.type != RplOptionType.SOLICITED_INFORMATION:
            continue
        if solicited is not None:
            raise RplError("duplicate Solicited Information option")
        solicited = SolicitedInformation.from_option(option)

    matches = solicited is None or solicited.matches(rpl_instance_id, dodag_id, version)
    if not matches:
        return DisAction.IGNORE
    if not destination_is_multicast:
        return DisAction.UNICAST_DIO_WITH_CONFIGURATION

    trickle.reset(now_ms)
    return DisAction.RESET_TRICKLE
