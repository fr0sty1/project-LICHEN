"""LICHEN RPL routing (RFC 6550, spec section 8).

RPL carries border-router traffic via a proactive DODAG tree. This package
currently provides the control-message codecs (DIO, DIS, DAO, DAO-ACK).
"""

from lichen.rpl.dao import (
    DaoError,
    DaoManager,
    RplTarget,
    TransitInformation,
)
from lichen.rpl.dodag import DodagRole, DodagState, ParentCandidate
from lichen.rpl.messages import (
    DAO,
    DIO,
    DIS,
    DAOAck,
    ModeOfOperation,
    RplCode,
    RplError,
    RplMessage,
    RplOption,
    RplOptionType,
    from_icmpv6,
    to_icmpv6,
)
from lichen.rpl.routing import (
    RoutingError,
    RoutingTable,
    SourceRoutingHeader,
    advance_source_route,
    insert_source_route,
    next_hop_upward,
)
from lichen.rpl.trickle import TrickleTimer

__all__ = [
    "DAO",
    "DIO",
    "DIS",
    "DAOAck",
    "DaoError",
    "DaoManager",
    "DodagRole",
    "DodagState",
    "ModeOfOperation",
    "ParentCandidate",
    "RoutingError",
    "RplTarget",
    "TransitInformation",
    "RoutingTable",
    "RplCode",
    "RplError",
    "RplMessage",
    "RplOption",
    "RplOptionType",
    "SourceRoutingHeader",
    "TrickleTimer",
    "advance_source_route",
    "from_icmpv6",
    "insert_source_route",
    "next_hop_upward",
    "to_icmpv6",
]
