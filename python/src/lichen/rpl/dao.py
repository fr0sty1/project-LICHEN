"""RPL DAO handling for non-storing mode (RFC 6550, spec section 8.5).

In non-storing mode every node sends a DAO directly to the root advertising
itself as an RPL Target and its preferred parent as Transit Information. The
root chains these (target -> parent) edges into a full source route for each
node and installs it in the routing table.

This module provides the RPL Target (type 5) and Transit Information (type 6)
option codecs and a :class:`DaoManager` for both sending (non-root) and
receiving (root) sides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv6Address

from lichen.rpl.messages import DAO, DAOAck, RplOption, RplOptionType
from lichen.rpl.routing import RoutingTable

_MAX_CHAIN = 64  # loop / runaway guard when assembling source routes


class DaoError(Exception):
    """Raised on malformed DAO options or misuse of the DAO manager."""


def _addr(value: IPv6Address | str) -> IPv6Address:
    return value if isinstance(value, IPv6Address) else IPv6Address(value)


@dataclass
class RplTarget:
    """RPL Target option (RFC 6550 6.7.7); a full /128 target by default."""

    target: IPv6Address
    prefix_length: int = 128

    def to_option(self) -> RplOption:
        nbytes = (self.prefix_length + 7) // 8
        data = bytes([0, self.prefix_length]) + self.target.packed[:nbytes]
        return RplOption(RplOptionType.RPL_TARGET, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> RplTarget:
        if opt.type != RplOptionType.RPL_TARGET:
            raise DaoError(f"not an RPL Target option: type {opt.type}")
        if len(opt.data) < 2:
            raise DaoError("RPL Target option too short")
        prefix_length = opt.data[1]
        nbytes = (prefix_length + 7) // 8
        prefix = opt.data[2 : 2 + nbytes]
        if len(prefix) != nbytes:
            raise DaoError("RPL Target prefix shorter than prefix length")
        return cls(IPv6Address(prefix.ljust(16, b"\x00")), prefix_length)


@dataclass
class TransitInformation:
    """Transit Information option (RFC 6550 6.7.8) carrying the parent address."""

    parent_address: IPv6Address
    path_lifetime: int = 255
    path_sequence: int = 0
    path_control: int = 0

    def to_option(self) -> RplOption:
        data = (
            bytes([0, self.path_control, self.path_sequence, self.path_lifetime])
            + self.parent_address.packed
        )
        return RplOption(RplOptionType.TRANSIT_INFORMATION, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> TransitInformation:
        if opt.type != RplOptionType.TRANSIT_INFORMATION:
            raise DaoError(f"not a Transit Information option: type {opt.type}")
        if len(opt.data) < 4 + 16:
            raise DaoError("Transit Information option missing parent address")
        return cls(
            parent_address=IPv6Address(opt.data[4:20]),
            path_control=opt.data[1],
            path_sequence=opt.data[2],
            path_lifetime=opt.data[3],
        )


@dataclass
class DaoManager:
    """Builds DAOs (non-root) and assembles routes from them (root).

    On the root, ``routing_table`` is kept in sync as DAOs arrive.
    """

    node_address: IPv6Address
    is_root: bool = False
    rpl_instance_id: int = 0
    dodag_id: IPv6Address | None = None
    routing_table: RoutingTable = field(default_factory=RoutingTable)
    _dao_sequence: int = 0
    _parent_map: dict[IPv6Address, IPv6Address] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.node_address = _addr(self.node_address)
        if self.dodag_id is not None:
            self.dodag_id = _addr(self.dodag_id)

    def build_dao(
        self, parent_address: IPv6Address | str, *, ack_requested: bool = False
    ) -> DAO:
        """Build this node's DAO advertising itself with ``parent_address``."""
        self._dao_sequence = (self._dao_sequence + 1) & 0xFF
        return DAO(
            rpl_instance_id=self.rpl_instance_id,
            dao_sequence=self._dao_sequence,
            dodag_id=self.dodag_id,
            ack_requested=ack_requested,
            options=[
                RplTarget(self.node_address).to_option(),
                TransitInformation(_addr(parent_address)).to_option(),
            ],
        )

    def process_dao(self, dao: DAO) -> DAOAck | None:
        """Root-side: record the target/parent edge and rebuild routes.

        Returns a DAO-ACK when the DAO requested one (K flag), else ``None``.
        """
        if not self.is_root:
            raise DaoError("process_dao is only valid on the root")

        target, parent = self._extract_edge(dao)
        self._parent_map[target] = parent
        self._rebuild_routes()

        if dao.ack_requested:
            return self.build_dao_ack(dao)
        return None

    def build_dao_ack(self, dao: DAO, status: int = 0) -> DAOAck:
        return DAOAck(
            rpl_instance_id=dao.rpl_instance_id,
            dao_sequence=dao.dao_sequence,
            status=status,
            dodag_id=dao.dodag_id,
        )

    @staticmethod
    def _extract_edge(dao: DAO) -> tuple[IPv6Address, IPv6Address]:
        target: IPv6Address | None = None
        parent: IPv6Address | None = None
        for opt in dao.options:
            if opt.type == RplOptionType.RPL_TARGET:
                target = RplTarget.from_option(opt).target
            elif opt.type == RplOptionType.TRANSIT_INFORMATION:
                parent = TransitInformation.from_option(opt).parent_address
        if target is None or parent is None:
            raise DaoError("DAO missing RPL Target or Transit Information")
        return target, parent

    def _rebuild_routes(self) -> None:
        for target in self._parent_map:
            path = self._assemble_path(target)
            if path is not None:
                self.routing_table.add_route(target, path)

    def _assemble_path(self, target: IPv6Address) -> list[IPv6Address] | None:
        """Walk target -> parent -> ... -> root; return the downward hop path.

        ``None`` if the chain is incomplete (a parent has not advertised yet) or
        contains a loop.
        """
        chain: list[IPv6Address] = []
        node = target
        visited: set[IPv6Address] = set()
        steps = 0
        while node != self.node_address:
            if node in visited or steps > _MAX_CHAIN:
                return None  # loop or runaway
            visited.add(node)
            chain.append(node)
            parent = self._parent_map.get(node)
            if parent is None:
                return None  # incomplete chain
            node = parent
            steps += 1
        return list(reversed(chain))
