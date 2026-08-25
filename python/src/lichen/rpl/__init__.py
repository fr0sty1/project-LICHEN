# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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
from lichen.rpl.dao_origin import (
    DAO_ORIGIN_DOMAIN,
    DAO_ORIGIN_SIGNATURE_LENGTH,
    DAO_ORIGIN_SIGNATURE_TYPE,
    DaoOriginRejectReason,
    DaoOriginResult,
    DaoOriginSignature,
    DaoOriginValidator,
    OriginReplayStore,
    PinTable,
    compute_dao_digest,
    compute_signature_transcript,
    extract_unsigned_dao_bytes,
)
from lichen.rpl.dao_persistence import (
    DaoPersistence,
    DaoPersistenceError,
    MemoryPersistence,
    RxFloor,
    TwoSlotFilePersistence,
    TxState,
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
    RplOption,
    RplOptionType,
    from_icmpv6,
    to_icmpv6,
)
from lichen.rpl.multi_instance import (
    DaoBackboneBridge,
    DaoBackboneMessage,
    GatewayInfo,
    GatewayRole,
    MultiRootCoordinator,
    generate_multi_instance_vectors,
    iid_compare,
    resolve_slot_conflict,
    validate_rpl_instance_id,
)
from lichen.rpl.root_signature import (
    RootSignatureError,
    RootSignatureResult,
    derive_dodagid_from_pubkey,
    verify_dodagid_binding,
    verify_root_signature,
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
from lichen.rpl.visualize import (
    format_source_route,
    ranks_from_states,
    to_ascii,
    to_dot,
    topology_from_states,
)

__all__ = [
    "DAO",
    "DAO_ORIGIN_DOMAIN",
    "DAO_ORIGIN_SIGNATURE_LENGTH",
    "DAO_ORIGIN_SIGNATURE_TYPE",
    "DIO",
    "DIS",
    "DAOAck",
    "DaoBackboneBridge",
    "DaoBackboneMessage",
    "DaoError",
    "DaoManager",
    "DaoOriginRejectReason",
    "DaoOriginResult",
    "DaoOriginSignature",
    "DaoOriginValidator",
    "DaoPersistence",
    "DaoPersistenceError",
    "DodagRole",
    "DodagState",
    "GatewayInfo",
    "GatewayRole",
    "MemoryPersistence",
    "ModeOfOperation",
    "MultiRootCoordinator",
    "OriginReplayStore",
    "ParentCandidate",
    "PinTable",
    "RoutingError",
    "RplTarget",
    "RxFloor",
    "RootSignatureError",
    "RootSignatureResult",
    "TransitInformation",
    "RoutingTable",
    "RplCode",
    "RplError",
    "RplOption",
    "RplOptionType",
    "SourceRoutingHeader",
    "TrickleTimer",
    "TwoSlotFilePersistence",
    "TxState",
    "advance_source_route",
    "compute_dao_digest",
    "compute_signature_transcript",
    "derive_dodagid_from_pubkey",
    "extract_unsigned_dao_bytes",
    "format_source_route",
    "from_icmpv6",
    "generate_multi_instance_vectors",
    "iid_compare",
    "insert_source_route",
    "next_hop_upward",
    "ranks_from_states",
    "resolve_slot_conflict",
    "to_ascii",
    "to_dot",
    "to_icmpv6",
    "topology_from_states",
    "validate_rpl_instance_id",
    "verify_dodagid_binding",
    "verify_root_signature",
]
