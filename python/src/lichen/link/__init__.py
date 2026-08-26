# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN link layer.

Frame format, signatures, replay protection, link-layer security, TX queue,
and operating class definitions (CCP-3/CCP-4).
"""

from lichen.link.address_assignment import (
    SHORT_ADDRESS_OPTION_TYPE,
    AddressAssignmentAck,
    AddressAssignmentRequest,
    AssignmentOperation,
    AssignmentPersistenceError,
    AssignmentProtocolError,
    AssignmentStatus,
    MemoryAddressAssignmentStore,
    ShortAddressAssignmentClient,
    ShortAddressCoordinator,
)
from lichen.link.channel import GnssHopConfig
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.link.op_class import (
    OPERATING_CLASS_TABLE,
    OperatingClass,
    OperatingClassParams,
    lookup_operating_class,
)
from lichen.link.replay import (
    WINDOW_SIZE,
    ReplayProtector,
    ReplayWindow,
    logical_counter,
)
from lichen.link.tx_queue import (
    DEADLINE_ACK_MS,
    DEADLINE_APP_MS,
    DEADLINE_BULK_MS,
    DEADLINE_ROUTING_MS,
    DEADLINE_SOS_MS,
    DEADLINE_URGENT_MS,
    TX_QUEUE_CAPACITY,
    Priority,
    QueueFullError,
    TxQueue,
    TxQueueEntry,
    TxQueueStats,
)

__all__ = [
    "DEADLINE_ACK_MS",
    "DEADLINE_APP_MS",
    "DEADLINE_BULK_MS",
    "DEADLINE_ROUTING_MS",
    "DEADLINE_SOS_MS",
    "DEADLINE_URGENT_MS",
    "GnssHopConfig",
    "SHORT_ADDRESS_OPTION_TYPE",
    "OPERATING_CLASS_TABLE",
    "OperatingClass",
    "OperatingClassParams",
    "Priority",
    "QueueFullError",
    "TX_QUEUE_CAPACITY",
    "TxQueue",
    "TxQueueEntry",
    "TxQueueStats",
    "WINDOW_SIZE",
    "AddrMode",
    "AddressAssignmentAck",
    "AddressAssignmentRequest",
    "AssignmentOperation",
    "AssignmentPersistenceError",
    "AssignmentProtocolError",
    "AssignmentStatus",
    "FrameError",
    "LichenFrame",
    "MicLength",
    "MemoryAddressAssignmentStore",
    "ReplayProtector",
    "ReplayWindow",
    "ShortAddressAssignmentClient",
    "ShortAddressCoordinator",
    "logical_counter",
    "lookup_operating_class",
]
