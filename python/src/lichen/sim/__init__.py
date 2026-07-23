# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN wireless channel simulator.

Simulates LoRa radio propagation for testing without hardware.
Provides TCP interface for nodes and HTTP REST API for control.
"""

from lichen.sim.node import NodeState, SimNode
from lichen.sim.pcap import PcapngWriter
from lichen.sim.propagation import (
    CAPTURE_THRESHOLD_DB,
    PATH_LOSS_FREE_SPACE,
    PATH_LOSS_INDOOR,
    PATH_LOSS_URBAN,
    SENSITIVITY_DEFAULT,
    SENSITIVITY_SF7,
    SENSITIVITY_SF8,
    SENSITIVITY_SF9,
    SENSITIVITY_SF10,
    SENSITIVITY_SF11,
    SENSITIVITY_SF12,
    PropagationModel,
)
from lichen.sim.renode_server import RenodeServer, start_renode_server
from lichen.sim.tdma import SuperframeClock, TDMAScheduler, TDMAState, hash_32, synchronized_hop_channel

__all__ = [
    "CAPTURE_THRESHOLD_DB",
    "NodeState",
    "RenodeServer",
    "start_renode_server",
    "PATH_LOSS_FREE_SPACE",
    "PcapngWriter",
    "PATH_LOSS_INDOOR",
    "PATH_LOSS_URBAN",
    "PropagationModel",
    "SENSITIVITY_DEFAULT",
    "SENSITIVITY_SF7",
    "SENSITIVITY_SF8",
    "SENSITIVITY_SF9",
    "SENSITIVITY_SF10",
    "SENSITIVITY_SF11",
    "SENSITIVITY_SF12",
    "SimNode",
    "TDMAScheduler",
    "TDMAState",
    "SuperframeClock",
    "hash_32",
    "synchronized_hop_channel",
]
