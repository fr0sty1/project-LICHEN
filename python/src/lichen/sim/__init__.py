# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN wireless channel simulator.

Simulates LoRa radio propagation for testing without hardware.
Provides TCP interface for nodes and HTTP REST API for control.
"""

from lichen.channel_plan import (
    AS923,
    AU915,
    CN470,
    EU868,
    IN865,
    KR920,
    REGIONAL_PLANS,
    REGIONAL_PLANS_BY_NAME,
    US915,
    ChannelEntry,
    ChannelPlan,
    channel_frequency,
    get_plan,
    get_plan_by_name,
    select_channel,
)
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
from lichen.sim.scenario import Scenario, ScenarioEvent, ScenarioRunner, parse_duration
from lichen.sim.tdma import (
    SuperframeClock,
    TDMAScheduler,
    TDMAState,
    hash_32,
    synchronized_hop_channel,
)
from lichen.sim.topology import (
    NodePosition,
    apply_topology,
    grid,
    line,
    random_disk,
    star,
)

__all__ = [
    "AS923",
    "AU915",
    "CN470",
    "CAPTURE_THRESHOLD_DB",
    "ChannelEntry",
    "ChannelPlan",
    "EU868",
    "IN865",
    "KR920",
    "NodePosition",
    "NodeState",
    "PATH_LOSS_FREE_SPACE",
    "PATH_LOSS_INDOOR",
    "PATH_LOSS_URBAN",
    "PcapngWriter",
    "PropagationModel",
    "REGIONAL_PLANS",
    "REGIONAL_PLANS_BY_NAME",
    "RenodeServer",
    "SENSITIVITY_DEFAULT",
    "SENSITIVITY_SF7",
    "SENSITIVITY_SF8",
    "SENSITIVITY_SF9",
    "SENSITIVITY_SF10",
    "SENSITIVITY_SF11",
    "SENSITIVITY_SF12",
    "Scenario",
    "ScenarioEvent",
    "ScenarioRunner",
    "SimNode",
    "SuperframeClock",
    "TDMAScheduler",
    "TDMAState",
    "US915",
    "apply_topology",
    "channel_frequency",
    "get_plan",
    "get_plan_by_name",
    "grid",
    "hash_32",
    "line",
    "parse_duration",
    "random_disk",
    "select_channel",
    "star",
    "start_renode_server",
    "synchronized_hop_channel",
]
