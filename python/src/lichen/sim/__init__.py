# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa Medium Simulator - Generic radio propagation for any LoRa stack.

This module provides a reusable LoRa radio medium simulation that is not
LICHEN-specific. The core components can be used with any LoRa protocol:
Meshtastic, LoRaWAN, RadioHead, or custom implementations.

Reusable Core Components
------------------------
These have no LICHEN-specific dependencies:

- :class:`PropagationModel`: Log-distance path loss with shadowing/fading
- :class:`Medium`: Radio medium with collision detection and capture effect
- :class:`DutyCycleTracker`: EU868-style regulatory duty cycle tracking
- :class:`ChaosEngine`: Fault injection (drops, partitions, jammers, latency)
- :class:`Transmission`: Transmission model with airtime calculation

Regional channel plans and channel selection are also generic LoRa utilities.

Example: Standalone LoRa Medium Simulation
------------------------------------------
>>> from lichen.sim import PropagationModel, Medium, Transmission
>>> from lichen.sim import DutyCycleTracker, ChaosEngine, DropRule
>>>
>>> # Create a propagation model (urban environment)
>>> prop = PropagationModel(n=2.7, shadow_std_db=4.0)
>>>
>>> # Create the radio medium with 1% duty cycle
>>> medium = Medium(propagation=prop, duty_cycle_limit_percent=1.0)
>>>
>>> # Transmit from node A at position (0, 0, 0)
>>> tx = medium.start_tx(
...     node_id="node_a",
...     payload=b"hello",
...     tx_power_dbm=14,
...     position=(0.0, 0.0, 0.0),
...     time_us=0,
... )
>>>
>>> # Check what node B at (100, 0, 0) can receive
>>> candidates = medium.get_rx_candidates(
...     rx_node_id="node_b",
...     rx_position=(100.0, 0.0, 0.0),
...     time_us=10000,
... )
>>>
>>> # Resolve collisions (capture effect)
>>> received = medium.resolve_reception(candidates)

Wire Protocol
-------------
The :mod:`lichen.sim.protocol` module defines a binary wire protocol for
node-to-simulator communication over TCP. This enables hardware-in-the-loop
testing where real embedded code talks to the simulated radio medium.

LICHEN Integration
------------------
When used within LICHEN, additional components provide:

- TCP server for simulated nodes (:mod:`lichen.sim.server`)
- HTTP REST API for control (:mod:`lichen.sim.api`)
- Scenario runner for automated tests (:mod:`lichen.sim.scenario`)
- Renode integration for Zephyr firmware testing (:mod:`lichen.sim.renode_server`)
"""

# Core components from lora-medium package
from lora_medium import (
    CAPTURE_THRESHOLD_DB,
    PATH_LOSS_FREE_SPACE,
    PATH_LOSS_INDOOR,
    PATH_LOSS_URBAN,
    QUIRK_PRESETS,
    SENSITIVITY_DEFAULT,
    SENSITIVITY_SF7,
    SENSITIVITY_SF8,
    SENSITIVITY_SF9,
    SENSITIVITY_SF10,
    SENSITIVITY_SF11,
    SENSITIVITY_SF12,
    ChannelLoad,
    # Chaos engineering
    ChaosEngine,
    ChaosRule,
    DegradeRule,
    DropRule,
    # Duty cycle
    DutyCycleTracker,
    GilbertElliottRule,
    JammerRule,
    LatencyRule,
    LossRule,
    Medium,
    PartitionRule,
    PropagationModel,
    QuirkProfile,
    RendezvousInfo,
    RendezvousMechanism,
    RxCandidate,
    TDMASlot,
    TDMAVector,
    Transmission,
    TxJitterRule,
    airtime_us,
    lr_fhss_airtime_us,
)

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
from lichen.sim.baseline import (
    BaselineComparisonResult,
    BaselineSnapshot,
    MetricRegression,
    RegressionThresholds,
    baseline_exists,
    compare_to_baseline,
    list_baselines,
    load_baseline,
    save_baseline,
    update_baseline,
)
from lichen.sim.hybrid import (
    HybridNode,
    HybridPropagationModel,
    NodeType,
    RFMeasurement,
    create_hybrid_topology,
)
from lichen.sim.mobility import (
    MobilityManager,
    MobilityPattern,
    RandomWaypoint,
)
from lichen.sim.node import NodeState, SimNode
from lichen.sim.pcap import PcapngWriter
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
    # Regional channel plans (generic LoRa)
    "AS923",
    "AU915",
    "CN470",
    "ChannelEntry",
    "ChannelPlan",
    "EU868",
    "IN865",
    "KR920",
    "REGIONAL_PLANS",
    "REGIONAL_PLANS_BY_NAME",
    "US915",
    "channel_frequency",
    "get_plan",
    "get_plan_by_name",
    "select_channel",
    # Core reusable components (no LICHEN dependencies)
    "ChaosEngine",
    "ChaosRule",
    "ChannelLoad",
    "DegradeRule",
    "DropRule",
    "DutyCycleTracker",
    "GilbertElliottRule",
    "JammerRule",
    "LatencyRule",
    "LossRule",
    "Medium",
    "PartitionRule",
    "PropagationModel",
    "RendezvousInfo",
    "RendezvousMechanism",
    "RxCandidate",
    "TDMASlot",
    "TDMAVector",
    "Transmission",
    "TxJitterRule",
    "airtime_us",
    "lr_fhss_airtime_us",
    # Propagation constants
    "CAPTURE_THRESHOLD_DB",
    "PATH_LOSS_FREE_SPACE",
    "PATH_LOSS_INDOOR",
    "PATH_LOSS_URBAN",
    "SENSITIVITY_DEFAULT",
    "SENSITIVITY_SF7",
    "SENSITIVITY_SF8",
    "SENSITIVITY_SF9",
    "SENSITIVITY_SF10",
    "SENSITIVITY_SF11",
    "SENSITIVITY_SF12",
    # Hardware quirks
    "QUIRK_PRESETS",
    "QuirkProfile",
    # TDMA scheduling
    "SuperframeClock",
    "TDMAScheduler",
    "TDMAState",
    "hash_32",
    "synchronized_hop_channel",
    # Baseline regression testing
    "BaselineComparisonResult",
    "BaselineSnapshot",
    "MetricRegression",
    "RegressionThresholds",
    "baseline_exists",
    "compare_to_baseline",
    "list_baselines",
    "load_baseline",
    "save_baseline",
    "update_baseline",
    # Hybrid simulation
    "HybridNode",
    "HybridPropagationModel",
    "NodeType",
    "RFMeasurement",
    "create_hybrid_topology",
    # Mobility
    "MobilityManager",
    "MobilityPattern",
    "RandomWaypoint",
    # Topology
    "NodePosition",
    "apply_topology",
    "grid",
    "line",
    "random_disk",
    "star",
    # Simulator infrastructure
    "NodeState",
    "PcapngWriter",
    "RenodeServer",
    "Scenario",
    "ScenarioEvent",
    "ScenarioRunner",
    "SimNode",
    "parse_duration",
    "start_renode_server",
]
