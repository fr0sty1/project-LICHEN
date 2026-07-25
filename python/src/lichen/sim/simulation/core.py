# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Core simulation class combining all mixins.

This module provides the final Simulation class that combines the base
class with all behavior mixins.
"""

from __future__ import annotations

from lichen.sim.simulation.base import SimulationBase, TimeMode
from lichen.sim.simulation.event_handlers import EventHandlersMixin
from lichen.sim.simulation.nodes import NodeManagementMixin
from lichen.sim.simulation.radio import RadioMixin
from lichen.sim.simulation.stats import StatsMixin


class Simulation(
    StatsMixin,
    RadioMixin,
    EventHandlersMixin,
    NodeManagementMixin,
    SimulationBase,
):
    """Core simulation engine that orchestrates nodes and events.

    The Simulation manages a collection of SimNodes, an EventQueue for
    time-ordered events, and a Medium for radio propagation. It supports
    two time modes:

    - BARRIER_SYNC: Deterministic mode where time only advances when all
      connected nodes are blocked (in RX_WAIT state). This ensures
      reproducible behavior for testing.

    - REALTIME: Time advances with the wall clock.

    This class combines functionality from multiple mixins:
    - SimulationBase: Core state and properties
    - NodeManagementMixin: Node CRUD operations
    - EventHandlersMixin: Event processing and time advancement
    - RadioMixin: Transmission and reception operations
    - StatsMixin: Statistics and metrics

    Attributes:
        id: Unique identifier for this simulation instance.
        time_mode: The time advancement mode.
        medium: The radio medium for propagation simulation.
        event_queue: Priority queue of simulation events.
    """

    pass


__all__ = ["Simulation", "TimeMode"]
