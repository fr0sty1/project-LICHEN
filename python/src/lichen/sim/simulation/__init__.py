# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Core simulation engine for the LICHEN simulator.

This package provides the Simulation class that orchestrates simulated nodes,
manages time progression, and coordinates transmissions through the radio
medium.

Re-exports all public symbols from the original simulation.py module for
backward compatibility.
"""

from lichen.sim.simulation.base import (
    TimeMode,
    disable_debug,
    enable_debug,
    is_debug_enabled,
)
from lichen.sim.simulation.core import Simulation

__all__ = [
    "Simulation",
    "TimeMode",
    "disable_debug",
    "enable_debug",
    "is_debug_enabled",
]
