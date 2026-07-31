# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Mobility patterns for LICHEN simulator.

Provides gradual node movement patterns as an alternative to instant
teleportation via set_position(). Each pattern implements step(node, dt)
to advance node position over time.

Example usage:
    from lichen.sim.mobility import RandomWaypoint

    # Create pattern: 500m x 500m area, 1 m/s speed, 5s pause
    pattern = RandomWaypoint(
        area_bounds=(0, 500, 0, 500),
        speed_m_s=1.0,
        pause_time_us=5_000_000,
        seed=42,
    )

    # In simulation loop:
    pattern.step(node, dt_us=1_000_000)  # 1 second step
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.sim.node import SimNode


class MobilityPattern(ABC):
    """Base class for node mobility patterns.

    Subclasses implement step() to update node position over time.
    Patterns maintain their own state (destination, pause timer, etc).
    """

    @abstractmethod
    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the node's position by dt_us microseconds.

        Args:
            node: The SimNode to move.
            dt_us: Time step in microseconds.
        """
        ...

    @abstractmethod
    def reset(self) -> None:
        """Reset pattern state for reuse or reattachment to new node."""
        ...


class WaypointState(Enum):
    """State of a RandomWaypoint pattern."""

    MOVING = auto()
    PAUSED = auto()


@dataclass
class RandomWaypoint(MobilityPattern):
    """Random waypoint mobility pattern.

    Node picks a random destination within bounds, moves toward it at
    constant speed, pauses for a duration, then picks a new destination.

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        speed_m_s: Movement speed in meters per second.
        pause_time_us: Pause duration at each waypoint in microseconds.
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (nodes stay at this height).
    """

    area_bounds: tuple[float, float, float, float]
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    seed: int | None = None
    z: float = 0.0

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.PAUSED)
    _target: tuple[float, float] | None = field(init=False, default=None)
    _pause_remaining_us: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0

    def reset(self) -> None:
        """Reset pattern to initial state."""
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance node position by dt_us microseconds.

        Args:
            node: The SimNode to move.
            dt_us: Time step in microseconds.
        """
        remaining_us = dt_us

        while remaining_us > 0:
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(node, remaining_us)
            else:
                remaining_us = self._handle_moving(node, remaining_us)

    def _handle_paused(self, node: SimNode, remaining_us: int) -> int:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        # Pause complete - pick new destination and start moving
        self._target = self._pick_waypoint()
        self._state = WaypointState.MOVING
        return remaining_us

    def _handle_moving(self, node: SimNode, remaining_us: int) -> int:
        """Handle moving state, returns remaining time after state change."""
        if self._target is None:
            # No target - go to pause state
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            return remaining_us

        x, y, _ = node.position
        tx, ty = self._target

        dx = tx - x
        dy = ty - y
        distance = math.sqrt(dx * dx + dy * dy)

        if distance < 1e-6:
            # Arrived at waypoint - enter pause
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        # Calculate how far we can move in remaining time
        time_s = remaining_us / 1_000_000.0
        max_distance = self.speed_m_s * time_s

        if max_distance >= distance:
            # We arrive this step
            node.set_position(tx, ty, self.z)
            time_used_s = distance / self.speed_m_s
            time_used_us = int(time_used_s * 1_000_000)
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us - time_used_us

        # Move toward target
        ratio = max_distance / distance
        new_x = x + dx * ratio
        new_y = y + dy * ratio
        node.set_position(new_x, new_y, self.z)
        return 0

    def _pick_waypoint(self) -> tuple[float, float]:
        """Pick a random waypoint within bounds."""
        min_x, max_x, min_y, max_y = self.area_bounds
        x = self._rng.uniform(min_x, max_x)
        y = self._rng.uniform(min_y, max_y)
        return (x, y)


@dataclass
class MobilityManager:
    """Manages mobility patterns for multiple nodes.

    Convenience class for attaching patterns to nodes and stepping
    all patterns together.
    """

    _patterns: dict[str, MobilityPattern] = field(default_factory=dict)

    def attach(self, node_id: str, pattern: MobilityPattern) -> None:
        """Attach a mobility pattern to a node.

        Args:
            node_id: The node ID to attach the pattern to.
            pattern: The MobilityPattern instance.
        """
        self._patterns[node_id] = pattern

    def detach(self, node_id: str) -> MobilityPattern | None:
        """Detach and return the pattern from a node.

        Args:
            node_id: The node ID to detach from.

        Returns:
            The detached pattern, or None if not found.
        """
        return self._patterns.pop(node_id, None)

    def step_all(self, nodes: dict[str, SimNode], dt_us: int) -> None:
        """Step all attached patterns.

        Args:
            nodes: Dict mapping node_id to SimNode.
            dt_us: Time step in microseconds.
        """
        for node_id, pattern in self._patterns.items():
            node = nodes.get(node_id)
            if node is not None:
                pattern.step(node, dt_us)

    def get_pattern(self, node_id: str) -> MobilityPattern | None:
        """Get the pattern attached to a node.

        Args:
            node_id: The node ID.

        Returns:
            The pattern, or None if not found.
        """
        return self._patterns.get(node_id)

    def clear(self) -> None:
        """Remove all attached patterns."""
        self._patterns.clear()
