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
class GroupMobility(MobilityPattern):
    """Group mobility pattern.

    A virtual group center navigates random waypoints within the area,
    while member nodes hold fixed offsets relative to the center. The
    first registered member sits at the center; remaining members are
    evenly spaced on a ring of radius group_radius_m around it.

    Center waypoints are picked within the bounds inset by
    group_radius_m, and the initial center is clamped into that inset,
    so every member stays inside area_bounds at all times.

    Attach the pattern to MobilityManager under one representative node
    id; step() moves all registered members. Attach one pattern instance
    per group only (attaching the same instance to multiple node ids
    would step the group once per attachment).

    Attributes:
        area_bounds: (min_x, max_x, min_y, max_y) in meters.
        speed_m_s: Group center movement speed in meters per second.
        pause_time_us: Pause duration at each waypoint in microseconds.
        seed: Random seed for reproducibility (None for random).
        z: Fixed altitude in meters (members stay at this height).
        group_size: Maximum number of member nodes in the group.
        group_radius_m: Distance from the center to ring members in meters.

    Raises:
        ValueError: If group_size < 1, speed_m_s <= 0, pause_time_us < 0,
            area_bounds min/max are inverted, or group_radius_m is
            negative or too large for the group to fit within bounds.
    """

    area_bounds: tuple[float, float, float, float]
    speed_m_s: float = 1.0
    pause_time_us: int = 5_000_000
    seed: int | None = None
    z: float = 0.0
    group_size: int = 1
    group_radius_m: float = 0.0

    # Internal state
    _rng: random.Random = field(init=False, repr=False)
    _state: WaypointState = field(init=False, default=WaypointState.PAUSED)
    _target: tuple[float, float] | None = field(init=False, default=None)
    _pause_remaining_us: int = field(init=False, default=0)
    _center: tuple[float, float] | None = field(init=False, default=None)
    _members: list[SimNode] = field(init=False, repr=False, default_factory=list)
    _offsets: list[tuple[float, float]] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        if self.group_size < 1:
            raise ValueError(f"group_size must be >= 1, got {self.group_size}")
        if self.speed_m_s <= 0:
            raise ValueError(f"speed_m_s must be > 0, got {self.speed_m_s}")
        if self.pause_time_us < 0:
            raise ValueError(f"pause_time_us must be >= 0, got {self.pause_time_us}")
        min_x, max_x, min_y, max_y = self.area_bounds
        if min_x >= max_x or min_y >= max_y:
            raise ValueError(f"area_bounds must have min < max, got {self.area_bounds}")
        if self.group_radius_m < 0:
            raise ValueError(f"group_radius_m must be >= 0, got {self.group_radius_m}")
        if 2 * self.group_radius_m > min(max_x - min_x, max_y - min_y):
            raise ValueError(f"group_radius_m {self.group_radius_m} too large for area_bounds")
        self._init_state()

    def _init_state(self) -> None:
        self._rng = random.Random(self.seed)
        self._state = WaypointState.PAUSED
        self._target = None
        self._pause_remaining_us = 0
        self._center = None
        self._members = []
        self._offsets = []

    def reset(self) -> None:
        """Reset pattern state, clearing group membership."""
        self._init_state()

    def add_member(self, node: SimNode) -> None:
        """Register a node as a group member.

        The member receives a fixed offset relative to the group center:
        the first member sits at the center, later members are evenly
        spaced on a ring of radius group_radius_m. The node's position is
        not changed until the next step().

        Args:
            node: The SimNode to add to the group.

        Raises:
            ValueError: If the group already has group_size members.
        """
        if len(self._members) >= self.group_size:
            raise ValueError(f"group is full at group_size={self.group_size}")
        self._members.append(node)
        self._offsets.append(self._offset_for(len(self._members) - 1))

    def step(self, node: SimNode, dt_us: int) -> None:
        """Advance the group center and reposition all members.

        The center navigates waypoints as in RandomWaypoint; after the
        step each member is placed at center + its fixed offset. Does
        nothing until at least one member is registered; the center then
        starts at the first member's position. The node argument is the
        attachment anchor used by MobilityManager and is moved only if
        registered as a member.

        Args:
            node: The SimNode the pattern is attached to.
            dt_us: Time step in microseconds.
        """
        if not self._members:
            return

        if self._center is None:
            x, y, _ = self._members[0].position
            min_x, max_x, min_y, max_y = self.area_bounds
            self._center = (
                min(max(x, min_x + self.group_radius_m), max_x - self.group_radius_m),
                min(max(y, min_y + self.group_radius_m), max_y - self.group_radius_m),
            )

        remaining_us = dt_us
        while remaining_us > 0:
            if self._state == WaypointState.PAUSED:
                remaining_us = self._handle_paused(remaining_us)
            else:
                remaining_us = self._handle_moving(remaining_us)

        self._place_members()

    def _offset_for(self, index: int) -> tuple[float, float]:
        """Return the fixed offset for the member registered at index."""
        if index == 0:
            return (0.0, 0.0)
        angle = 2.0 * math.pi * (index - 1) / (self.group_size - 1)
        return (self.group_radius_m * math.cos(angle), self.group_radius_m * math.sin(angle))

    def _handle_paused(self, remaining_us: int) -> int:
        """Handle pause state, returns remaining time after state change."""
        if self._pause_remaining_us > 0:
            if remaining_us <= self._pause_remaining_us:
                self._pause_remaining_us -= remaining_us
                return 0
            remaining_us -= self._pause_remaining_us
            self._pause_remaining_us = 0

        self._target = self._pick_waypoint()
        self._state = WaypointState.MOVING
        return remaining_us

    def _handle_moving(self, remaining_us: int) -> int:
        """Handle moving state, returns remaining time after state change."""
        if self._target is None or self._center is None:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        cx, cy = self._center
        tx, ty = self._target

        dx = tx - cx
        dy = ty - cy
        distance = math.sqrt(dx * dx + dy * dy)

        if distance < 1e-6:
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us

        time_s = remaining_us / 1_000_000.0
        max_distance = self.speed_m_s * time_s

        if max_distance >= distance:
            self._center = (tx, ty)
            time_used_us = int(distance / self.speed_m_s * 1_000_000)
            self._state = WaypointState.PAUSED
            self._pause_remaining_us = self.pause_time_us
            self._target = None
            return remaining_us - time_used_us

        ratio = max_distance / distance
        self._center = (cx + dx * ratio, cy + dy * ratio)
        return 0

    def _pick_waypoint(self) -> tuple[float, float]:
        """Pick a random waypoint within the bounds inset by group radius."""
        min_x, max_x, min_y, max_y = self.area_bounds
        x = self._rng.uniform(min_x + self.group_radius_m, max_x - self.group_radius_m)
        y = self._rng.uniform(min_y + self.group_radius_m, max_y - self.group_radius_m)
        return (x, y)

    def _place_members(self) -> None:
        """Place each member at the center plus its fixed offset."""
        if self._center is None:
            return
        cx, cy = self._center
        for member, (ox, oy) in zip(self._members, self._offsets, strict=True):
            member.set_position(cx + ox, cy + oy, self.z)


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
