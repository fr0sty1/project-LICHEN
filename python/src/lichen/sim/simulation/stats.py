# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Statistics and metrics mixin for the simulation.

This module provides the StatsMixin class that adds statistics tracking
and metrics export operations to the simulation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lichen.sim.node import NodeState


class StatsMixin:
    """Mixin providing statistics and metrics operations.

    This mixin adds methods for tracking simulation statistics and
    exporting metrics data.
    """

    # Type hints for attributes from base class
    _nodes: dict[str, Any]
    _event_queue: Any
    _pending_rx_timeouts: dict[str, int]
    _debug_enabled: bool

    def get_connected_node_count(self) -> int:
        """Return the number of connected nodes.

        Returns:
            Count of nodes where connected is True.
        """
        return sum(1 for n in self._nodes.values() if n.connected)

    def _get_blocked_node_info(self) -> dict[str, int]:
        """Return detailed blocked node info for debug logging.

        Returns counts of total, connected, rx_wait, tx, idle, blocked nodes
        when debug is enabled (blocked = rx_wait count for barrier sync).
        """
        if not self._debug_enabled:
            return {}
        connected_nodes = [n for n in self._nodes.values() if n.connected]
        rx_wait = sum(1 for n in connected_nodes if n.state == NodeState.RX_WAIT)
        return {
            "total": len(self._nodes),
            "connected": len(connected_nodes),
            "rx_wait": rx_wait,
            "tx": sum(1 for n in connected_nodes if n.state == NodeState.TX),
            "idle": sum(1 for n in connected_nodes if n.state == NodeState.IDLE),
            "blocked": rx_wait,
        }

    def export_metrics(self, path: Path | str) -> None:
        """Export per-node metrics as JSON for analysis.

        Writes a JSON file containing per-node telemetry metrics including
        TX/RX counts, byte totals, unique peers seen, and packet hashes
        (32-char lowercase hex of first 16 SHA256 bytes). Matches Rust
        hetero_node.rs METRICS export for cross-impl interop.

        Args:
            path: Path to the output JSON file.
        """
        path = Path(path)
        metrics = {node_id: node.metrics.to_dict() for node_id, node in self._nodes.items()}
        path.write_text(json.dumps(metrics, indent=2))
