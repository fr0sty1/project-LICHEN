# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO handling for non-storing mode (RFC 6550, spec section 8.5).

This module re-exports the split DAO components for backward compatibility.
The implementation is now organized into:
  - dao_types: Message types, exceptions, and helper functions
  - dao_paths: Path computation utilities
  - dao_state: State tracking helpers
  - dao_manager: The main DaoManager class
  - dao_vectors: Test vector runner
"""
from __future__ import annotations

# Re-export public API from submodules for backward compatibility
from lichen.rpl.dao_manager import DaoManager
from lichen.rpl.dao_types import (
    DaoError,
    DaoOutcome,
    RplTarget,
    TransitInformation,
)
from lichen.rpl.dao_vectors import run_route_state_vectors

__all__ = [
    "DaoError",
    "DaoManager",
    "DaoOutcome",
    "RplTarget",
    "TransitInformation",
    "run_route_state_vectors",
]
