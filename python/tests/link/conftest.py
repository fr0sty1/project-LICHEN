# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared fixtures for link layer tests."""

import asyncio

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.link.link_layer import LinkLayer


class MockRadio:
    """Mock radio for testing link layer without real hardware.

    Why a mock: We're testing link layer logic, not radio behavior.
    The real radio is tested elsewhere (sim_client tests).
    """

    def __init__(self):
        self.tx_history: list[bytes] = []
        self.tx_attempts: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []
        self.cad_returns: bool = False  # False = channel clear
        self.transmit_returns: bool = True
        self.transmit_results: list[bool] = []
        self.transmit_error: Exception | None = None
        self.transmit_started: asyncio.Event | None = None
        self.transmit_release: asyncio.Event | None = None
        self.active_transmits = 0
        self.max_active_transmits = 0
        self.cad_started: asyncio.Event | None = None
        self.cad_release: asyncio.Event | None = None

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        """Record transmitted frames."""
        self.active_transmits += 1
        self.max_active_transmits = max(self.max_active_transmits, self.active_transmits)
        self.tx_attempts.append(payload)
        try:
            if self.transmit_error is not None:
                raise self.transmit_error
            if self.transmit_started is not None:
                self.transmit_started.set()
            if self.transmit_release is not None:
                await self.transmit_release.wait()
            result = (
                self.transmit_results.pop(0) if self.transmit_results else self.transmit_returns
            )
            if result:
                self.tx_history.append(payload)
            return result
        finally:
            self.active_transmits -= 1

    async def receive(self, timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        """Return next queued frame or None."""
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """No-op for mock."""
        pass

    async def cad(self, timeout_ms: int, channel: int = 0) -> bool:
        """Return configured CAD result (default: channel clear)."""
        if self.cad_started is not None:
            self.cad_started.set()
        if self.cad_release is not None:
            await self.cad_release.wait()
        return self.cad_returns

    def queue_rx(self, data: bytes, rssi: int = -50, snr: int = 10) -> None:
        """Queue a frame for reception."""
        self.rx_queue.append((data, rssi, snr))


@pytest.fixture
def node_identity() -> Identity:
    """Create a test node identity."""
    # Use fixed seed for reproducibility
    return Identity.from_seed(bytes(32))


@pytest.fixture
def peer_identity() -> Identity:
    """Create a test peer identity."""
    # Different seed than node
    return Identity.from_seed(bytes([1] + [0] * 31))


@pytest.fixture
def mock_radio() -> MockRadio:
    """Create a mock radio."""
    return MockRadio()


@pytest.fixture
def peer_db(peer_identity: Identity) -> dict[bytes, PeerIdentity]:
    """Create a peer database with one known peer."""
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    return {peer.iid: peer}


@pytest.fixture
def link_layer(
    mock_radio: MockRadio,
    node_identity: Identity,
    peer_db: dict[bytes, PeerIdentity],
) -> LinkLayer:
    """Create a link layer instance for testing."""

    def peer_lookup(hint: bytes) -> PeerIdentity | None:
        # For testing: return the first peer (simulating broadcast lookup)
        if peer_db:
            return next(iter(peer_db.values()))
        return None

    def peer_lookup_all() -> list[PeerIdentity]:
        # Return all known peers for exhaustive signature verification
        return list(peer_db.values())

    ll = LinkLayer(
        radio=mock_radio,
        identity=node_identity,
        peer_lookup=peer_lookup,
        peer_lookup_all=peer_lookup_all,
    )
    ll.set_sequence(0, 0)  # deterministic epoch for tests
    return ll
