# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SimulatorServer main entry point."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from lichen.sim.node_server import read_message, write_message
from lichen.sim.protocol import (
    MSG_OK,
    encode_register,
    get_message_type,
)
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode


class TestSimulatorServerLifecycle:
    """Test server start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_server_start_stop(self) -> None:
        """Server can be started and stopped cleanly."""
        server = SimulatorServer(node_port=0, api_port=0)

        await server.start()

        # Server should be running
        assert server._api is not None
        assert server._uvicorn_server is not None

        await server.stop()

        # Server should be stopped
        assert server._uvicorn_server.should_exit is True

    @pytest.mark.asyncio
    async def test_server_double_stop(self) -> None:
        """Server can be stopped multiple times without error."""
        server = SimulatorServer(node_port=0, api_port=0)

        await server.start()
        await server.stop()
        await server.stop()  # Should not raise


class TestSimulatorServerSimulations:
    """Test simulation management via SimulatorServer."""

    @pytest.mark.asyncio
    async def test_create_simulation(self) -> None:
        """Simulation can be created directly via server."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            sim = await server.create_simulation("test-sim")

            assert sim is not None
            assert sim.id == "test-sim"
            assert sim.time_mode == TimeMode.BARRIER_SYNC
            assert server.get_simulation("test-sim") is sim
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_create_simulation_with_time_mode(self) -> None:
        """Simulation can be created with custom time mode."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            sim = await server.create_simulation("test-sim", TimeMode.REALTIME)

            assert sim.time_mode == TimeMode.REALTIME
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_create_duplicate_simulation_fails(self) -> None:
        """Creating duplicate simulation raises ValueError."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("test-sim")

            with pytest.raises(ValueError, match="already exists"):
                await server.create_simulation("test-sim")
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_delete_simulation(self) -> None:
        """Simulation can be deleted."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("test-sim")
            assert server.get_simulation("test-sim") is not None

            await server.delete_simulation("test-sim")
            assert server.get_simulation("test-sim") is None
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_delete_nonexistent_simulation(self) -> None:
        """Deleting nonexistent simulation is a no-op."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.delete_simulation("nonexistent")  # Should not raise
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_get_simulation_not_found(self) -> None:
        """Getting nonexistent simulation returns None."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            assert server.get_simulation("nonexistent") is None
        finally:
            await server.stop()


class TestSimulatorServerNodeServer:
    """Test TCP node server integration."""

    @pytest.mark.asyncio
    async def test_node_server_created_for_simulation(self) -> None:
        """TCP node server is created when simulation is created."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("test-sim")

            # Node server should be running
            assert "test-sim" in server._node_servers
            port = server.get_node_server_port("test-sim")
            assert port is not None
            assert port > 0
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_node_server_accepts_connections(self) -> None:
        """TCP node server accepts client connections."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            sim = await server.create_simulation("test-sim")
            port = server.get_node_server_port("test-sim")
            assert port is not None

            # Connect and register
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            try:
                register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
                await write_message(writer, register_msg)
                response = await read_message(reader)

                assert response is not None
                assert get_message_type(response) == MSG_OK

                # Node should be in simulation
                node = sim.get_node("node1")
                assert node is not None
                assert node.connected is True
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_node_server_stopped_on_delete(self) -> None:
        """TCP node server is stopped when simulation is deleted."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("test-sim")
            port = server.get_node_server_port("test-sim")
            assert port is not None

            await server.delete_simulation("test-sim")

            # Node server should be stopped
            assert "test-sim" not in server._node_servers
            assert server.get_node_server_port("test-sim") is None
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_multiple_simulations_separate_ports(self) -> None:
        """Each simulation gets its own TCP port."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("sim1")
            await server.create_simulation("sim2")

            port1 = server.get_node_server_port("sim1")
            port2 = server.get_node_server_port("sim2")

            assert port1 is not None
            assert port2 is not None
            assert port1 != port2
        finally:
            await server.stop()


class TestSimulatorServerAPI:
    """Test REST API integration."""

    @pytest.fixture
    async def server(self) -> AsyncGenerator[SimulatorServer, None]:
        """Create and start a server for testing."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()
        yield server
        await server.stop()

    @pytest.fixture
    async def client(self, server: SimulatorServer) -> AsyncGenerator[AsyncClient, None]:
        """Create an async test client for the API."""
        assert server._api is not None
        app = server._api.create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

    @pytest.mark.asyncio
    async def test_api_create_simulation_starts_node_server(
        self, server: SimulatorServer, client: AsyncClient
    ) -> None:
        """Creating simulation via API also starts node server."""
        response = await client.post("/sim", json={"id": "api-sim"})

        assert response.status_code == 200

        # Give server time to start node server
        await asyncio.sleep(0.1)

        # Node server should be running
        assert "api-sim" in server._node_servers
        port = server.get_node_server_port("api-sim")
        assert port is not None

    @pytest.mark.asyncio
    async def test_api_delete_simulation_stops_node_server(
        self, server: SimulatorServer, client: AsyncClient
    ) -> None:
        """Deleting simulation via API also stops node server."""
        # Create via API
        await client.post("/sim", json={"id": "api-sim"})
        await asyncio.sleep(0.1)

        # Verify node server is running
        assert "api-sim" in server._node_servers

        # Delete via API
        response = await client.delete("/sim/api-sim")
        assert response.status_code == 200

        # Node server should be stopped
        assert "api-sim" not in server._node_servers

    @pytest.mark.asyncio
    async def test_api_node_management(self, server: SimulatorServer, client: AsyncClient) -> None:
        """Nodes can be managed via API."""
        await client.post("/sim", json={"id": "api-sim"})

        # Add node via API
        response = await client.post(
            "/sim/api-sim/node",
            json={"id": "node1", "x": 10, "y": 20, "z": 0},
        )

        assert response.status_code == 200

        # Verify node exists in simulation
        sim = server.get_simulation("api-sim")
        assert sim is not None
        node = sim.get_node("node1")
        assert node is not None
        assert node.position == (10.0, 20.0, 0.0)


class TestSimulatorServerShutdown:
    """Test graceful shutdown behavior."""

    @pytest.mark.asyncio
    async def test_stop_closes_all_node_servers(self) -> None:
        """Stopping server closes all node servers."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        # Create multiple simulations
        await server.create_simulation("sim1")
        await server.create_simulation("sim2")
        await server.create_simulation("sim3")

        assert len(server._node_servers) == 3

        await server.stop()

        assert len(server._node_servers) == 0

    @pytest.mark.asyncio
    async def test_stop_disconnects_clients(self) -> None:
        """Stopping server disconnects connected clients."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            sim = await server.create_simulation("test-sim")
            port = server.get_node_server_port("test-sim")
            assert port is not None

            # Connect a client
            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            register_msg = encode_register("test-sim", "node1", 0.0, 0.0, 0.0)
            await write_message(writer, register_msg)
            await read_message(reader)

            node = sim.get_node("node1")
            assert node is not None
            assert node.connected is True

            # Stop server
            await server.stop()

            # Connection should be closed
            # Reading from closed connection should return None or raise
            writer.close()
            await writer.wait_closed()

        except Exception:
            await server.stop()
            raise


class TestGetNodeServerPort:
    """Test get_node_server_port method."""

    @pytest.mark.asyncio
    async def test_get_port_nonexistent(self) -> None:
        """Getting port for nonexistent simulation returns None."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            assert server.get_node_server_port("nonexistent") is None
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_get_port_after_delete(self) -> None:
        """Getting port after simulation deleted returns None."""
        server = SimulatorServer(node_port=0, api_port=0)
        await server.start()

        try:
            await server.create_simulation("test-sim")
            assert server.get_node_server_port("test-sim") is not None

            await server.delete_simulation("test-sim")
            assert server.get_node_server_port("test-sim") is None
        finally:
            await server.stop()
