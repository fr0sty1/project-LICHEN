"""Main entry point for the LICHEN simulator server.

This module provides the SimulatorServer class that runs both the TCP node
server (for SimRadio client connections) and the HTTP REST API (for simulation
management).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import TYPE_CHECKING

import structlog
import uvicorn

from lichen.sim.api import SimulatorAPI
from lichen.sim.node_server import start_node_server
from lichen.sim.simulation import Simulation, TimeMode

if TYPE_CHECKING:
    from starlette.applications import Starlette


class SimulatorServer:
    """Server that runs both TCP node server and HTTP REST API.

    The SimulatorServer manages multiple simulations, each with its own
    TCP server for node connections. The REST API provides endpoints for
    creating/deleting simulations and managing nodes and chaos rules.

    Security note: The REST API has no authentication. Only bind to
    ``127.0.0.1`` (the default) in development environments. Do not expose
    the API port on a network interface accessible to untrusted hosts.

    Attributes:
        node_port: Base TCP port for node connections.
        api_port: HTTP port for REST API.
        bind_host: Host address to bind both servers.
    """

    def __init__(
        self, node_port: int = 4444, api_port: int = 4445, bind_host: str = "127.0.0.1"
    ) -> None:
        """Initialize the simulator server.

        Args:
            node_port: Base TCP port for node connections. Each simulation
                gets its own port starting from this value.
            api_port: HTTP port for the REST API.
            bind_host: Host address to bind. Defaults to ``127.0.0.1``
                (loopback only). Set to ``0.0.0.0`` only on a trusted
                network — the API has no authentication.
        """
        self.node_port = node_port
        self.api_port = api_port
        self.bind_host = bind_host
        self._simulations: dict[str, Simulation] = {}
        self._node_servers: dict[str, asyncio.Server] = {}
        self._api: SimulatorAPI | None = None
        self._uvicorn_server: uvicorn.Server | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._logger = structlog.get_logger()
        self._next_node_port = node_port

    async def start(self) -> None:
        """Start the simulator server.

        Creates the REST API and starts the uvicorn server. The REST API
        will handle simulation creation, which triggers TCP node server
        creation.
        """
        self._shutdown_event = asyncio.Event()

        # Create the API with callbacks so that creating/deleting a simulation
        # over REST also starts/stops its TCP node server. This is composition
        # via hooks rather than monkey-patching the API's methods at runtime.
        self._api = SimulatorAPI(
            on_simulation_created=self._start_node_server_for_sim,
            on_simulation_deleted=self._stop_node_server_for_sim,
        )
        # Share our simulations dict so both REST and programmatic paths agree.
        self._api._simulations = self._simulations

        # Create Starlette app
        app = self._api.create_app()

        # Start uvicorn server
        config = uvicorn.Config(
            app,
            host=self.bind_host,
            port=self.api_port,
            log_level="warning",
        )
        self._uvicorn_server = uvicorn.Server(config)

        # Run uvicorn in background task
        asyncio.create_task(self._uvicorn_server.serve())

        self._logger.info(
            "Simulator server started",
            api_port=self.api_port,
            node_port_base=self.node_port,
        )

    async def stop(self) -> None:
        """Stop the simulator server.

        Signals shutdown, stops uvicorn, and closes all TCP node servers.
        """
        self._logger.info("Shutting down simulator server")

        # Signal shutdown
        if self._shutdown_event is not None:
            self._shutdown_event.set()

        # Stop uvicorn
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True

        # Close all node servers
        for sim_id in list(self._node_servers.keys()):
            await self._stop_node_server_for_sim(sim_id)

        self._logger.info("Simulator server stopped")

    async def create_simulation(
        self,
        sim_id: str,
        time_mode: TimeMode = TimeMode.BARRIER_SYNC,
    ) -> Simulation:
        """Create a new simulation with its TCP node server.

        Args:
            sim_id: Unique identifier for the simulation.
            time_mode: Time advancement mode for the simulation.

        Returns:
            The created Simulation instance.

        Raises:
            ValueError: If a simulation with this ID already exists.
        """
        if sim_id in self._simulations:
            raise ValueError(f"Simulation '{sim_id}' already exists")

        # Create chaos engine and wire it to the simulation
        from lichen.sim.chaos import ChaosEngine

        chaos_engine = ChaosEngine()
        sim = Simulation(sim_id=sim_id, time_mode=time_mode, chaos_engine=chaos_engine)
        self._simulations[sim_id] = sim

        # Also register chaos engine in API if we have one
        if self._api is not None:
            self._api._chaos_engines[sim_id] = chaos_engine

        await self._start_node_server_for_sim(sim_id)

        self._logger.info(
            "Created simulation",
            sim_id=sim_id,
            time_mode=time_mode.name,
        )

        return sim

    async def delete_simulation(self, sim_id: str) -> None:
        """Delete a simulation and its TCP node server.

        Args:
            sim_id: ID of the simulation to delete.
        """
        await self._stop_node_server_for_sim(sim_id)

        self._simulations.pop(sim_id, None)

        if self._api is not None:
            self._api._chaos_engines.pop(sim_id, None)

        self._logger.info("Deleted simulation", sim_id=sim_id)

    def get_simulation(self, sim_id: str) -> Simulation | None:
        """Get a simulation by ID.

        Args:
            sim_id: ID of the simulation to retrieve.

        Returns:
            The Simulation instance, or None if not found.
        """
        return self._simulations.get(sim_id)

    def get_node_server_port(self, sim_id: str) -> int | None:
        """Get the TCP port for a simulation's node server.

        Args:
            sim_id: ID of the simulation.

        Returns:
            The port number, or None if not found.
        """
        server = self._node_servers.get(sim_id)
        if server is None or not server.sockets:
            return None
        port: int = server.sockets[0].getsockname()[1]
        return port

    def get_app(self) -> Starlette | None:
        """Get the Starlette application.

        Returns:
            The Starlette app, or None if not started.
        """
        if self._api is None:
            return None
        return self._api.create_app()

    async def _start_node_server_for_sim(self, sim_id: str) -> None:
        """Start a TCP node server for a simulation.

        Args:
            sim_id: ID of the simulation.
        """
        sim = self._simulations.get(sim_id)
        if sim is None:
            return

        # Use port 0 to let OS assign if base port is 0, otherwise use sequential ports
        if self.node_port == 0:
            port = 0
        else:
            port = self._next_node_port
            self._next_node_port += 1

        server = await start_node_server(sim, host=self.bind_host, port=port)
        self._node_servers[sim_id] = server

        actual_port = server.sockets[0].getsockname()[1]
        self._logger.info(
            "Started node server",
            sim_id=sim_id,
            port=actual_port,
        )

    async def _stop_node_server_for_sim(self, sim_id: str) -> None:
        """Stop the TCP node server for a simulation.

        Args:
            sim_id: ID of the simulation.
        """
        server = self._node_servers.pop(sim_id, None)
        if server is not None:
            server.close()
            await server.wait_closed()
            self._logger.info("Stopped node server", sim_id=sim_id)


def main() -> None:
    """CLI entry point for the LICHEN simulator server."""
    import argparse

    parser = argparse.ArgumentParser(description="LICHEN Simulator Server")
    parser.add_argument(
        "--node-port",
        type=int,
        default=4444,
        help="Base TCP port for node connections (default: 4444)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=4445,
        help="HTTP port for REST API (default: 4445)",
    )
    parser.add_argument(
        "--bind-address",
        default="127.0.0.1",
        metavar="HOST",
        help=(
            "Host address to bind (default: 127.0.0.1). "
            "The REST API has no authentication — only change this on a trusted network."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    # Configure structlog
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, args.log_level)
        ),
    )

    # Also configure standard logging for uvicorn
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(message)s",
    )

    # Create server
    server = SimulatorServer(
        node_port=args.node_port, api_port=args.api_port, bind_host=args.bind_address
    )

    async def run() -> None:
        await server.start()

        # Set up signal handlers
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        # Wait for shutdown signal
        try:
            await stop_event.wait()
        finally:
            await server.stop()

    # Run the server
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run())


if __name__ == "__main__":
    main()
