# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN node web status dashboard.

Lightweight Starlette server that proxies a node's CoAP resources into a
live browser dashboard. Each section auto-refreshes via HTMX.

Usage:
    lichen-dashboard --node [::1]:5683 --port 8080
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import cbor2
import httpx
import uvicorn
from aiocoap import GET, Context, Message
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.websockets import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).parent
_templates = Jinja2Templates(directory=_BASE_DIR / "templates")

# ---------------------------------------------------------------------------
# CoAP helpers
# ---------------------------------------------------------------------------

_coap_ctx: Context | None = None
_node_addr: str = "coap://[::1]"
_sim_url: str | None = None
_topology_cache: dict[str, Any] = {}
_metrics_cache: dict[str, Any] = {}
_ws_clients: set[WebSocket] = set()


async def _get_coap_ctx() -> Context:
    global _coap_ctx
    if _coap_ctx is None:
        _coap_ctx = await Context.create_client_context()
    return _coap_ctx


async def _fetch(path: str) -> Any:
    """GET a CoAP resource, decode CBOR, return Python object or None on error."""
    try:
        ctx = await _get_coap_ctx()
        resp = await asyncio.wait_for(
            ctx.request(Message(code=GET, uri=f"{_node_addr}{path}")).response,
            timeout=5.0,
        )
        if resp.payload:
            return cbor2.loads(resp.payload)
        return None
    except Exception as exc:
        logger.warning("CoAP fetch %s failed: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# Simulator data helpers
# ---------------------------------------------------------------------------


async def _fetch_sim(path: str) -> Any:
    """GET a simulator REST resource, return parsed JSON or None."""
    if not _sim_url:
        return None
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{_sim_url}{path}", timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
            return None
    except Exception as exc:
        logger.debug("Sim fetch %s failed: %s", path, exc)
        return None


async def _refresh_sim_data() -> None:
    """Periodically refresh topology and metrics caches from the simulator."""
    while True:
        if _sim_url:
            topo = await _fetch_sim("/sim/demo/topology")
            if topo is not None:
                global _topology_cache
                _topology_cache = topo
                await _broadcast_ws({"event": "topology", "data": topo})
            metrics = await _fetch_sim("/sim/demo/metrics")
            if metrics is not None:
                global _metrics_cache
                _metrics_cache = metrics
                await _broadcast_ws({"event": "metrics", "data": metrics})
        await asyncio.sleep(3)


async def _broadcast_ws(data: dict[str, Any]) -> None:
    dead: set[WebSocket] = set()
    payload = json.dumps(data)
    for ws in _ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


async def index(request: Request):
    node_display = _node_addr.replace("coap://", "")
    return _templates.TemplateResponse(
        request, "index.html", {"node": node_display}
    )


async def partial_status(request: Request):
    data = await _fetch("/status")
    return _templates.TemplateResponse(
        request, "partials/status.html", {"data": data}
    )


async def partial_neighbors(request: Request):
    data = await _fetch("/neighbors")
    return _templates.TemplateResponse(
        request, "partials/list.html", {"data": data, "empty_msg": "No neighbors"}
    )


async def partial_presence(request: Request):
    data = await _fetch("/presence")
    return _templates.TemplateResponse(
        request, "partials/list.html", {"data": data, "empty_msg": "No peers in presence table"}
    )


async def partial_messages(request: Request):
    data = await _fetch("/msg/inbox")
    if isinstance(data, dict):
        data = data.get("messages")
    return _templates.TemplateResponse(
        request, "partials/list.html", {"data": data, "empty_msg": "Inbox empty"}
    )


async def partial_sensors(request: Request):
    data = await _fetch("/sensors")
    return _templates.TemplateResponse(request, "partials/senml.html", {"data": data})


async def partial_location(request: Request):
    data = await _fetch("/location")
    return _templates.TemplateResponse(request, "partials/senml.html", {"data": data})


async def partial_mesh_stats(request: Request):
    """Live stats from simulator REST API, falling back to mock."""
    metrics = _metrics_cache
    if metrics:
        t = metrics.get("transmissions", 0)
        cr = round(metrics.get("collision_rate", 0) * 100, 1)
        latency = metrics.get("latency_us", {})
        hops = round(latency.get("mean", 0) / 1000, 1) if latency.get("mean") else 0
        node_count = topology_node_count()
        context = {
            "active": f"{node_count}/{node_count}",
            "pps": t if t else 0,
            "loss": f"{cr}%",
            "hops": hops,
            "is_simulator": bool(_sim_url),
        }
    else:
        context = {
            "active": "-",
            "pps": 0,
            "loss": "-",
            "hops": "-",
            "is_simulator": bool(_sim_url),
        }
    return _templates.TemplateResponse(request, "partials/mesh_stats.html", context)


def topology_node_count() -> int:
    nodes = _topology_cache.get("nodes", [])
    return len(nodes) if nodes else 20


async def partial_topology_data(request: Request) -> JSONResponse:
    """Return topology node positions as JSON for D3.js rendering."""
    nodes = _topology_cache.get("nodes", [])
    if nodes:
        return JSONResponse({"nodes": nodes})
    # Fallback mock data
    import random
    random.seed(42)
    mock = [
        {
            "id": f"n{i}",
            "x": random.uniform(0, 800),
            "y": random.uniform(0, 380),
            "group": i % 4,
            "connected": True,
        }
        for i in range(20)
    ]
    return JSONResponse({"nodes": mock})


async def partial_mesh_metrics(request: Request) -> JSONResponse:
    """Return simulator metrics as JSON."""
    if _metrics_cache:
        return JSONResponse(_metrics_cache)
    return JSONResponse({
        "transmissions": 0,
        "receptions": 0,
        "collisions": 0,
        "delivery_rate": 0,
        "collision_rate": 0,
        "latency_us": {"count": 0, "min": None, "max": None, "mean": None},
    })


async def ws_events(websocket: WebSocket) -> None:
    """WebSocket endpoint for live dashboard events."""
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            try:
                _ = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except TimeoutError:
                await websocket.send_text('{"event":"ping"}')
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        _ws_clients.discard(websocket)


async def api_status(request: Request) -> JSONResponse:
    data = await _fetch("/status")
    return JSONResponse({"ok": data is not None, "data": data})


def create_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/", index),
            Route("/partial/status", partial_status),
            Route("/partial/neighbors", partial_neighbors),
            Route("/partial/presence", partial_presence),
            Route("/partial/messages", partial_messages),
            Route("/partial/sensors", partial_sensors),
            Route("/partial/location", partial_location),
            Route("/partial/mesh-stats", partial_mesh_stats),
            Route("/partial/topology-data", partial_topology_data),
            Route("/partial/mesh-metrics", partial_mesh_metrics),
            Route("/api/status", api_status),
            WebSocketRoute("/ws", ws_events),
            Mount("/static", StaticFiles(directory=_BASE_DIR / "static"), name="static"),
        ]
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LICHEN node web status dashboard")
    parser.add_argument(
        "--node",
        default="[::1]:5683",
        metavar="HOST:PORT",
        help="LICHEN node CoAP address (default: [::1]:5683)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        metavar="PORT",
        help="HTTP port for the dashboard (default: 8080)",
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        metavar="HOST",
        help="HTTP bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--sim-url",
        default=None,
        metavar="URL",
        help="Simulator REST API URL for live data (e.g. http://localhost:9000)",
    )
    args = parser.parse_args()

    global _node_addr, _sim_url
    _node_addr = f"coap://{args.node}"
    _sim_url = args.sim_url

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger.info("Dashboard: http://%s:%d  ->  CoAP node %s", args.bind, args.port, _node_addr)
    if _sim_url:
        logger.info("  Live data: %s", _sim_url)

    config = uvicorn.Config(
        create_app(), host=args.bind, port=args.port, log_level="warning"
    )
    server = uvicorn.Server(config)

    loop = asyncio.new_event_loop()
    if _sim_url:
        loop.create_task(_refresh_sim_data())
    loop.run_until_complete(server.serve())


if __name__ == "__main__":
    main()
