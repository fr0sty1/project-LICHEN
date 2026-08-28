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
import random
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
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
_coap_lock: asyncio.Lock | None = None
_node_addr: str = "coap://[::1]"
_sim_url: str | None = None
_topology_cache: dict[str, Any] = {}
_metrics_cache: dict[str, Any] = {}
_ws_clients: set[WebSocket] = set()
_refresh_task: asyncio.Task[None] | None = None

# Time-series history for telemetry graphs (last 60 samples per metric)
_HISTORY_SIZE = 60
_metrics_history: dict[str, list[float]] = {
    "rssi": [],
    "battery": [],
    "nodecount": [],
    "pps": [],
    "collision_rate": [],
}

# Alert thresholds
ALERT_THRESHOLDS = {
    "rssi": {"warn": -90, "crit": -100},  # dBm, higher is better
    "battery": {"warn": 25, "crit": 10},  # %, higher is better
    "collision_rate": {"warn": 5, "crit": 15},  # %, lower is better
}


async def _get_coap_ctx() -> Context:
    global _coap_ctx, _coap_lock
    if _coap_lock is None:
        _coap_lock = asyncio.Lock()
    async with _coap_lock:
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
    try:
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
    except asyncio.CancelledError:
        logger.debug("Refresh task cancelled, shutting down")
        raise


async def _start_refresh_task() -> None:
    """Start the background refresh task if simulator URL is configured."""
    global _refresh_task
    if _sim_url and _refresh_task is None:
        _refresh_task = asyncio.create_task(_refresh_sim_data())
        logger.debug("Started refresh task")


async def _stop_refresh_task() -> None:
    """Cancel and await the background refresh task."""
    global _refresh_task
    if _refresh_task is not None:
        _refresh_task.cancel()
        with suppress(asyncio.CancelledError):
            await _refresh_task
        _refresh_task = None
        logger.debug("Stopped refresh task")


async def _broadcast_ws(data: dict[str, Any]) -> None:
    dead: set[WebSocket] = set()
    payload = json.dumps(data)
    for ws in list(_ws_clients):
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
    data = await _fetch("/presence/cache")
    if isinstance(data, dict):
        data = data.get("nodes")
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


async def partial_metrics(request: Request):
    """Fetch /metrics SenML from CoAP and render with alerts and sparklines."""
    data = await _fetch("/metrics")

    # Parse SenML records into a dict
    metrics: dict[str, Any] = {}
    if data and isinstance(data, (list, tuple)):
        for rec in data:
            if isinstance(rec, dict):
                name = rec.get("n")
                value = rec.get("v")
                if name and value is not None:
                    # Normalize names for history tracking
                    key = name.replace("-", "_")
                    metrics[name] = {"value": value, "unit": rec.get("u", "")}
                    # Update history (skip non-numeric values)
                    if key in _metrics_history:
                        try:
                            numeric_val = float(value)
                            _metrics_history[key].append(numeric_val)
                            if len(_metrics_history[key]) > _HISTORY_SIZE:
                                _metrics_history[key] = _metrics_history[key][-_HISTORY_SIZE:]
                        except (ValueError, TypeError):
                            # Skip non-numeric SenML values for history tracking
                            pass

    # Calculate alert states
    alerts: dict[str, str] = {}
    for name, thresholds in ALERT_THRESHOLDS.items():
        display_name = name.replace("_", "-")
        if display_name in metrics:
            val = metrics[display_name]["value"]
            # Skip non-numeric values to avoid TypeError on comparison
            if not isinstance(val, (int, float)):
                continue
            if name == "collision_rate":
                # Lower is better
                if val >= thresholds["crit"]:
                    alerts[display_name] = "crit"
                elif val >= thresholds["warn"]:
                    alerts[display_name] = "warn"
            else:
                # Higher is better (rssi, battery)
                if val <= thresholds["crit"]:
                    alerts[display_name] = "crit"
                elif val <= thresholds["warn"]:
                    alerts[display_name] = "warn"

    # Generate SVG sparklines for each metric with history
    sparklines: dict[str, str] = {}
    for key, history in _metrics_history.items():
        if len(history) >= 2:
            sparklines[key.replace("_", "-")] = _generate_sparkline(history)

    return _templates.TemplateResponse(
        request,
        "partials/metrics.html",
        {
            "metrics": metrics,
            "alerts": alerts,
            "sparklines": sparklines,
            "has_data": bool(metrics),
        },
    )


def _generate_sparkline(values: list[float], width: int = 100, height: int = 24) -> str:
    """Generate an SVG sparkline path from a list of values."""
    if not values or len(values) < 2:
        return ""

    min_val = min(values)
    max_val = max(values)
    val_range = max_val - min_val if max_val != min_val else 1.0

    # Scale points to SVG coordinates
    x_step = width / (len(values) - 1)
    points = []
    for i, val in enumerate(values):
        x = i * x_step
        y = height - ((val - min_val) / val_range) * (height - 4) - 2
        points.append(f"{x:.1f},{y:.1f}")

    path = "M" + "L".join(points)
    return (
        f'<svg width="{width}" height="{height}" class="sparkline">'
        f'<path d="{path}" fill="none" stroke="#58a6ff" stroke-width="1.5"/>'
        f"</svg>"
    )


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
            "active": f"{node_count}/{node_count}" if node_count else "-",
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
    """Return the number of nodes in the topology cache, or 0 if no data."""
    nodes = _topology_cache.get("nodes", [])
    return len(nodes)


async def partial_topology_data(request: Request) -> JSONResponse:
    """Return topology node positions as JSON for D3.js rendering."""
    nodes = _topology_cache.get("nodes", [])
    if nodes:
        return JSONResponse({"nodes": nodes})
    # Fallback mock data - use local RNG to avoid polluting global state
    rng = random.Random(42)
    mock = [
        {
            "id": f"n{i}",
            "x": rng.uniform(0, 800),
            "y": rng.uniform(0, 380),
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
            except (TimeoutError, asyncio.TimeoutError):  # noqa: UP041 - need both for Python 3.10
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


@asynccontextmanager
async def _lifespan(app: Starlette) -> AsyncGenerator[None, None]:
    """Manage background task lifecycle for Starlette app."""
    await _start_refresh_task()
    try:
        yield
    finally:
        await _stop_refresh_task()
        if _coap_ctx is not None:
            await _coap_ctx.shutdown()


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
            Route("/partial/metrics", partial_metrics),
            Route("/partial/mesh-stats", partial_mesh_stats),
            Route("/partial/topology-data", partial_topology_data),
            Route("/partial/mesh-metrics", partial_mesh_metrics),
            Route("/api/status", api_status),
            WebSocketRoute("/ws", ws_events),
            Mount("/static", StaticFiles(directory=_BASE_DIR / "static"), name="static"),
        ],
        lifespan=_lifespan,
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
    loop.run_until_complete(server.serve())


if __name__ == "__main__":
    main()
