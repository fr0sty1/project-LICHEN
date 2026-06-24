# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN node web status dashboard.

Lightweight FastAPI server that proxies a node's CoAP resources into a
live browser dashboard. Each section auto-refreshes via HTMX polling.

Usage:
    lichen-dashboard --node [::1]:5683 --port 8080
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
from typing import Any

import cbor2
import uvicorn
from aiocoap import GET, Context, Message
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CoAP helpers
# ---------------------------------------------------------------------------

_coap_ctx: Context | None = None
_node_addr: str = "coap://[::1]"


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
# HTML rendering helpers
# ---------------------------------------------------------------------------

def _esc(v: Any) -> str:
    return html.escape(str(v))


def _kv_rows(data: dict[str, Any]) -> str:
    rows = []
    for k, v in data.items():
        rows.append(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>")
    return "\n".join(rows) or "<tr><td colspan='2'>(empty)</td></tr>"


def _render_status(data: Any) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    if isinstance(data, dict):
        return f"<table class='kv'>{_kv_rows(data)}</table>"
    return f"<pre>{_esc(json.dumps(data, default=str))}</pre>"


def _render_list(data: Any, empty_msg: str) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    if not isinstance(data, list) or not data:
        return f"<p class='empty'>{empty_msg}</p>"
    rows = []
    for item in data:
        if isinstance(item, dict):
            rows.append(f"<li><pre>{_esc(json.dumps(item, default=str, indent=2))}</pre></li>")
        else:
            rows.append(f"<li>{_esc(str(item))}</li>")
    return f"<ul>{''.join(rows)}</ul>"


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

async def index(request: Request) -> HTMLResponse:
    node_display = _node_addr.replace("coap://", "")
    return HTMLResponse(_PAGE_HTML.replace("{{NODE}}", html.escape(node_display)))


async def partial_status(request: Request) -> HTMLResponse:
    data = await _fetch("/status")
    return HTMLResponse(_render_status(data))


async def partial_neighbors(request: Request) -> HTMLResponse:
    data = await _fetch("/neighbors")
    return HTMLResponse(_render_list(data, "No neighbors"))


async def partial_presence(request: Request) -> HTMLResponse:
    data = await _fetch("/presence")
    return HTMLResponse(_render_list(data, "No peers in presence table"))


async def partial_messages(request: Request) -> HTMLResponse:
    data = await _fetch("/messages")
    return HTMLResponse(_render_list(data, "Inbox empty"))


async def partial_sensors(request: Request) -> HTMLResponse:
    data = await _fetch("/sensors")
    return HTMLResponse(_render_senml(data))


async def partial_location(request: Request) -> HTMLResponse:
    data = await _fetch("/location")
    return HTMLResponse(_render_senml(data))


async def api_status(request: Request) -> JSONResponse:
    data = await _fetch("/status")
    return JSONResponse({"ok": data is not None, "data": data})


def _render_senml(data: Any) -> str:
    """Render a SenML pack (list of [name, value, unit?, time?] or maps) as a table."""
    if data is None:
        return "<p class='err'>Unreachable</p>"
    if not isinstance(data, list) or not data:
        return "<p class='empty'>No data</p>"
    rows = []
    for entry in data:
        if isinstance(entry, list) and len(entry) >= 2:
            name, value = entry[0], entry[1]
            unit = entry[2] if len(entry) > 2 else ""
            rows.append(f"<tr><th>{_esc(name)}</th><td>{_esc(value)}{(' ' + _esc(unit)) if unit else ''}</td></tr>")
        elif isinstance(entry, dict):
            name = entry.get("n", entry.get(0, ""))
            value = entry.get("v", entry.get("vs", entry.get("vb", entry.get(2, ""))))
            unit = entry.get("u", entry.get(1, ""))
            rows.append(f"<tr><th>{_esc(name)}</th><td>{_esc(value)}{(' ' + _esc(unit)) if unit else ''}</td></tr>")
    if not rows:
        return f"<pre>{_esc(json.dumps(data, default=str))}</pre>"
    return f"<table class='kv'>{''.join(rows)}</table>"


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
            Route("/api/status", api_status),
        ]
    )


# ---------------------------------------------------------------------------
# HTML page template
# ---------------------------------------------------------------------------

_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LICHEN — {{NODE}}</title>
  <script src="https://unpkg.com/htmx.org@1.9.10"></script>
  <style>
    :root { --bg: #0d1117; --fg: #e6edf3; --border: #30363d;
            --accent: #238636; --err: #f85149; --muted: #8b949e; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--fg); font: 14px/1.5 'Cascadia Code', monospace; padding: 1rem; }
    h1 { font-size: 1.1rem; margin-bottom: 1.5rem; color: var(--accent); }
    h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: .1em;
         color: var(--muted); margin-bottom: .5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 1rem; }
    .card { background: #161b22; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; }
    table.kv { width: 100%; border-collapse: collapse; }
    table.kv th, table.kv td { padding: .25rem .5rem; border-bottom: 1px solid var(--border); text-align: left; }
    table.kv th { color: var(--muted); width: 40%; }
    ul { list-style: none; }
    li { border-bottom: 1px solid var(--border); padding: .4rem 0; }
    li:last-child { border-bottom: none; }
    pre { white-space: pre-wrap; word-break: break-all; font-size: 12px; }
    .err { color: var(--err); }
    .empty { color: var(--muted); font-style: italic; }
    .htmx-indicator { opacity: 0; transition: opacity 200ms; }
    .htmx-request .htmx-indicator { opacity: 1; }
  </style>
</head>
<body>
  <h1>LICHEN &#9675; {{NODE}}</h1>
  <div class="grid">

    <div class="card">
      <h2>Status <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/status" hx-trigger="load, every 10s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

    <div class="card">
      <h2>Neighbors <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/neighbors" hx-trigger="load, every 15s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

    <div class="card">
      <h2>Presence <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/presence" hx-trigger="load, every 15s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

    <div class="card">
      <h2>Messages <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/messages" hx-trigger="load, every 30s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

    <div class="card">
      <h2>Sensors <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/sensors" hx-trigger="load, every 10s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

    <div class="card">
      <h2>Location <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/location" hx-trigger="load, every 15s" hx-indicator="closest .card">
        Loading&#8230;
      </div>
    </div>

  </div>
</body>
</html>
"""


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
    args = parser.parse_args()

    global _node_addr
    _node_addr = f"coap://{args.node}"

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger.info("Dashboard: http://%s:%d  →  CoAP node %s", args.bind, args.port, _node_addr)

    app = create_app()
    uvicorn.run(app, host=args.bind, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
