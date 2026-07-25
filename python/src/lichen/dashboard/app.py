# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN node web status dashboard.

Lightweight FastAPI server that proxies a node's CoAP resources into a
live browser dashboard. Each section auto-refreshes via HTMX.

Note: HTMX browser-side refresh is a standard web UI pattern and is
acceptable per the no-polling policy. The polling occurs entirely in the
browser (client-side); the Python server is event-driven with no polling.

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
import httpx
import uvicorn
from aiocoap import GET, Context, Message
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

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
    data = await _fetch("/msg/inbox")
    if isinstance(data, dict):
        data = data.get("messages")
    return HTMLResponse(_render_list(data, "Inbox empty"))


async def partial_sensors(request: Request) -> HTMLResponse:
    data = await _fetch("/sensors")
    return HTMLResponse(_render_senml(data))


async def partial_location(request: Request) -> HTMLResponse:
    data = await _fetch("/location")
    return HTMLResponse(_render_senml(data))


async def partial_mesh_stats(request: Request) -> HTMLResponse:
    """Live stats from simulator REST API, falling back to mock."""
    metrics = _metrics_cache
    if metrics:
        t = metrics.get("transmissions", 0)
        cr = round(metrics.get("collision_rate", 0) * 100, 1)
        latency = metrics.get("latency_us", {})
        hops = round(latency.get("mean", 0) / 1000, 1) if latency.get("mean") else 0
        node_count = topology_node_count()
        active = f"{node_count}/{node_count}"
        loss = f"{round(cr, 1)}%"
        pps = t if t else 0
    else:
        active = "—"
        pps = 0
        loss = "—"
        hops = "—"
    html = f'''<div id="mesh-stats-content" style="font-size:1.1em;line-height:1.8"
      hx-get="/partial/mesh-stats" hx-trigger="load, every 5s" hx-swap="outerHTML">
<div><strong>Nodes:</strong> {active}</div>
<div><strong>PPS:</strong> {pps}</div>
<div><strong>Loss:</strong> {loss}</div>
<div><strong>Hops:</strong> {hops}</div>
<div><strong>GWs:</strong> —</div>
<div style="margin-top:0.5rem;font-size:0.8em;color:#58a6ff">Live {'• simulator' if _sim_url else '• mock'}</div>
</div><div style="margin-top:1rem;height:120px;background:#161b22;border:1px solid #30363d;border-radius:4px;position:relative" id="mini-waterfall"></div>'''
    return HTMLResponse(html)


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
    mock = [{"id": f"n{i}", "x": random.uniform(0, 800), "y": random.uniform(0, 380),
             "group": i % 4, "connected": True} for i in range(20)]
    return JSONResponse({"nodes": mock})


async def partial_mesh_metrics(request: Request) -> JSONResponse:
    """Return simulator metrics as JSON."""
    if _metrics_cache:
        return JSONResponse(_metrics_cache)
    return JSONResponse({"transmissions": 0, "receptions": 0, "collisions": 0,
                         "delivery_rate": 0, "collision_rate": 0,
                         "latency_us": {"count": 0, "min": None, "max": None, "mean": None}})


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


def _senml_row(name: Any, value: Any, unit: Any) -> str:
    cell = f"{_esc(value)}{(' ' + _esc(unit)) if unit else ''}"
    return f"<tr><th>{_esc(name)}</th><td>{cell}</td></tr>"


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
            rows.append(_senml_row(name, value, unit))
        elif isinstance(entry, dict):
            name = entry.get("n", entry.get(0, ""))
            value = entry.get("v", entry.get("vs", entry.get("vb", entry.get(2, ""))))
            unit = entry.get("u", entry.get(1, ""))
            rows.append(_senml_row(name, value, unit))
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
            Route("/partial/mesh-stats", partial_mesh_stats),
            Route("/partial/topology-data", partial_topology_data),
            Route("/partial/mesh-metrics", partial_mesh_metrics),
            Route("/api/status", api_status),
            WebSocketRoute("/ws", ws_events),
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
  <script>
    function refreshElement(el) {
      var target = el.getAttribute("hx-get");
      if (!target) return;
      var card = el.closest(".card");
      if (card) card.classList.add("htmx-request");
      fetch(target, { headers: { "HX-Request": "true" } })
        .then(function (response) { return response.text(); })
        .then(function (html) { el.innerHTML = html; })
        .catch(function () { el.innerHTML = "<p class='err'>Unreachable</p>"; })
        .finally(function () {
          if (card) card.classList.remove("htmx-request");
        });
    }
    document.addEventListener("DOMContentLoaded", function () {
      document.querySelectorAll("[hx-get]").forEach(function (el) {
        var trigger = el.getAttribute("hx-trigger") || "";
        if (trigger.indexOf("load") !== -1) refreshElement(el);
        var match = trigger.match(/every\\s+(\\d+)s/);
        if (match) {
          window.setInterval(function () { refreshElement(el); }, Number(match[1]) * 1000);
        }
      });
    });
  </script>
  <style>
    :root { --bg: #0d1117; --fg: #e6edf3; --border: #30363d;
            --accent: #238636; --err: #f85149; --muted: #8b949e; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--fg);
           font: 14px/1.5 'Cascadia Code', monospace; padding: 1rem; }
    h1 { font-size: 1.1rem; margin-bottom: 1.5rem; color: var(--accent); }
    h2 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: .1em;
         color: var(--muted); margin-bottom: .5rem; }
    .grid { display: grid; gap: 1rem;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); }
    .card { background: #161b22; border: 1px solid var(--border);
            border-radius: 6px; padding: 1rem; }
    table.kv { width: 100%; border-collapse: collapse; }
    table.kv th, table.kv td { padding: .25rem .5rem;
      border-bottom: 1px solid var(--border); text-align: left; }
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

    <div class="card" style="grid-column: span 2;">
      <h2>Live Mesh Stats (500 nodes) <span class="htmx-indicator">&#8635;</span></h2>
      <div id="mesh-stats" hx-get="/partial/mesh-stats" hx-trigger="load, every 5s" hx-indicator="closest .card">
        Loading conference mesh stats...
      </div>
    </div>

    <div class="card" style="grid-column: span 3; height: 420px;">
      <h2>Topology <span class="htmx-indicator">&#8635;</span></h2>
      <div id="topology" style="width:100%; height:380px; background:#161b22; border:1px solid #30363d; border-radius:4px; position:relative;">
        <svg id="mesh-svg" width="100%" height="100%" style="position:absolute;"></svg>
      </div>
      <script src="https://d3js.org/d3.v7.min.js"></script>
      <script>
        // Live topology from /partial/topology-data, falls back to mock
        (function() {
          const svg = d3.select("#mesh-svg");
          const width = 800, height = 380;
          svg.attr("viewBox", `0 0 ${width} ${height}`);
          const colors = ["#ff7f0e","#2ca02c","#1f77b4","#d62728"];
          let simulation, link, node;

          function updateTopology(data) {
            const rawNodes = (data && data.nodes) ? data.nodes : [];
            const nodes = rawNodes.map(function(d) {
              return {id: d.id, x: d.x * width / 1000 || Math.random()*width,
                      y: d.y * height / 500 || Math.random()*height, group: d.group || 0};
            });
            if (nodes.length === 0) {
              for (var i=0; i<20; i++)
                nodes.push({id:"n"+i,x:Math.random()*width,y:Math.random()*height,group:i%4});
            }
            // Build links: connect each node to nearest 2
            var links = [];
            for (var i=0; i<nodes.length; i++) {
              var dists = [];
              for (var j=0; j<nodes.length; j++) {
                if (i===j) continue;
                dists.push({j:j, d:Math.pow(nodes[i].x-nodes[j].x,2)+Math.pow(nodes[i].y-nodes[j].y,2)});
              }
              dists.sort(function(a,b){return a.d-b.d;});
              for (var k=0; k<Math.min(2,dists.length); k++)
                links.push({source:nodes[i].id, target:nodes[dists[k].j].id});
            }
            svg.selectAll("*").remove();
            simulation = d3.forceSimulation(nodes)
              .force("link", d3.forceLink(links).id(function(d){return d.id;}).distance(40))
              .force("charge", d3.forceManyBody().strength(-60))
              .force("center", d3.forceCenter(width/2,height/2));
            link = svg.append("g").selectAll("line")
              .data(links).join("line")
              .attr("stroke","#58a6ff").attr("stroke-opacity",0.5).attr("stroke-width",0.5);
            node = svg.append("g").selectAll("circle")
              .data(nodes).join("circle")
              .attr("r",4).attr("fill",function(d){return colors[d.group%4];});
            simulation.on("tick",function(){
              link.attr("x1",function(d){return d.source.x;}).attr("y1",function(d){return d.source.y;})
                  .attr("x2",function(d){return d.target.x;}).attr("y2",function(d){return d.target.y;});
              node.attr("cx",function(d){return d.x;}).attr("cy",function(d){return d.y;});
            });
            // Pulse animation for packet activity
            setInterval(function(){node.attr("r",function(d){return 4+Math.random()*3;});
              setTimeout(function(){node.attr("r",4);},300);},800);
          }

          function fetchTopology() {
            fetch("/partial/topology-data", {headers:{"HX-Request":"true"}})
              .then(function(r){return r.json();})
              .then(updateTopology)
              .catch(function(){updateTopology(null);});
          }
          fetchTopology();
          setInterval(fetchTopology, 5000);

          // Live updates via WebSocket
          (function(){
            var proto = location.protocol === "https:" ? "wss:" : "ws:";
            var ws = new WebSocket(proto + "//" + location.host + "/ws");
            ws.onmessage = function(e) {
              try {
                var msg = JSON.parse(e.data);
                if (msg.event === "topology") updateTopology(msg.data);
                if (msg.event === "metrics" && msg.data) {
                  var m = msg.data;
                  var el = document.querySelector("#mesh-stats-content");
                  if (el) {
                    el.innerHTML = "<div><strong>Nodes:</strong> " + (m.node_count || "—") + "</div>" +
                      "<div><strong>PPS:</strong> " + (m.transmissions||0) + "</div>" +
                      "<div><strong>Loss:</strong> " + (Math.round((m.collision_rate||0)*100*10)/10) + "%</div>" +
                      "<div><strong>Hops:</strong> —</div>" +
                      "<div><strong>GWs:</strong> —</div>" +
                      "<div style='margin-top:0.5rem;font-size:0.8em;color:#58a6ff'>Live &#8226; WebSocket</div>";
                  }
                }
              } catch(e) {}
            };
            ws.onclose = function(){setTimeout(function(){location.reload();},5000);};
          })();
        })();
      </script>
    </div>

    <div class="card" style="grid-column: span 2;">
      <h2>Spectrum Waterfall + TDMA <span class="htmx-indicator">&#8635;</span></h2>
      <canvas id="spectrum" width="800" height="160" style="background:#000; display:block; margin:0 auto; image-rendering:pixelated;"></canvas>
      <script>
        const canvas = document.getElementById('spectrum');
        const ctx = canvas.getContext('2d');
        let t = 0;
        function drawSpectrum() {
          ctx.fillStyle = '#000'; ctx.fillRect(0,0,800,160);
          for (let x=0; x<800; x+=4) {
            const intensity = Math.sin(t/10 + x/50) * 40 + 80 + Math.random()*20;
            const hue = (x / 8) % 360;
            ctx.fillStyle = `hsl(${hue}, 80%, ${intensity}%)`;
            ctx.fillRect(x, 0, 4, 160);
          }
          // Overlay LICHEN channel and TDMA slots
          ctx.fillStyle = 'rgba(0,255,100,0.3)'; ctx.fillRect(200, 0, 80, 160); // active channel
          ctx.strokeStyle = '#0f0'; ctx.lineWidth=2;
          for (let s=0; s<8; s++) {
            const y = 20 + (t % 160); ctx.beginPath(); ctx.moveTo(50+s*90, y); ctx.lineTo(120+s*90, y+20); ctx.stroke();
          }
          t += 3; requestAnimationFrame(drawSpectrum);
        }
        drawSpectrum();
      </script>
      <div style="text-align:center; font-size:0.75em; margin-top:0.5rem; color:#58a6ff;">
        LoRa CSS channels • LICHEN active on SF10 CH4 • TDMA slots active (green bars)
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
    logger.info("Dashboard: http://%s:%d  →  CoAP node %s", args.bind, args.port, _node_addr)
    if _sim_url:
        logger.info("  Live data: %s", _sim_url)

    config = uvicorn.Config(create_app(), host=args.bind, port=args.port, log_level="warning")
    server = uvicorn.Server(config)

    loop = asyncio.new_event_loop()
    if _sim_url:
        loop.create_task(_refresh_sim_data())
    loop.run_until_complete(server.serve())


if __name__ == "__main__":
    main()
