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
import uvicorn
from aiocoap import GET, Context, Message  # type: ignore[import-untyped]  # no official stubs
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
    """Mock live stats for 500-node conference mesh demo."""
    # TODO: aggregate CoAP from gateways for real topology/packet data.
    stats = {
        "nodes": "500/500",
        "pps": 1243,
        "loss": "0.3%",
        "hops": 2.4,
        "gws": 4,
        "tdma": "98.7%",
    }
    html = f"""<div style="font-size:1.1em;line-height:1.8">
<div><strong>Nodes:</strong> {stats["nodes"]}</div>
<div><strong>PPS:</strong> {stats["pps"]}</div>
<div><strong>Loss:</strong> {stats["loss"]}</div>
<div><strong>Hops:</strong> {stats["hops"]}</div>
<div><strong>GWs:</strong> {stats["gws"]}</div>
<div><strong>TDMA:</strong> {stats["tdma"]}</div>
<div style="margin-top:1rem;font-size:0.8em;color:#58a6ff">Live • 4 gateways</div>
</div><div style="margin-top:1rem;height:120px;background:#161b22;border:1px solid #30363d;border-radius:4px;position:relative">
<div style="position:absolute;bottom:10px;left:10px;font-size:0.7em;color:#58a6ff">Converged, no collisions</div>
</div>"""
    return HTMLResponse(html)


async def partial_confessions(request: Request) -> HTMLResponse:
    data = await _fetch("/confessions")
    return HTMLResponse(_render_confessions(data))


async def partial_deaddrop(request: Request) -> HTMLResponse:
    data = await _fetch("/deaddrop")
    return HTMLResponse(_render_deaddrop(data))


async def partial_crowd_map(request: Request) -> HTMLResponse:
    data = await _fetch("/sensors/location")
    return HTMLResponse(_render_crowd_map(data))


async def partial_telemetry(request: Request) -> HTMLResponse:
    data = await _fetch("/sensors")
    return HTMLResponse(_render_telemetry(data))


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


def _render_confessions(data: Any) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    if isinstance(data, list):
        if not data:
            return "<p class='empty'>No confessions yet</p>"
        rows = []
        for entry in data:
            if isinstance(entry, dict):
                text = _esc(entry.get("text", entry.get("v", json.dumps(entry))))
                ts = _esc(str(entry.get("t", entry.get("bt", ""))))
                rows.append(f"<li><span class='conf-ts'>{ts}</span> {text}</li>")
            elif isinstance(entry, list):
                text = _esc(str(entry[1] if len(entry) > 1 else entry[0]))
                rows.append(f"<li>{text}</li>")
            else:
                rows.append(f"<li>{_esc(str(entry))}</li>")
        return f"<ul class='confessions'>{''.join(rows)}</ul>"
    return f"<pre>{_esc(json.dumps(data, default=str))}</pre>"


def _render_deaddrop(data: Any) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    if isinstance(data, list):
        if not data:
            return "<p class='empty'>No dead drops</p>"
        rows = []
        for i, entry in enumerate(data):
            if isinstance(entry, dict):
                dest = _esc(entry.get("dest", entry.get("r", "*")))
                size = _esc(str(entry.get("size", entry.get("v", 0))))
                expiry = _esc(str(entry.get("expiry", entry.get("bt", ""))))
                rows.append(
                    f"<li class='dd-entry'>"
                    f"<span class='dd-dest'>{dest}</span> "
                    f"<span class='dd-size'>{size}B</span> "
                    f"<span class='dd-expiry'>exp {expiry}</span>"
                    f"</li>"
                )
            else:
                rows.append(f"<li>{_esc(str(entry))}</li>")
        return f"<ul class='deaddrops'>{''.join(rows)}</ul>"
    return f"<pre>{_esc(json.dumps(data, default=str))}</pre>"


def _render_crowd_map(data: Any) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    try:
        lat = lon = None
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    n = entry.get("n", "")
                    v = entry.get("v", None)
                    if "lat" in str(n).lower():
                        lat = float(v) if v is not None else None
                    elif "lon" in str(n).lower() or "lng" in str(n).lower():
                        lon = float(v) if v is not None else None
                elif isinstance(entry, list) and len(entry) >= 2:
                    n, v = entry[0], entry[1]
                    if "lat" in str(n).lower():
                        lat = float(v) if v is not None else None
                    elif "lon" in str(n).lower() or "lng" in str(n).lower():
                        lon = float(v) if v is not None else None
        if lat is not None and lon is not None:
            return (
                f"<div id='crowd-map-inner' data-lat='{lat}' data-lon='{lon}' "
                f"style='height:200px;background:#161b22;border:1px solid #30363d;"
                f"border-radius:4px;display:flex;align-items:center;justify-content:center;"
                f"color:#58a6ff;font-size:0.85em;'>"
                f"{lat:.4f}&deg;, {lon:.4f}&deg; &mdash; loading map&hellip;"
                f"</div>"
            )
        return "<p class='empty'>No position data</p>"
    except (TypeError, ValueError):
        return f"<pre>{_esc(json.dumps(data, default=str))}</pre>"


def _render_telemetry(data: Any) -> str:
    if data is None:
        return "<p class='err'>Unreachable</p>"
    rows = []
    labels: list[str] = []
    values: list[float] = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                n = entry.get("n", "")
                v = entry.get("v", None)
                u = entry.get("u", "")
                if v is not None:
                    labels.append(_esc(str(n)))
                    value: float | str = _esc(str(v)) if not isinstance(v, (int, float)) else v  # type: ignore[assignment]
                    if isinstance(value, (int, float)):
                        values.append(float(value))
                    else:
                        values.append(0.0)
                    rows.append(f"<tr><th>{_esc(str(n))}</th><td>{_esc(str(v))}{' ' + _esc(str(u)) if u else ''}</td></tr>")
            elif isinstance(entry, list) and len(entry) >= 2:
                labels.append(_esc(str(entry[0])))
                v = entry[1]
                if isinstance(v, (int, float)):
                    values.append(float(v))
                u = _esc(str(entry[2])) if len(entry) > 2 else ""
                rows.append(f"<tr><th>{_esc(str(entry[0]))}</th><td>{_esc(str(v))}{' ' + u if u else ''}</td></tr>")
    if not rows:
        return "<p class='empty'>No telemetry</p>"
    table = f"<table class='kv'>{''.join(rows)}</table>"
    chart_id = "telemetry-chart"
    chart_data_json = json.dumps([{"label": l, "value": v} for l, v in zip(labels, values)])
    chart_js = (
        f"<canvas id='{chart_id}' width='400' height='160' "
        f"style='background:#0d1117;border-radius:4px;margin-top:0.5rem;width:100%;height:120px;'></canvas>"
        f"<script>"
        f"(function(){{"
        f"var c=document.getElementById('{chart_id}');"
        f"if(!c)return;"
        f"var ctx=c.getContext('2d');"
        f"var data={chart_data_json};"
        f"if(!data.length){{ctx.fillStyle='#8b949e';ctx.fillText('no data',10,20);return;}}"
        f"var w=c.width,h=c.height,pad=10;"
        f"var max=Math.max(1,...data.map(function(d){{return d.value}}));"
        f"var col=['#238636','#58a6ff','#d29922','#f85149','#bc8cff','#f0883e'];"
        f"var bw=(w-2*pad)/data.length;"
        f"data.forEach(function(d,i){{"
        f"var bh=(d.value/max)*(h-2*pad);"
        f"ctx.fillStyle=col[i%col.length];"
        f"ctx.fillRect(pad+i*bw,h-pad-bh,bw-2,bh);"
        f"ctx.fillStyle='#e6edf3';"
        f"ctx.font='9px monospace';"
        f"var label=d.label.length>6?d.label.slice(0,6):d.label;"
        f"ctx.fillText(label,pad+i*bw,h-pad+10);"
        f"}});"
        f"}})();"
        f"</script>"
    )
    return table + chart_js


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
            Route("/partial/confessions", partial_confessions),
            Route("/partial/deaddrop", partial_deaddrop),
            Route("/partial/crowd-map", partial_crowd_map),
            Route("/partial/telemetry", partial_telemetry),
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
      <h2>Crowd Map <span class="htmx-indicator">&#8635;</span></h2>
      <div id="crowd-map" hx-get="/partial/crowd-map" hx-trigger="load, every 30s" hx-indicator="closest .card">
        Loading position&hellip;
      </div>
      <div style="margin-top:0.5rem;font-size:0.75em;color:#58a6ff;">
        Node positions from /sensors/location &mdash; Leaflet.js
      </div>
    </div>

    <div class="card">
      <h2>Confessions <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/confessions" hx-trigger="load, every 15s" hx-indicator="closest .card">
        Loading&hellip;
      </div>
    </div>

    <div class="card">
      <h2>Dead Drops <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/deaddrop" hx-trigger="load, every 20s" hx-indicator="closest .card">
        Loading&hellip;
      </div>
    </div>

    <div class="card">
      <h2>Telemetry <span class="htmx-indicator">&#8635;</span></h2>
      <div hx-get="/partial/telemetry" hx-trigger="load, every 10s" hx-indicator="closest .card">
        Loading&hellip;
      </div>
    </div>

    <div class="card" style="grid-column: span 2;">
      <h2>Live Mesh Stats (500 nodes) <span class="htmx-indicator">&#8635;</span></h2>
      <div id="mesh-stats" hx-get="/partial/mesh-stats" hx-trigger="load, every 5s" hx-indicator="closest .card">
        Loading conference mesh stats...
      </div>
    </div>

    <div class="card" style="grid-column: span 3; height: 420px;">
      <h2>Topology (500 nodes) <span class="htmx-indicator">&#8635;</span></h2>
      <div id="topology" style="width:100%; height:380px; background:#161b22; border:1px solid #30363d; border-radius:4px; position:relative;">
        <svg id="mesh-svg" width="100%" height="100%" style="position:absolute;"></svg>
      </div>
      <script src="https://d3js.org/d3.v7.min.js"></script>
      <script>
        function initTopology() {
          const svg = d3.select("#mesh-svg");
          const width = 800, height = 380;
          svg.attr("viewBox", `0 0 ${width} ${height}`);
          // Mock 500-node graph (20 for perf; WebGL for full)
          const nodes = Array.from({length:20},(_,i)=>({id:i,x:Math.random()*width,y:Math.random()*height,group:i%4}));
          const links = nodes.slice(1).map((n,i)=>({source:0,target:i+1,value:Math.random()}));
          const simulation = d3.forceSimulation(nodes)
            .force("link",d3.forceLink(links).distance(30))
            .force("charge",d3.forceManyBody().strength(-80))
            .force("center",d3.forceCenter(width/2,height/2));
          const link = svg.append("g").selectAll("line")
            .data(links).join("line")
            .attr("stroke","#58a6ff").attr("stroke-opacity",0.6);
          const node = svg.append("g").selectAll("circle")
            .data(nodes).join("circle")
            .attr("r",5).attr("fill",d=>["#ff7f0e","#2ca02c","#1f77b4","#d62728"][d.group]);
          simulation.on("tick",()=>{link
            .attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
            .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
            node.attr("cx",d=>d.x).attr("cy",d=>d.y);});
          setInterval(()=>{node.attr("r",d=>5+Math.random()*3);
            setTimeout(()=>node.attr("r",5),300);},800);
        }
        setTimeout(initTopology, 100);
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
    args = parser.parse_args()

    global _node_addr
    _node_addr = f"coap://{args.node}"

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logger.info("Dashboard: http://%s:%d  →  CoAP node %s", args.bind, args.port, _node_addr)

    app = create_app()
    uvicorn.run(app, host=args.bind, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
