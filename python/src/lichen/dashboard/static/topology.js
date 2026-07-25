// Live topology visualization using D3.js
(function() {
  const svg = d3.select("#mesh-svg");
  const width = 800, height = 380;
  svg.attr("viewBox", `0 0 ${width} ${height}`);
  const colors = ["#ff7f0e", "#2ca02c", "#1f77b4", "#d62728"];
  let simulation, link, node;

  function updateTopology(data) {
    const rawNodes = (data && data.nodes) ? data.nodes : [];
    const nodes = rawNodes.map(function(d) {
      return {
        id: d.id,
        x: d.x * width / 1000 || Math.random() * width,
        y: d.y * height / 500 || Math.random() * height,
        group: d.group || 0
      };
    });

    if (nodes.length === 0) {
      for (var i = 0; i < 20; i++) {
        nodes.push({
          id: "n" + i,
          x: Math.random() * width,
          y: Math.random() * height,
          group: i % 4
        });
      }
    }

    // Build links: connect each node to nearest 2
    var links = [];
    for (var i = 0; i < nodes.length; i++) {
      var dists = [];
      for (var j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        var dx = nodes[i].x - nodes[j].x;
        var dy = nodes[i].y - nodes[j].y;
        dists.push({ j: j, d: dx * dx + dy * dy });
      }
      dists.sort(function(a, b) { return a.d - b.d; });
      for (var k = 0; k < Math.min(2, dists.length); k++) {
        links.push({ source: nodes[i].id, target: nodes[dists[k].j].id });
      }
    }

    svg.selectAll("*").remove();

    simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(function(d) { return d.id; }).distance(40))
      .force("charge", d3.forceManyBody().strength(-60))
      .force("center", d3.forceCenter(width / 2, height / 2));

    link = svg.append("g").selectAll("line")
      .data(links).join("line")
      .attr("stroke", "#58a6ff")
      .attr("stroke-opacity", 0.5)
      .attr("stroke-width", 0.5);

    node = svg.append("g").selectAll("circle")
      .data(nodes).join("circle")
      .attr("r", 4)
      .attr("fill", function(d) { return colors[d.group % 4]; });

    simulation.on("tick", function() {
      link
        .attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });
      node
        .attr("cx", function(d) { return d.x; })
        .attr("cy", function(d) { return d.y; });
    });

    // Pulse animation for packet activity
    setInterval(function() {
      node.attr("r", function(d) { return 4 + Math.random() * 3; });
      setTimeout(function() { node.attr("r", 4); }, 300);
    }, 800);
  }

  function fetchTopology() {
    fetch("/partial/topology-data", { headers: { "HX-Request": "true" } })
      .then(function(r) { return r.json(); })
      .then(updateTopology)
      .catch(function() { updateTopology(null); });
  }

  fetchTopology();
  setInterval(fetchTopology, 5000);

  // Live updates via WebSocket
  (function() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var ws = new WebSocket(proto + "//" + location.host + "/ws");

    ws.onmessage = function(e) {
      try {
        var msg = JSON.parse(e.data);
        if (msg.event === "topology") {
          updateTopology(msg.data);
        }
        if (msg.event === "metrics" && msg.data) {
          var m = msg.data;
          var el = document.querySelector("#mesh-stats-content");
          if (el) {
            el.innerHTML =
              "<div><strong>Nodes:</strong> " + (m.node_count || "-") + "</div>" +
              "<div><strong>PPS:</strong> " + (m.transmissions || 0) + "</div>" +
              "<div><strong>Loss:</strong> " + (Math.round((m.collision_rate || 0) * 1000) / 10) + "%</div>" +
              "<div><strong>Hops:</strong> -</div>" +
              "<div><strong>GWs:</strong> -</div>" +
              "<div style='margin-top:0.5rem;font-size:0.8em;color:#58a6ff'>Live - WebSocket</div>";
          }
        }
      } catch (e) {}
    };

    ws.onclose = function() {
      setTimeout(function() { location.reload(); }, 5000);
    };
  })();
})();
