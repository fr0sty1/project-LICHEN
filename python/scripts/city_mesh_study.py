#!/usr/bin/env python3
"""City-Scale Mesh Simulation: LICHEN in San Francisco

Models 2000 nodes spread across SF with realistic LoRa propagation,
multi-hop routing, and spatial channel reuse.
"""

import json
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from lora_medium import PropagationModel, airtime_us
from lichen.timing.sfn import slot_for, TDMA_SLOT_MS
from lichen.link.channel import hash_32

# San Francisco dimensions (approximate)
SF_WIDTH_KM = 12.0   # East-West
SF_HEIGHT_KM = 12.0  # North-South

# LoRa parameters
LORA_TX_POWER_DBM = 14
LORA_SENSITIVITY_DBM = -137  # SF10 sensitivity
URBAN_PATH_LOSS_EXPONENT = 3.5  # Urban environment with buildings
REFERENCE_LOSS_DB = 40.27  # Free space at 1m, 915MHz

MSG_SIZE = 60
AIRTIME_US = airtime_us(MSG_SIZE)
AIRTIME_S = AIRTIME_US / 1_000_000

NUM_CHANNELS = 64
TDMA_SLOTS = 64

@dataclass
class Node:
    id: int
    x_km: float  # Position in km
    y_km: float
    eui64: bytes
    neighbors: list = field(default_factory=list)
    routing_table: dict = field(default_factory=dict)  # dest_id -> next_hop_id
    last_tx_s: float = -1000
    messages_sent: int = 0
    messages_received: int = 0
    messages_relayed: int = 0

@dataclass
class Message:
    id: int
    src_id: int
    dst_id: int
    created_s: float
    hops: int = 0
    delivered: bool = False
    delivery_time_s: float = 0
    path: list = field(default_factory=list)

def distance_km(n1: Node, n2: Node) -> float:
    return math.sqrt((n1.x_km - n2.x_km)**2 + (n1.y_km - n2.y_km)**2)

def path_loss_db(distance_km: float) -> float:
    """Urban log-distance path loss model."""
    if distance_km <= 0:
        return 0
    distance_m = distance_km * 1000
    if distance_m < 1:
        distance_m = 1
    # Log-distance: PL = PL0 + 10*n*log10(d/d0)
    return REFERENCE_LOSS_DB + 10 * URBAN_PATH_LOSS_EXPONENT * math.log10(distance_m)

def can_communicate(n1: Node, n2: Node) -> bool:
    """Check if two nodes can communicate directly."""
    pl = path_loss_db(distance_km(n1, n2))
    rx_power = LORA_TX_POWER_DBM - pl
    return rx_power >= LORA_SENSITIVITY_DBM

def estimate_range_km() -> float:
    """Estimate max communication range for these parameters."""
    # Solve: TX_POWER - PL(d) = SENSITIVITY
    # PL(d) = PL0 + 10*n*log10(d)
    # TX - PL0 - 10*n*log10(d) = SENS
    # log10(d) = (TX - PL0 - SENS) / (10*n)
    max_loss = LORA_TX_POWER_DBM - LORA_SENSITIVITY_DBM
    log_d_m = (max_loss - REFERENCE_LOSS_DB) / (10 * URBAN_PATH_LOSS_EXPONENT)
    return (10 ** log_d_m) / 1000

def create_city_mesh(num_nodes: int, rng: random.Random) -> list[Node]:
    """Create nodes distributed across SF with neighbor discovery."""
    nodes = []

    for i in range(num_nodes):
        # Random distribution across SF
        # Could add clustering around neighborhoods later
        x = rng.uniform(0, SF_WIDTH_KM)
        y = rng.uniform(0, SF_HEIGHT_KM)
        eui64 = bytes([rng.randint(0, 255) for _ in range(8)])

        nodes.append(Node(
            id=i,
            x_km=x,
            y_km=y,
            eui64=eui64,
        ))

    # Discover neighbors (nodes that can communicate directly)
    for i, n1 in enumerate(nodes):
        for j, n2 in enumerate(nodes):
            if i != j and can_communicate(n1, n2):
                n1.neighbors.append(j)

    return nodes

def build_routing_tables(nodes: list[Node]) -> None:
    """Build simple shortest-path routing tables using BFS."""
    for src in nodes:
        # BFS from this node
        visited = {src.id}
        queue = [(src.id, None)]  # (node_id, first_hop)

        while queue:
            current_id, first_hop = queue.pop(0)
            current = nodes[current_id]

            for neighbor_id in current.neighbors:
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    # First hop is the immediate neighbor we go through
                    hop = first_hop if first_hop is not None else neighbor_id
                    src.routing_table[neighbor_id] = hop
                    queue.append((neighbor_id, hop))

def analyze_topology(nodes: list[Node]) -> dict:
    """Analyze mesh topology statistics."""
    neighbor_counts = [len(n.neighbors) for n in nodes]
    reachability = [len(n.routing_table) for n in nodes]

    # Find connected components
    visited = set()
    components = []

    for start in nodes:
        if start.id in visited:
            continue
        component = set()
        queue = [start.id]
        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            component.add(nid)
            queue.extend(nodes[nid].neighbors)
        components.append(len(component))

    return {
        'num_nodes': len(nodes),
        'avg_neighbors': sum(neighbor_counts) / len(nodes),
        'min_neighbors': min(neighbor_counts),
        'max_neighbors': max(neighbor_counts),
        'isolated_nodes': sum(1 for c in neighbor_counts if c == 0),
        'avg_reachable': sum(reachability) / len(nodes),
        'num_components': len(components),
        'largest_component': max(components) if components else 0,
        'fully_connected': len(components) == 1 and components[0] == len(nodes),
    }

def simulate_traffic(
    nodes: list[Node],
    duration_s: float,
    msg_rate_per_node_per_min: float,
    rng: random.Random,
    use_tdma_fh: bool = True,
) -> dict:
    """Simulate message traffic across the mesh."""

    messages = []
    msg_id = 0
    delivered = 0
    failed = 0
    total_hops = 0
    latencies = []

    # Track channel usage per location for spatial reuse analysis
    channel_usage = defaultdict(int)

    slot_s = TDMA_SLOT_MS / 1000
    min_tx_interval = AIRTIME_S / 0.01  # 1% duty cycle

    time_s = 0
    pending_transmissions = []  # (time, msg, current_node_id)

    while time_s < duration_s or pending_transmissions:
        # Generate new messages
        if time_s < duration_s:
            for node in nodes:
                if rng.random() < (slot_s / 60) * msg_rate_per_node_per_min:
                    # Pick random destination (that's reachable)
                    if node.routing_table:
                        dst_id = rng.choice(list(node.routing_table.keys()))
                        msg = Message(
                            id=msg_id,
                            src_id=node.id,
                            dst_id=dst_id,
                            created_s=time_s,
                            path=[node.id],
                        )
                        messages.append(msg)
                        pending_transmissions.append((time_s, msg, node.id))
                        msg_id += 1
                        node.messages_sent += 1

        # Process transmissions at current time
        current_txs = [(t, m, n) for t, m, n in pending_transmissions if t <= time_s]
        pending_transmissions = [(t, m, n) for t, m, n in pending_transmissions if t > time_s]

        for tx_time, msg, current_id in current_txs:
            if msg.delivered:
                continue

            current_node = nodes[current_id]

            # Check if at destination
            if current_id == msg.dst_id:
                msg.delivered = True
                msg.delivery_time_s = time_s
                delivered += 1
                total_hops += msg.hops
                latencies.append(time_s - msg.created_s)
                nodes[current_id].messages_received += 1
                continue

            # Route to next hop
            if msg.dst_id not in current_node.routing_table:
                failed += 1
                continue

            next_hop = current_node.routing_table[msg.dst_id]

            # Simulate TX with TDMA+FH
            if use_tdma_fh:
                sfn = int(time_s / (TDMA_SLOTS * slot_s))
                my_slot = slot_for(current_node.eui64, sfn, TDMA_SLOTS)
                channel = 1 + hash_32(sfn.to_bytes(4, 'little') + current_node.eui64) % (NUM_CHANNELS - 1)

                # Track spatial channel usage
                grid_x = int(current_node.x_km)
                grid_y = int(current_node.y_km)
                channel_usage[(grid_x, grid_y, channel)] += 1

            # Schedule delivery at next hop (simplified - assume success)
            msg.hops += 1
            msg.path.append(next_hop)
            nodes[current_id].messages_relayed += 1

            # Add propagation delay + processing
            next_time = time_s + slot_s + AIRTIME_S
            pending_transmissions.append((next_time, msg, next_hop))

        time_s += slot_s

        # Timeout check
        if time_s > duration_s + 60:  # 60s timeout for in-flight messages
            break

    # Count failed (undelivered) messages
    for msg in messages:
        if not msg.delivered:
            failed += 1

    return {
        'messages_generated': len(messages),
        'messages_delivered': delivered,
        'messages_failed': failed,
        'delivery_rate': delivered / max(len(messages), 1),
        'avg_hops': total_hops / max(delivered, 1),
        'avg_latency_s': sum(latencies) / max(len(latencies), 1) if latencies else 0,
        'max_latency_s': max(latencies) if latencies else 0,
        'min_latency_s': min(latencies) if latencies else 0,
        'unique_channel_locations': len(channel_usage),
    }

def run_sf_study():
    """Run the San Francisco mesh study."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path(f'results/sf_mesh_{timestamp}')
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("LICHEN City-Scale Mesh: San Francisco")
    print("=" * 70)

    max_range = estimate_range_km()
    print(f"Estimated LoRa range: {max_range:.2f} km")
    print(f"City area: {SF_WIDTH_KM} x {SF_HEIGHT_KM} km")
    print(f"Path loss exponent: {URBAN_PATH_LOSS_EXPONENT} (urban)")
    print()

    # Run multiple scenarios
    scenarios = [
        {'num_nodes': 500, 'duration_s': 300, 'msg_rate': 0.5},
        {'num_nodes': 1000, 'duration_s': 300, 'msg_rate': 0.5},
        {'num_nodes': 2000, 'duration_s': 300, 'msg_rate': 0.5},
        {'num_nodes': 2000, 'duration_s': 300, 'msg_rate': 1.0},
        {'num_nodes': 2000, 'duration_s': 300, 'msg_rate': 2.0},
    ]

    all_results = []

    for i, scenario in enumerate(scenarios):
        num_nodes = scenario['num_nodes']
        duration_s = scenario['duration_s']
        msg_rate = scenario['msg_rate']

        print(f"\n[{i+1}/{len(scenarios)}] {num_nodes} nodes, {msg_rate} msg/node/min, {duration_s}s")
        print("-" * 50)

        # Multiple runs for statistics
        runs = 5
        run_results = []

        for run in range(runs):
            seed = hash(f"sf_{num_nodes}_{msg_rate}_{run}") & 0xFFFFFFFF
            rng = random.Random(seed)

            # Create mesh
            start = time.time()
            nodes = create_city_mesh(num_nodes, rng)
            build_routing_tables(nodes)
            setup_time = time.time() - start

            # Analyze topology
            topo = analyze_topology(nodes)

            # Simulate traffic
            start = time.time()
            traffic = simulate_traffic(nodes, duration_s, msg_rate, rng, use_tdma_fh=True)
            sim_time = time.time() - start

            result = {
                'scenario': scenario,
                'run': run,
                'seed': seed,
                'topology': topo,
                'traffic': traffic,
                'setup_time_s': setup_time,
                'sim_time_s': sim_time,
            }
            run_results.append(result)

            print(f"  Run {run}: delivery={traffic['delivery_rate']:.1%}, "
                  f"avg_hops={traffic['avg_hops']:.1f}, "
                  f"latency={traffic['avg_latency_s']:.1f}s, "
                  f"neighbors={topo['avg_neighbors']:.1f}")

        # Aggregate stats
        avg_delivery = sum(r['traffic']['delivery_rate'] for r in run_results) / runs
        avg_hops = sum(r['traffic']['avg_hops'] for r in run_results) / runs
        avg_latency = sum(r['traffic']['avg_latency_s'] for r in run_results) / runs
        avg_neighbors = sum(r['topology']['avg_neighbors'] for r in run_results) / runs

        print(f"  AVG: delivery={avg_delivery:.1%}, hops={avg_hops:.1f}, "
              f"latency={avg_latency:.1f}s, neighbors={avg_neighbors:.1f}")

        all_results.extend(run_results)

    # Save results
    with open(output_dir / 'results.json', 'w') as f:
        json.dump(all_results, f, indent=2, default=str)

    # Save metadata
    metadata = {
        'timestamp': timestamp,
        'sf_width_km': SF_WIDTH_KM,
        'sf_height_km': SF_HEIGHT_KM,
        'lora_tx_power_dbm': LORA_TX_POWER_DBM,
        'lora_sensitivity_dbm': LORA_SENSITIVITY_DBM,
        'path_loss_exponent': URBAN_PATH_LOSS_EXPONENT,
        'estimated_range_km': max_range,
        'msg_size': MSG_SIZE,
        'airtime_s': AIRTIME_S,
        'num_channels': NUM_CHANNELS,
        'tdma_slots': TDMA_SLOTS,
        'scenarios': scenarios,
    }
    with open(output_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"\n{'='*70}")
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Nodes':>6} {'MsgRate':>8} {'Delivery':>10} {'Hops':>6} {'Latency':>10} {'Neighbors':>10}")
    print("-" * 70)

    for scenario in scenarios:
        matching = [r for r in all_results
                   if r['scenario']['num_nodes'] == scenario['num_nodes']
                   and r['scenario']['msg_rate'] == scenario['msg_rate']]
        if matching:
            n = scenario['num_nodes']
            rate = scenario['msg_rate']
            del_rate = sum(r['traffic']['delivery_rate'] for r in matching) / len(matching)
            hops = sum(r['traffic']['avg_hops'] for r in matching) / len(matching)
            lat = sum(r['traffic']['avg_latency_s'] for r in matching) / len(matching)
            neigh = sum(r['topology']['avg_neighbors'] for r in matching) / len(matching)
            print(f"{n:>6} {rate:>8.1f} {del_rate:>10.1%} {hops:>6.1f} {lat:>9.1f}s {neigh:>10.1f}")

    print(f"\nResults saved to: {output_dir}")
    return output_dir

if __name__ == '__main__':
    run_sf_study()
