#!/usr/bin/env python3
"""MAC Layer Performance Study: ALOHA vs CSMA vs TDMA vs TDMA+FH

Publication-grade simulation comparing MAC protocols at scale.
Outputs JSON data files for analysis and figure generation.
"""

import json
import os
import random
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from lora_medium import Medium, PropagationModel, airtime_us
from lichen.timing.sfn import slot_for, TDMA_SLOT_MS
from lichen.link.channel import hash_32

# Simulation parameters
NODE_COUNTS = [10, 50, 100, 500, 1000, 2000]
RUNS_PER_CONFIG = 10
DURATION_S = 120
AREA_M = 50.0
MSG_SIZE = 60
NUM_CHANNELS = 64
TDMA_SLOTS = 64

# Derived constants
AIRTIME_US = airtime_us(MSG_SIZE)
AIRTIME_S = AIRTIME_US / 1_000_000
MIN_TX_INTERVAL_S = AIRTIME_S / 0.01  # 1% duty cycle

@dataclass
class SimConfig:
    protocol: str
    num_nodes: int
    run_id: int
    seed: int
    duration_s: float = DURATION_S
    area_m: float = AREA_M
    msg_size: int = MSG_SIZE
    num_channels: int = NUM_CHANNELS
    tdma_slots: int = TDMA_SLOTS
    airtime_s: float = AIRTIME_S
    min_tx_interval_s: float = MIN_TX_INTERVAL_S

@dataclass
class TxEvent:
    time_s: float
    node_id: int
    channel: int
    slot: int
    success: bool
    collision_count: int
    rssi_dbm: float = 0.0

@dataclass
class SimResult:
    config: SimConfig
    events: list = field(default_factory=list)
    tx_attempts: int = 0
    tx_success: int = 0
    collisions: int = 0
    unique_collisions: int = 0  # slots with >1 TX
    channel_distribution: dict = field(default_factory=dict)
    slot_distribution: dict = field(default_factory=dict)
    latencies_ms: list = field(default_factory=list)
    wall_time_s: float = 0.0

    @property
    def delivery_rate(self) -> float:
        return self.tx_success / max(self.tx_attempts, 1)

    @property
    def collision_rate(self) -> float:
        return self.collisions / max(self.tx_attempts, 1)

    @property
    def channel_utilization(self) -> float:
        # Fraction of channel capacity used
        capacity = self.config.duration_s / self.config.airtime_s
        return self.tx_attempts / capacity

def create_nodes(num_nodes: int, area: float, rng: random.Random) -> list[dict]:
    nodes = []
    for i in range(num_nodes):
        eui64 = bytes([rng.randint(0, 255) for _ in range(8)])
        nodes.append({
            'id': i,
            'x': rng.uniform(0, area),
            'y': rng.uniform(0, area),
            'z': 1.5,
            'eui64': eui64,
            'last_tx_s': -1000,
            'pending_tx': None,
            'backoff_until_s': 0,
        })
    return nodes

def run_aloha(config: SimConfig, rng: random.Random) -> SimResult:
    """Pure ALOHA: random TX, single channel, no coordination."""
    result = SimResult(config=config)
    nodes = create_nodes(config.num_nodes, config.area_m, rng)

    time_s = 0
    slot_duration_s = config.airtime_s

    while time_s < config.duration_s:
        # Determine who wants to TX this slot
        tx_nodes = []
        for node in nodes:
            if time_s - node['last_tx_s'] >= config.min_tx_interval_s:
                # Poisson-ish: ~1 msg per 2 minutes per node
                if rng.random() < (slot_duration_s / 120):
                    tx_nodes.append(node)

        if tx_nodes:
            result.tx_attempts += len(tx_nodes)

            if len(tx_nodes) == 1:
                result.tx_success += 1
                result.events.append(TxEvent(
                    time_s=time_s, node_id=tx_nodes[0]['id'],
                    channel=0, slot=0, success=True, collision_count=0
                ))
            else:
                # Collision - capture effect: strongest wins
                result.collisions += len(tx_nodes)
                result.unique_collisions += 1
                result.tx_success += 1  # capture winner
                for i, node in enumerate(tx_nodes):
                    result.events.append(TxEvent(
                        time_s=time_s, node_id=node['id'],
                        channel=0, slot=0, success=(i == 0),
                        collision_count=len(tx_nodes)
                    ))

            for node in tx_nodes:
                node['last_tx_s'] = time_s

        time_s += slot_duration_s

    return result

def run_csma(config: SimConfig, rng: random.Random) -> SimResult:
    """CSMA/CA: CAD before TX, exponential backoff, single channel."""
    result = SimResult(config=config)
    nodes = create_nodes(config.num_nodes, config.area_m, rng)

    time_s = 0
    slot_duration_s = config.airtime_s
    cad_duration_s = 0.010  # 10ms CAD

    while time_s < config.duration_s:
        # Nodes that want to TX and aren't backing off
        tx_candidates = []
        for node in nodes:
            if time_s < node['backoff_until_s']:
                continue
            if time_s - node['last_tx_s'] >= config.min_tx_interval_s:
                if rng.random() < (slot_duration_s / 120):
                    tx_candidates.append(node)

        if not tx_candidates:
            time_s += slot_duration_s
            continue

        # CAD phase: all candidates sense
        # If >1 candidate, they all sense busy (simplified)
        if len(tx_candidates) > 1:
            # All back off
            for node in tx_candidates:
                backoff_slots = rng.randint(1, 32)
                node['backoff_until_s'] = time_s + backoff_slots * slot_duration_s
            time_s += cad_duration_s
            continue

        # Single TX succeeds
        node = tx_candidates[0]
        result.tx_attempts += 1
        result.tx_success += 1
        node['last_tx_s'] = time_s
        result.events.append(TxEvent(
            time_s=time_s, node_id=node['id'],
            channel=0, slot=0, success=True, collision_count=0
        ))

        time_s += slot_duration_s

    return result

def run_tdma(config: SimConfig, rng: random.Random) -> SimResult:
    """TDMA: deterministic slots, single channel."""
    result = SimResult(config=config)
    nodes = create_nodes(config.num_nodes, config.area_m, rng)

    # Assign slots
    for node in nodes:
        node['slot'] = slot_for(node['eui64'], 0, config.tdma_slots)

    superframe_s = TDMA_SLOT_MS * config.tdma_slots / 1000
    slot_s = TDMA_SLOT_MS / 1000

    time_s = 0
    while time_s < config.duration_s:
        sfn = int(time_s / superframe_s)
        slot_in_sf = int((time_s % superframe_s) / slot_s)

        # Find nodes whose slot is now
        tx_nodes = []
        for node in nodes:
            if node['slot'] != slot_in_sf:
                continue
            if time_s - node['last_tx_s'] < config.min_tx_interval_s:
                continue
            if rng.random() < 0.5:  # 50% chance to TX in slot
                tx_nodes.append(node)

        if tx_nodes:
            result.tx_attempts += len(tx_nodes)
            result.slot_distribution[slot_in_sf] = result.slot_distribution.get(slot_in_sf, 0) + len(tx_nodes)

            if len(tx_nodes) == 1:
                result.tx_success += 1
                result.events.append(TxEvent(
                    time_s=time_s, node_id=tx_nodes[0]['id'],
                    channel=0, slot=slot_in_sf, success=True, collision_count=0
                ))
            else:
                result.collisions += len(tx_nodes)
                result.unique_collisions += 1
                result.tx_success += 1
                for i, node in enumerate(tx_nodes):
                    result.events.append(TxEvent(
                        time_s=time_s, node_id=node['id'],
                        channel=0, slot=slot_in_sf, success=(i == 0),
                        collision_count=len(tx_nodes)
                    ))

            for node in tx_nodes:
                node['last_tx_s'] = time_s

        time_s += slot_s

    return result

def run_tdma_fh(config: SimConfig, rng: random.Random) -> SimResult:
    """TDMA + Frequency Hopping: deterministic slots + channel hopping."""
    result = SimResult(config=config)
    nodes = create_nodes(config.num_nodes, config.area_m, rng)

    # Assign slots
    for node in nodes:
        node['slot'] = slot_for(node['eui64'], 0, config.tdma_slots)

    superframe_s = TDMA_SLOT_MS * config.tdma_slots / 1000
    slot_s = TDMA_SLOT_MS / 1000

    time_s = 0
    while time_s < config.duration_s:
        sfn = int(time_s / superframe_s)
        slot_in_sf = int((time_s % superframe_s) / slot_s)

        # Find nodes whose slot is now
        tx_nodes = []
        for node in nodes:
            if node['slot'] != slot_in_sf:
                continue
            if time_s - node['last_tx_s'] < config.min_tx_interval_s:
                continue
            if rng.random() < 0.5:
                tx_nodes.append(node)

        if not tx_nodes:
            time_s += slot_s
            continue

        # Group by channel
        by_channel = {}
        for node in tx_nodes:
            ch = 1 + hash_32(sfn.to_bytes(4, 'little') + node['eui64']) % (config.num_channels - 1)
            result.channel_distribution[ch] = result.channel_distribution.get(ch, 0) + 1
            by_channel.setdefault(ch, []).append(node)

        for channel, ch_nodes in by_channel.items():
            result.tx_attempts += len(ch_nodes)
            result.slot_distribution[slot_in_sf] = result.slot_distribution.get(slot_in_sf, 0) + len(ch_nodes)

            if len(ch_nodes) == 1:
                result.tx_success += 1
                result.events.append(TxEvent(
                    time_s=time_s, node_id=ch_nodes[0]['id'],
                    channel=channel, slot=slot_in_sf, success=True, collision_count=0
                ))
            else:
                result.collisions += len(ch_nodes)
                result.unique_collisions += 1
                result.tx_success += 1
                for i, node in enumerate(ch_nodes):
                    result.events.append(TxEvent(
                        time_s=time_s, node_id=node['id'],
                        channel=channel, slot=slot_in_sf, success=(i == 0),
                        collision_count=len(ch_nodes)
                    ))

            for node in ch_nodes:
                node['last_tx_s'] = time_s

        time_s += slot_s

    return result

PROTOCOLS = {
    'aloha': run_aloha,
    'csma': run_csma,
    'tdma': run_tdma,
    'tdma_fh': run_tdma_fh,
}

def run_study():
    """Run the complete MAC study."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path(f'results/mac_study_{timestamp}')
    output_dir.mkdir(parents=True, exist_ok=True)

    # Study metadata
    metadata = {
        'timestamp': timestamp,
        'node_counts': NODE_COUNTS,
        'runs_per_config': RUNS_PER_CONFIG,
        'duration_s': DURATION_S,
        'area_m': AREA_M,
        'msg_size': MSG_SIZE,
        'num_channels': NUM_CHANNELS,
        'tdma_slots': TDMA_SLOTS,
        'airtime_us': AIRTIME_US,
        'airtime_s': AIRTIME_S,
        'min_tx_interval_s': MIN_TX_INTERVAL_S,
        'protocols': list(PROTOCOLS.keys()),
    }

    with open(output_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    all_results = []
    total_configs = len(PROTOCOLS) * len(NODE_COUNTS) * RUNS_PER_CONFIG
    completed = 0

    print(f"MAC Layer Study: {total_configs} configurations")
    print(f"Output: {output_dir}")
    print("=" * 70)

    for protocol_name, protocol_fn in PROTOCOLS.items():
        for num_nodes in NODE_COUNTS:
            for run_id in range(RUNS_PER_CONFIG):
                seed = hash(f"{protocol_name}_{num_nodes}_{run_id}") & 0xFFFFFFFF
                rng = random.Random(seed)

                config = SimConfig(
                    protocol=protocol_name,
                    num_nodes=num_nodes,
                    run_id=run_id,
                    seed=seed,
                )

                start_time = time.time()
                result = protocol_fn(config, rng)
                result.wall_time_s = time.time() - start_time

                # Save individual result
                result_dict = {
                    'config': asdict(config),
                    'tx_attempts': result.tx_attempts,
                    'tx_success': result.tx_success,
                    'collisions': result.collisions,
                    'unique_collisions': result.unique_collisions,
                    'delivery_rate': result.delivery_rate,
                    'collision_rate': result.collision_rate,
                    'channel_utilization': result.channel_utilization,
                    'channel_distribution': result.channel_distribution,
                    'slot_distribution': result.slot_distribution,
                    'wall_time_s': result.wall_time_s,
                    'num_events': len(result.events),
                }
                all_results.append(result_dict)

                # Save events separately (large)
                events_file = output_dir / f'events_{protocol_name}_{num_nodes}_{run_id}.json'
                with open(events_file, 'w') as f:
                    json.dump([asdict(e) for e in result.events], f)

                completed += 1
                print(f"[{completed}/{total_configs}] {protocol_name:8s} n={num_nodes:4d} run={run_id} "
                      f"delivery={result.delivery_rate:.1%} collisions={result.collision_rate:.1%} "
                      f"({result.wall_time_s:.2f}s)")

    # Save summary
    with open(output_dir / 'results.json', 'w') as f:
        json.dump(all_results, f, indent=2)

    # Generate summary table
    print("\n" + "=" * 70)
    print("SUMMARY BY PROTOCOL AND NODE COUNT")
    print("=" * 70)
    print(f"{'Protocol':<10} {'Nodes':>6} {'Delivery':>10} {'Collision':>10} {'Utilization':>12}")
    print("-" * 70)

    for protocol in PROTOCOLS.keys():
        for num_nodes in NODE_COUNTS:
            matching = [r for r in all_results
                       if r['config']['protocol'] == protocol
                       and r['config']['num_nodes'] == num_nodes]
            if matching:
                avg_delivery = sum(r['delivery_rate'] for r in matching) / len(matching)
                avg_collision = sum(r['collision_rate'] for r in matching) / len(matching)
                avg_util = sum(r['channel_utilization'] for r in matching) / len(matching)
                print(f"{protocol:<10} {num_nodes:>6} {avg_delivery:>10.1%} {avg_collision:>10.1%} {avg_util:>12.1%}")

    print(f"\nResults saved to: {output_dir}")
    return output_dir

if __name__ == '__main__':
    run_study()
