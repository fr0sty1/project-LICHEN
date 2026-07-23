#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Analyze telemetry from heterogeneous LICHEN mesh tests.

Parses logs from Python, Rust, and Zephyr implementations to find
interop issues by cross-referencing packet hashes.

Usage:
    python scripts/analyze-hetero-fleet.py <logs_dir> -o report.md
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PacketEvent:
    """A single TX or RX event."""

    node_id: str
    impl: str  # 'py', 'rust', 'zephyr'
    direction: str  # 'TX' or 'RX'
    hash: str
    timestamp: str | None = None


@dataclass
class NodeStats:
    """Statistics for a single node."""

    node_id: str
    impl: str
    tx_hashes: set[str] = field(default_factory=set)
    rx_hashes: set[str] = field(default_factory=set)
    tx_count: int = 0
    rx_count: int = 0


def parse_telemetry(content: str, stats: NodeStats) -> bool:
    """Parse common JSONL events; return whether any valid event was found."""
    found = False
    for line in content.splitlines():
        marker = line.find("TELEMETRY ")
        if marker < 0:
            continue
        try:
            event = json.loads(line[marker + len("TELEMETRY "):])
        except json.JSONDecodeError:
            continue
        if event.get("schema") != "lichen.telemetry.v1":
            continue
        direction = event.get("direction")
        packet_hash = event.get("packet_hash")
        if direction not in {"tx", "rx"} or not isinstance(packet_hash, str):
            continue
        found = True
        if direction == "tx":
            stats.tx_count += 1
            stats.tx_hashes.add(packet_hash.lower())
        else:
            stats.rx_count += 1
            stats.rx_hashes.add(packet_hash.lower())
    return found


def parse_python_logs(log_dir: Path) -> dict[str, NodeStats]:
    """Parse py-*.log files, extract TX/RX with hashes."""
    nodes: dict[str, NodeStats] = {}

    for log_file in sorted(log_dir.glob("py-*.log")):
        node_id = log_file.stem  # e.g., "py-1000"
        stats = NodeStats(node_id=node_id, impl="py")

        try:
            content = log_file.read_text(errors="replace")
        except OSError as e:
            print(f"Warning: skipping {log_file}: {e}", file=sys.stderr)
            continue

        if parse_telemetry(content, stats):
            if stats.tx_count > 0 or stats.rx_count > 0:
                nodes[node_id] = stats
            continue

        # Look for [TX] or [RX] with hash=
        # Pattern: [TX] ... hash=abc123 or similar
        for line in content.splitlines():
            if "[TX]" in line or "TX:" in line.upper():
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.tx_hashes.add(match.group(1).lower())
                stats.tx_count += 1
            elif "[RX]" in line or "RX:" in line.upper():
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.rx_hashes.add(match.group(1).lower())
                stats.rx_count += 1

        # Also look for summary line: "py-1000: TX=5 RX=3"
        for line in content.splitlines():
            summary = re.search(r"TX=(\d+)\s+RX=(\d+)", line)
            if summary:
                stats.tx_count = max(stats.tx_count, int(summary.group(1)))
                stats.rx_count = max(stats.rx_count, int(summary.group(2)))

        if stats.tx_count > 0 or stats.rx_count > 0 or stats.tx_hashes or stats.rx_hashes:
            nodes[node_id] = stats

    return nodes


def parse_rust_logs(log_dir: Path) -> dict[str, NodeStats]:
    """Parse rust-*.log files, extract TX/RX with hashes."""
    nodes: dict[str, NodeStats] = {}

    for log_file in sorted(log_dir.glob("rust-*.log")):
        node_id = log_file.stem  # e.g., "rust-2000"
        stats = NodeStats(node_id=node_id, impl="rust")

        try:
            content = log_file.read_text(errors="replace")
        except OSError as e:
            print(f"Warning: skipping {log_file}: {e}", file=sys.stderr)
            continue

        if parse_telemetry(content, stats):
            if stats.tx_count > 0 or stats.rx_count > 0:
                nodes[node_id] = stats
            continue

        for line in content.splitlines():
            if "[TX]" in line or "TX:" in line.upper():
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.tx_hashes.add(match.group(1).lower())
                stats.tx_count += 1
            elif "[RX]" in line or "RX:" in line.upper():
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.rx_hashes.add(match.group(1).lower())
                stats.rx_count += 1

        # Summary line
        for line in content.splitlines():
            summary = re.search(r"TX=(\d+)\s+RX=(\d+)", line)
            if summary:
                stats.tx_count = max(stats.tx_count, int(summary.group(1)))
                stats.rx_count = max(stats.rx_count, int(summary.group(2)))

        if stats.tx_count > 0 or stats.rx_count > 0 or stats.tx_hashes or stats.rx_hashes:
            nodes[node_id] = stats

    return nodes


def parse_zephyr_logs(log_dir: Path) -> dict[str, NodeStats]:
    """Parse zephyr-*.log files, extract TX/RX with hashes."""
    nodes: dict[str, NodeStats] = {}

    for log_file in sorted(log_dir.glob("zephyr-*.log")):
        node_id = log_file.stem  # e.g., "zephyr-3000"
        stats = NodeStats(node_id=node_id, impl="zephyr")

        try:
            content = log_file.read_text(errors="replace")
        except OSError as e:
            print(f"Warning: skipping {log_file}: {e}", file=sys.stderr)
            continue

        if parse_telemetry(content, stats):
            if stats.tx_count > 0 or stats.rx_count > 0:
                nodes[node_id] = stats
            continue

        for line in content.splitlines():
            # Zephyr may use TX/Send, RX/Recv
            if "[TX]" in line or "TX:" in line.upper() or "Send" in line:
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.tx_hashes.add(match.group(1).lower())
                stats.tx_count += 1
            elif "[RX]" in line or "RX:" in line.upper() or "Recv" in line:
                match = re.search(r"hash[=:]\s*([a-fA-F0-9]{8,})", line)
                if match:
                    stats.rx_hashes.add(match.group(1).lower())
                stats.rx_count += 1

        if stats.tx_count > 0 or stats.rx_count > 0 or stats.tx_hashes or stats.rx_hashes:
            nodes[node_id] = stats

    return nodes


def find_missing_packets(
    all_nodes: dict[str, NodeStats],
) -> list[tuple[str, str, str]]:
    """Find packets sent but never received by any node.

    Supports multiple senders per hash (origin + forwarders) to preserve
    forwarding information instead of first-wins policy. Fixes skewed
    statistics and missing-packet detection for forwarded drops.
    Returns list of (hash, sender_node_id, sender_impl).
    """
    sent_by_hash: dict[str, set[tuple[str, str]]] = defaultdict(set)
    received_hashes: set[str] = set()

    for node_id, stats in all_nodes.items():
        for h in stats.tx_hashes:
            sent_by_hash[h].add((node_id, stats.impl))
        received_hashes.update(stats.rx_hashes)

    missing = []
    for h, senders in sent_by_hash.items():
        if h not in received_hashes:
            for node_id, impl in sorted(senders):
                missing.append((h, node_id, impl))

    return sorted(missing, key=lambda x: (x[2], x[1], x[0]))


def build_reception_matrix(
    all_nodes: dict[str, NodeStats],
) -> dict[str, dict[str, int]]:
    """Build matrix showing packet reception between implementation pairs.

    Returns dict[sender_impl][receiver_impl] = count.

    For this to work accurately, we need hash overlap data. Without
    per-packet sender tracking, we estimate based on overall reception.
    """
    # Group nodes by implementation
    impls = ["py", "rust", "zephyr"]
    impl_nodes: dict[str, list[NodeStats]] = {impl: [] for impl in impls}

    for stats in all_nodes.values():
        impl_nodes[stats.impl].append(stats)

    # Build hash -> sender impl mapping
    hash_to_sender: dict[str, str] = {}
    for stats in all_nodes.values():
        for h in stats.tx_hashes:
            if h not in hash_to_sender:
                hash_to_sender[h] = stats.impl

    # Count reception by sender impl -> receiver impl
    matrix: dict[str, dict[str, int]] = {
        impl: {impl2: 0 for impl2 in impls} for impl in impls
    }

    for stats in all_nodes.values():
        receiver_impl = stats.impl
        for h in stats.rx_hashes:
            sender_impl = hash_to_sender.get(h)
            if sender_impl:
                matrix[sender_impl][receiver_impl] += 1

    return matrix


def generate_report(logs_dir: Path, output: Path) -> None:
    """Generate markdown report with analysis results."""
    # Parse all logs
    py_nodes = parse_python_logs(logs_dir)
    rust_nodes = parse_rust_logs(logs_dir)
    zephyr_nodes = parse_zephyr_logs(logs_dir)

    all_nodes = {**py_nodes, **rust_nodes, **zephyr_nodes}

    # Calculate stats per implementation
    impl_stats: dict[str, dict[str, int]] = {
        "py": {"nodes": 0, "tx": 0, "rx": 0, "tx_hashes": 0, "rx_hashes": 0},
        "rust": {"nodes": 0, "tx": 0, "rx": 0, "tx_hashes": 0, "rx_hashes": 0},
        "zephyr": {"nodes": 0, "tx": 0, "rx": 0, "tx_hashes": 0, "rx_hashes": 0},
    }

    for stats in all_nodes.values():
        impl_stats[stats.impl]["nodes"] += 1
        impl_stats[stats.impl]["tx"] += stats.tx_count
        impl_stats[stats.impl]["rx"] += stats.rx_count
        impl_stats[stats.impl]["tx_hashes"] += len(stats.tx_hashes)
        impl_stats[stats.impl]["rx_hashes"] += len(stats.rx_hashes)

    # Find missing packets
    missing = find_missing_packets(all_nodes)

    # Build reception matrix
    matrix = build_reception_matrix(all_nodes)

    # Generate report
    lines = []
    lines.append("# Heterogeneous Fleet Analysis Report")
    lines.append("")
    lines.append(f"**Logs directory:** `{logs_dir}`")
    lines.append(f"**Total nodes:** {len(all_nodes)}")
    lines.append("")

    # Per-implementation stats
    lines.append("## Per-Implementation Statistics")
    lines.append("")
    lines.append("| Implementation | Nodes | TX Count | RX Count | TX Hashes | RX Hashes |")
    lines.append("|----------------|-------|----------|----------|-----------|-----------|")

    for impl in ["py", "rust", "zephyr"]:
        s = impl_stats[impl]
        lines.append(
            f"| {impl:14} | {s['nodes']:5} | {s['tx']:8} | {s['rx']:8} | "
            f"{s['tx_hashes']:9} | {s['rx_hashes']:9} |"
        )

    lines.append("")

    # Reception matrix
    lines.append("## Cross-Implementation Reception Matrix")
    lines.append("")
    lines.append("Rows = senders, Columns = receivers. Values = packet count.")
    lines.append("")
    lines.append("|           | py-rx | rust-rx | zephyr-rx |")
    lines.append("|-----------|-------|---------|-----------|")

    for sender in ["py", "rust", "zephyr"]:
        row = f"| {sender:9} |"
        for receiver in ["py", "rust", "zephyr"]:
            count = matrix[sender][receiver]
            row += f" {count:5} |"
        lines.append(row)

    lines.append("")

    # Interop issues
    lines.append("## Interop Analysis")
    lines.append("")

    issues = []
    for sender in ["py", "rust", "zephyr"]:
        for receiver in ["py", "rust", "zephyr"]:
            if sender == receiver:
                continue
            if matrix[sender][receiver] == 0:
                # Check if sender actually sent anything
                sender_tx = impl_stats[sender]["tx_hashes"]
                if sender_tx > 0:
                    issues.append(f"- **{sender} -> {receiver}**: No packets received (0/{sender_tx})")

    if issues:
        lines.append("### Interop Failures")
        lines.append("")
        for issue in issues:
            lines.append(issue)
        lines.append("")
    else:
        lines.append("No interop failures detected (all impl pairs communicated).")
        lines.append("")

    # Missing packets
    lines.append("## Missing Packets")
    lines.append("")
    lines.append(f"**Total missing:** {len(missing)} packets sent but never received.")
    lines.append("")

    if missing:
        # Group by implementation
        by_impl: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for h, node_id, impl in missing:
            by_impl[impl].append((h, node_id))

        for impl in ["py", "rust", "zephyr"]:
            if impl in by_impl and by_impl[impl]:
                lines.append(f"### {impl} ({len(by_impl[impl])} missing)")
                lines.append("")
                # Show first 10, summarize rest
                for h, node_id in by_impl[impl][:10]:
                    lines.append(f"- `{h}` from {node_id}")
                if len(by_impl[impl]) > 10:
                    lines.append(f"- ... and {len(by_impl[impl]) - 10} more")
                lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")

    total_tx = sum(s["tx"] for s in impl_stats.values())
    total_rx = sum(s["rx"] for s in impl_stats.values())
    total_tx_hashes = sum(s["tx_hashes"] for s in impl_stats.values())
    total_rx_hashes = sum(s["rx_hashes"] for s in impl_stats.values())

    if total_tx > 0:
        rx_rate = (total_rx / total_tx) * 100
    else:
        rx_rate = 0.0

    lines.append(f"- **Total TX:** {total_tx}")
    lines.append(f"- **Total RX:** {total_rx}")
    lines.append(f"- **Reception rate:** {rx_rate:.1f}%")
    lines.append(f"- **Unique TX hashes:** {total_tx_hashes}")
    lines.append(f"- **Unique RX hashes:** {total_rx_hashes}")
    lines.append(f"- **Missing packets:** {len(missing)}")

    if issues:
        lines.append(f"- **Interop failures:** {len(issues)}")
        lines.append("")
        lines.append("**VERDICT: INTEROP ISSUES DETECTED** - see failures above.")
    else:
        lines.append("")
        lines.append("**VERDICT: All implementations communicate successfully.**")

    lines.append("")

    # Write report
    report_content = "\n".join(lines)
    output.write_text(report_content)
    print(f"Report written to: {output}")

    # Also print summary to stdout
    print()
    print("=== Summary ===")
    print(f"Nodes: py={impl_stats['py']['nodes']}, rust={impl_stats['rust']['nodes']}, zephyr={impl_stats['zephyr']['nodes']}")
    print(f"TX/RX: {total_tx}/{total_rx} ({rx_rate:.1f}%)")
    print(f"Missing: {len(missing)} packets")
    if issues:
        print(f"INTEROP FAILURES: {len(issues)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze heterogeneous LICHEN mesh telemetry."
    )
    parser.add_argument(
        "logs_dir",
        type=Path,
        help="Directory containing log files (py-*.log, rust-*.log, zephyr-*.log)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("hetero-report.md"),
        help="Output markdown report path (default: hetero-report.md)",
    )

    args = parser.parse_args()

    if not args.logs_dir.is_dir():
        parser.error(f"Logs directory not found: {args.logs_dir}")

    generate_report(args.logs_dir, args.output)


if __name__ == "__main__":
    main()
