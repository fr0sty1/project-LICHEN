#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# ec2-hetero-fleet.sh - Heterogeneous mesh: Zephyr C + Rust + Python nodes
#
# Runs a mixed-implementation mesh where all three codebases communicate
# through the same lichen-sim RF propagation. This is the real interop test.
#
# Usage:
#   ./scripts/ec2-hetero-fleet.sh --zephyr 50 --rust 50 --python 50
#   ./scripts/ec2-hetero-fleet.sh --total 150  # auto-split evenly
#
# Architecture:
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  lichen-sim (coordinator)                                       │
#   │  RF propagation for ALL nodes regardless of implementation      │
#   └─────────────────────────────────────────────────────────────────┘
#          │                    │                    │
#          ▼                    ▼                    ▼
#   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
#   │  Zephyr C   │      │    Rust     │      │   Python    │
#   │  (Renode)   │      │  (native)   │      │  (native)   │
#   │             │      │             │      │             │
#   │ SX1262.cs   │      │  SimRadio   │      │  SimRadio   │
#   │ peripheral  │      │  (TCP)      │      │  (TCP)      │
#   └─────────────┘      └─────────────┘      └─────────────┘
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
ZEPHYR_NODES=0
RUST_NODES=0
PYTHON_NODES=0
TOTAL_NODES=0
DURATION_S=300
RENODES_PER_EC2=20

# Colors
log_info()  { echo -e "\033[0;34m>>>\033[0m $*" >&2; }
log_ok()    { echo -e "\033[0;32m>>>\033[0m $*" >&2; }
log_warn()  { echo -e "\033[0;33m>>>\033[0m $*" >&2; }
log_error() { echo -e "\033[0;31mERROR:\033[0m $*" >&2; }

usage() {
    cat << 'EOF'
Usage: ec2-hetero-fleet.sh [OPTIONS]

Run heterogeneous mesh with Zephyr C, Rust, and Python implementations.

Options:
  --zephyr N     Number of Zephyr/Renode nodes (actual C firmware)
  --rust N       Number of Rust nodes (lichen-node stack)
  --python N     Number of Python nodes (lichen package)
  --total N      Total nodes, split evenly across implementations
  --duration S   Test duration in seconds (default: 300)
  --help         Show this help

Examples:
  # 50 of each implementation
  ./ec2-hetero-fleet.sh --zephyr 50 --rust 50 --python 50

  # 150 nodes split evenly (50 each)
  ./ec2-hetero-fleet.sh --total 150

  # Heavy on Zephyr, light on others
  ./ec2-hetero-fleet.sh --zephyr 100 --rust 25 --python 25
EOF
    exit 0
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --zephyr) ZEPHYR_NODES="$2"; shift 2 ;;
        --rust) RUST_NODES="$2"; shift 2 ;;
        --python) PYTHON_NODES="$2"; shift 2 ;;
        --total) TOTAL_NODES="$2"; shift 2 ;;
        --duration) DURATION_S="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown: $1"; exit 1 ;;
    esac
done

# If --total specified, split evenly
if [[ $TOTAL_NODES -gt 0 ]]; then
    EACH=$((TOTAL_NODES / 3))
    ZEPHYR_NODES=$EACH
    RUST_NODES=$EACH
    PYTHON_NODES=$((TOTAL_NODES - 2 * EACH))
fi

# Validate
if [[ $((ZEPHYR_NODES + RUST_NODES + PYTHON_NODES)) -eq 0 ]]; then
    log_error "Specify node counts with --zephyr/--rust/--python or --total"
    exit 1
fi

TOTAL=$((ZEPHYR_NODES + RUST_NODES + PYTHON_NODES))

log_info "=== Heterogeneous LICHEN Mesh ==="
log_info "  Zephyr (C firmware): $ZEPHYR_NODES nodes"
log_info "  Rust (native):       $RUST_NODES nodes"
log_info "  Python (native):     $PYTHON_NODES nodes"
log_info "  Total:               $TOTAL nodes"
log_info "  Duration:            ${DURATION_S}s"
echo ""

# AWS config
AWS_PROFILE="${AWS_PROFILE:-AdministratorAccess-921772462201}"
AWS_REGION="us-east-2"
AMI_ID="ami-03a84069f5e253220"
KEY_NAME="lichen-ct4d-20260702232050"

aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

# Check prerequisites
check_prereqs() {
    # Zephyr firmware
    if [[ $ZEPHYR_NODES -gt 0 ]]; then
        if [[ ! -f "$PROJECT_ROOT/build/lora_ping/zephyr/zephyr.elf" ]]; then
            log_error "Zephyr firmware not found. Build it:"
            log_error "  west build -b nrf52840_lichen lichen/samples/lora_ping -d build/lora_ping"
            exit 1
        fi
    fi

    # Rust binary
    if [[ $RUST_NODES -gt 0 ]]; then
        if [[ ! -f "$PROJECT_ROOT/rust/target/release/hetero-node" ]]; then
            log_warn "Rust hetero-node not found, will build..."
        fi
    fi
}

check_prereqs

# State
INSTANCE_IDS=()
SIM_PID=""
RUST_PIDS=()
PYTHON_PIDS=()
RESULTS_DIR="/tmp/hetero-fleet-$(date +%s)"
mkdir -p "$RESULTS_DIR"

cleanup() {
    log_info "Cleaning up..."

    # Kill local processes
    [[ -n "$SIM_PID" ]] && kill "$SIM_PID" 2>/dev/null || true
    for pid in "${RUST_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PYTHON_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Terminate EC2
    if [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
        log_info "Terminating ${#INSTANCE_IDS[@]} EC2 instances..."
        aws_cmd ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Get public IP
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com)
log_info "Coordinator IP: $PUBLIC_IP"

# Start lichen-sim
log_info "Starting lichen-sim server..."
cd "$PROJECT_ROOT/python"

cat > /tmp/hetero-sim.py << 'SIMPY'
import asyncio
import sys
sys.path.insert(0, "src")
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode

async def main():
    server = SimulatorServer(node_port=5555, api_port=5556, bind_host="0.0.0.0")
    await server.start()
    sim = await server.create_simulation("hetero-mesh", TimeMode.REALTIME)
    print("lichen-sim ready on 0.0.0.0:5555", flush=True)

    # Track connections
    connected = set()
    while True:
        await asyncio.sleep(5)
        nodes = list(sim._nodes.keys())
        new_nodes = set(nodes) - connected
        if new_nodes:
            print(f"New nodes: {new_nodes} (total: {len(nodes)})", flush=True)
            connected = set(nodes)

asyncio.run(main())
SIMPY

uv run python3 /tmp/hetero-sim.py > "$RESULTS_DIR/lichen-sim.log" 2>&1 &
SIM_PID=$!
sleep 3

if ! kill -0 "$SIM_PID" 2>/dev/null; then
    log_error "lichen-sim failed to start"
    cat "$RESULTS_DIR/lichen-sim.log"
    exit 1
fi
log_ok "lichen-sim running"

# === PYTHON NODES ===
if [[ $PYTHON_NODES -gt 0 ]]; then
    log_info "Starting $PYTHON_NODES Python nodes..."

    cat > /tmp/python-node.py << 'PYNODE'
import asyncio
import sys
import os
sys.path.insert(0, "src")

from lichen.radio.sim_client import SimRadio
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity

async def run_node(node_id, host, port, position, duration):
    """Run a Python LICHEN node."""
    seed = bytes([node_id & 0xFF, (node_id >> 8) & 0xFF] + [0] * 30)
    identity = Identity.from_seed(seed)

    class TxCapture:
        def __init__(self, radio):
            self.radio = radio
        async def transmit_announce(self, data):
            await self.radio.transmit(data)
            return True

    async with SimRadio(host, port, "hetero-mesh", f"py-{node_id}", position) as radio:
        tx = TxCapture(radio)
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=tx,
            config=SchedulerConfig(interval_ms=10000, jitter_ms=2000, initial_delay_ms=1000),
        )

        start = asyncio.get_event_loop().time()
        tx_count = 0
        rx_count = 0

        while asyncio.get_event_loop().time() - start < duration:
            # Send announce
            announce = scheduler.build_announce()
            await radio.transmit(announce.to_bytes())
            tx_count += 1

            # Listen for a bit
            for _ in range(5):
                result = await radio.receive(1000)
                if result:
                    rx_count += 1

        print(f"py-{node_id}: TX={tx_count} RX={rx_count}", flush=True)

if __name__ == "__main__":
    node_id = int(sys.argv[1])
    host = sys.argv[2]
    port = int(sys.argv[3])
    x = float(sys.argv[4])
    duration = int(sys.argv[5])
    asyncio.run(run_node(node_id, host, port, (x, 0.0, 0.0), duration))
PYNODE

    for i in $(seq 0 $((PYTHON_NODES - 1))); do
        NODE_ID=$((1000 + i))  # Python nodes: 1000+
        X_POS=$((i * 50))

        uv run python3 /tmp/python-node.py "$NODE_ID" "127.0.0.1" 5555 "$X_POS" "$DURATION_S" \
            > "$RESULTS_DIR/py-$NODE_ID.log" 2>&1 &
        PYTHON_PIDS+=($!)
    done
    log_ok "Started $PYTHON_NODES Python nodes"
fi

# === RUST NODES ===
if [[ $RUST_NODES -gt 0 ]]; then
    log_info "Building and starting $RUST_NODES Rust nodes..."

    RUST_BIN="$PROJECT_ROOT/rust/target/release/hetero-node"
    (cd "$PROJECT_ROOT/rust" && cargo build --release --target-dir "$PROJECT_ROOT/rust/target" \
        -p lichen-apps --bin hetero-node) || {
        log_error "Rust hetero-node build failed"
        exit 1
    }
    if [[ ! -x "$RUST_BIN" ]]; then
        log_error "Rust hetero-node binary missing after successful build"
        exit 1
    fi

    for i in $(seq 0 $((RUST_NODES - 1))); do
        NODE_ID=$((2000 + i))  # Rust nodes: 2000+
        X_POS=$((i * 50))

        "$RUST_BIN" "$NODE_ID" "127.0.0.1" 5555 "$X_POS" "$DURATION_S" \
            > "$RESULTS_DIR/rust-$NODE_ID.log" 2>&1 &
        RUST_PIDS+=($!)
    done
    log_ok "Started $RUST_NODES Rust nodes"
fi

# === ZEPHYR NODES (EC2 + Renode) ===
if [[ $ZEPHYR_NODES -gt 0 ]]; then
    log_info "Launching EC2 instances for $ZEPHYR_NODES Zephyr nodes..."

    NUM_EC2=$(( (ZEPHYR_NODES + RENODES_PER_EC2 - 1) / RENODES_PER_EC2 ))

    # Find/create security group
    SG_ID=$(aws_cmd ec2 describe-security-groups \
        --filters "Name=group-name,Values=lichen-renode-fleet" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

    if [[ "$SG_ID" == "None" ]]; then
        SG_ID=$(aws_cmd ec2 create-security-group \
            --group-name "lichen-renode-fleet" \
            --description "LICHEN Renode fleet" \
            --query 'GroupId' --output text)
        aws_cmd ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" --protocol tcp --port 22 --cidr "0.0.0.0/0" >/dev/null
        aws_cmd ec2 create-tags --resources "$SG_ID" --tags Key=Project,Value=LICHEN
    fi

    # User data for Renode installation
    USER_DATA=$(cat << 'EOF' | base64 -w0
#!/bin/bash
dnf install -y python3 wget mono-core
wget -q https://github.com/renode/renode/releases/download/v1.14.0/renode-1.14.0.linux-portable-dotnet.tar.gz -O /tmp/renode.tar.gz
tar xf /tmp/renode.tar.gz -C /opt
ln -s /opt/renode_1.14.0_portable/renode /usr/local/bin/renode
touch /tmp/renode-ready
EOF
)

    # Launch EC2 instances
    NODE_OFFSET=0
    for ec2_num in $(seq 1 "$NUM_EC2"); do
        if [[ $ec2_num -eq $NUM_EC2 ]]; then
            NODES_THIS=$(( ZEPHYR_NODES - (NUM_EC2 - 1) * RENODES_PER_EC2 ))
        else
            NODES_THIS=$RENODES_PER_EC2
        fi

        INSTANCE_ID=$(aws_cmd ec2 run-instances \
            --image-id "$AMI_ID" \
            --instance-type "c7g.xlarge" \
            --key-name "$KEY_NAME" \
            --security-group-ids "$SG_ID" \
            --user-data "$USER_DATA" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=hetero-zephyr-$ec2_num},{Key=Project,Value=LICHEN}]" \
            --query 'Instances[0].InstanceId' --output text)

        INSTANCE_IDS+=("$INSTANCE_ID")
        log_info "  EC2 $ec2_num: $INSTANCE_ID (Zephyr nodes $NODE_OFFSET-$((NODE_OFFSET + NODES_THIS - 1)))"
        NODE_OFFSET=$((NODE_OFFSET + NODES_THIS))
    done

    # Wait for instances
    log_info "Waiting for EC2 instances..."
    aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"

    # Get IPs and wait for Renode
    declare -A EC2_IPS
    for id in "${INSTANCE_IDS[@]}"; do
        IP=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        EC2_IPS[$id]=$IP

        for attempt in {1..30}; do
            if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ec2-user@"$IP" \
                "test -f /tmp/renode-ready" 2>/dev/null; then
                break
            fi
            sleep 10
        done
    done
    log_ok "EC2 instances ready"

    # Upload files
    log_info "Uploading firmware to EC2..."
    for id in "${INSTANCE_IDS[@]}"; do
        IP="${EC2_IPS[$id]}"
        scp -o StrictHostKeyChecking=no -q \
            "$PROJECT_ROOT/build/lora_ping/zephyr/zephyr.elf" \
            "$PROJECT_ROOT/lichen/boards/renode/peripherals/SX1262.cs" \
            "$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl" \
            ec2-user@"$IP":/tmp/ &
    done
    wait

    # Start Renodes
    log_info "Starting Renode instances..."
    NODE_ID=3000  # Zephyr nodes: 3000+
    EC2_NUM=0

    for id in "${INSTANCE_IDS[@]}"; do
        IP="${EC2_IPS[$id]}"
        EC2_NUM=$((EC2_NUM + 1))

        if [[ $EC2_NUM -eq $NUM_EC2 ]]; then
            NODES_THIS=$(( ZEPHYR_NODES - (NUM_EC2 - 1) * RENODES_PER_EC2 ))
        else
            NODES_THIS=$RENODES_PER_EC2
        fi

        ssh -o StrictHostKeyChecking=no ec2-user@"$IP" bash -s << REMOTE
cd /tmp
for i in \$(seq 0 $((NODES_THIS - 1))); do
    NID=\$((${NODE_ID} + i))
    X_POS=\$((NID * 50))

    cat > node-\$NID.resc << RESC
:name: zephyr-\$NID
include @/tmp/SX1262.cs
mach create "zephyr-\$NID"
machine LoadPlatformDescription @/tmp/nrf52840_lichen.repl
spi1.sx1262 SimHost "$PUBLIC_IP"
spi1.sx1262 SimPort 5555
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NID))
sysbus LoadELF @/tmp/zephyr.elf
logFile @/tmp/zephyr-\$NID.log true
start
RESC

    renode --disable-gui --port \$((50000 + NID)) node-\$NID.resc > /dev/null 2>&1 &
done
REMOTE
        NODE_ID=$((NODE_ID + NODES_THIS))
    done &

    log_ok "Started $ZEPHYR_NODES Zephyr nodes on ${#INSTANCE_IDS[@]} EC2 instances"
fi

# === MONITOR TEST ===
log_info "Test running for ${DURATION_S}s..."
log_info "Nodes: Python=$PYTHON_NODES, Rust=$RUST_NODES, Zephyr=$ZEPHYR_NODES"

# Show progress
START_TIME=$(date +%s)
while true; do
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION_S - ELAPSED))
    [[ $REMAINING -le 0 ]] && break

    # Count connected nodes from lichen-sim log
    CONNECTED=$(grep -c "New nodes" "$RESULTS_DIR/lichen-sim.log" 2>/dev/null || echo "?")
    printf "\r  Elapsed: %ds, Remaining: %ds, Connected: %s  " "$ELAPSED" "$REMAINING" "$CONNECTED"
    sleep 10
done
echo ""

RUST_PROCESS_FAILURE=0
for pid in "${RUST_PIDS[@]-}"; do
    if [[ -n "$pid" ]] && ! wait "$pid"; then
        RUST_PROCESS_FAILURE=1
    fi
done
if [[ $RUST_PROCESS_FAILURE -ne 0 ]]; then
    log_error "One or more Rust nodes exited unsuccessfully"
    exit 1
fi

log_ok "Test complete"

# === COLLECT RESULTS ===
log_info "Collecting results..."

# Get Zephyr logs from EC2
for id in "${INSTANCE_IDS[@]}"; do
    IP="${EC2_IPS[$id]}"
    scp -o StrictHostKeyChecking=no -q \
        ec2-user@"$IP":/tmp/zephyr-*.log "$RESULTS_DIR/" 2>/dev/null || true
done

# Analyze
echo ""
log_ok "=== HETEROGENEOUS MESH RESULTS ==="

# Python results
PY_TX=0
PY_RX=0
for log in "$RESULTS_DIR"/py-*.log; do
    [[ -f "$log" ]] || continue
    if grep -q "TX=" "$log"; then
        tx=$(grep "TX=" "$log" | sed 's/.*TX=\([0-9]*\).*/\1/')
        rx=$(grep "RX=" "$log" | sed 's/.*RX=\([0-9]*\).*/\1/')
        PY_TX=$((PY_TX + tx))
        PY_RX=$((PY_RX + rx))
    fi
done
echo "  Python:  TX=$PY_TX  RX=$PY_RX"

# Rust results
RUST_TX=0
RUST_RX=0
for log in "$RESULTS_DIR"/rust-*.log; do
    [[ -f "$log" ]] || continue
    if grep -q "TX=" "$log"; then
        tx=$(grep "TX=" "$log" | sed 's/.*TX=\([0-9]*\).*/\1/')
        rx=$(grep "RX=" "$log" | sed 's/.*RX=\([0-9]*\).*/\1/')
        RUST_TX=$((RUST_TX + tx))
        RUST_RX=$((RUST_RX + rx))
    fi
done
echo "  Rust:    TX=$RUST_TX  RX=$RUST_RX"

# Zephyr results
ZEPHYR_TX=0
ZEPHYR_RX=0
for log in "$RESULTS_DIR"/zephyr-*.log; do
    [[ -f "$log" ]] || continue
    ZEPHYR_TX=$((ZEPHYR_TX + $(grep -c "TX\|Send" "$log" 2>/dev/null || echo 0)))
    ZEPHYR_RX=$((ZEPHYR_RX + $(grep -c "RX\|Recv" "$log" 2>/dev/null || echo 0)))
done
echo "  Zephyr:  TX=$ZEPHYR_TX  RX=$ZEPHYR_RX"

# Cross-impl check
TOTAL_TX=$((PY_TX + RUST_TX + ZEPHYR_TX))
TOTAL_RX=$((PY_RX + RUST_RX + ZEPHYR_RX))
echo ""
echo "  Total:   TX=$TOTAL_TX  RX=$TOTAL_RX"
echo "  Logs:    $RESULTS_DIR"

# Check for interop issues
if [[ $RUST_NODES -gt 0 && $RUST_TX -eq 0 ]]; then
    log_error "Rust nodes produced no transmissions"
    exit 1
elif [[ $TOTAL_RX -eq 0 ]] && [[ $TOTAL_TX -gt 0 ]]; then
    log_error "NO CROSS-IMPL RECEPTION - implementations may not interop!"
    cd "$PROJECT_ROOT"
    bd create "Hetero mesh: $TOTAL_TX TX but 0 RX - interop failure" \
        --type bug --priority P0 2>/dev/null || true
    exit 1
elif [[ $TOTAL_RX -lt $((TOTAL_TX / 10)) ]]; then
    log_warn "Low reception rate - possible interop issues"
    cd "$PROJECT_ROOT"
    bd create "Hetero mesh: low RX rate ($TOTAL_RX/$TOTAL_TX) - check interop" \
        --type bug --priority P1 2>/dev/null || true
else
    log_ok "Cross-implementation communication verified!"
fi
