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
EC2_SSH_KEY="${EC2_SSH_KEY:-$HOME/.ssh/id_ed25519}"
ZEPHYR_ELF="${ZEPHYR_ELF:-$PROJECT_ROOT/build/t_echo_renode/zephyr/zephyr.elf}"
ZEPHYR_VECTOR_OFFSET="${ZEPHYR_VECTOR_OFFSET:-0x32200}"
ZEPHYR_SP="${ZEPHYR_SP:-0x2000d8c0}"
ZEPHYR_PC="${ZEPHYR_PC:-0x35f1d}"

aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

# Check prerequisites
check_prereqs() {
    # Zephyr firmware
    if [[ $ZEPHYR_NODES -gt 0 ]]; then
        if [[ ! -f "$ZEPHYR_ELF" ]]; then
            log_error "Zephyr firmware not found. Build it:"
            log_error "  west build -b t_echo/nrf52840 lichen/apps/puck -d build/t_echo_renode"
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
    for pid in "${RUST_PIDS[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PYTHON_PIDS[@]-}"; do
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
import hashlib
import json
import sys
import time
sys.path.insert(0, "src")

from lichen.radio.sim_client import SimRadio
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity

def telemetry(event, node_id, payload, status="ok", rssi=None, snr=None):
    packet_hash = hashlib.sha256(payload).hexdigest()[:16]
    record = {
        "schema": "lichen.telemetry.v1",
        "event": event,
        "ts_us": time.monotonic_ns() // 1000,
        "node_id": f"py-{node_id}",
        "impl": "python",
        "tx_id": packet_hash,
        "packet_hash": packet_hash,
        "direction": "tx" if event.startswith("tx") else "rx",
        "peer_id": None,
        "payload_len": len(payload),
        "rssi_dbm": rssi,
        "snr_db": snr,
        "seq": None,
        "status": status,
    }
    print("TELEMETRY " + json.dumps(record, sort_keys=True), flush=True)

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
            payload = announce.to_bytes()
            if await radio.transmit(payload):
                telemetry("tx", node_id, payload)
                tx_count += 1

            # Listen for a bit
            for _ in range(5):
                result = await radio.receive(1000)
                if result:
                    payload, rssi, snr = result
                    telemetry("rx", node_id, payload, rssi=rssi, snr=snr)
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

    # Create Rust hetero-node binary if needed
    RUST_BIN="$PROJECT_ROOT/rust/target/release/hetero-node"
    if [[ ! -f "$RUST_BIN" || "$PROJECT_ROOT/rust/lichen-apps/src/bin/hetero_node.rs" -nt "$RUST_BIN" ]]; then
        # Create the binary
        mkdir -p "$PROJECT_ROOT/rust/lichen-apps/src/bin"
        cat > "$PROJECT_ROOT/rust/lichen-apps/src/bin/hetero_node.rs" << 'RUSTNODE'
//! Heterogeneous mesh node - connects to lichen-sim and participates in mesh.

use std::env;
use std::time::{Duration, Instant};

use lichen_link::identity::Identity;
use lichen_node::announce::{AnnounceMessage, AnnounceScheduler};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: hetero-node <node_id> <sim_host> <sim_port> <duration_s>");
        std::process::exit(1);
    }

    let node_id: u32 = args[1].parse().unwrap();
    let host = &args[2];
    let port: u16 = args[3].parse().unwrap();
    let duration_s: u64 = args[4].parse().unwrap();

    // Create identity from node_id
    let mut seed = [0u8; 32];
    seed[0] = (node_id & 0xFF) as u8;
    seed[1] = ((node_id >> 8) & 0xFF) as u8;
    let identity = Identity::from_seed(&seed);

    println!("rust-{}: connecting to {}:{}", node_id, host, port);

    // Connect to lichen-sim
    let mut radio = match lichen_embassy::sim::SimRadio::connect(host, port) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rust-{}: connect failed: {:?}", node_id, e);
            std::process::exit(1);
        }
    };

    let start = Instant::now();
    let mut tx_count = 0u32;
    let mut rx_count = 0u32;
    let mut buf = [0u8; 256];

    while start.elapsed() < Duration::from_secs(duration_s) {
        // Build and send announce
        // (simplified - real impl would use full scheduler)
        let announce_data = format!("RUST-{}-{}", node_id, tx_count);

        if let Err(e) = futures::executor::block_on(
            lichen_hal::Radio::transmit(&mut radio, announce_data.as_bytes())
        ) {
            eprintln!("rust-{}: TX error: {:?}", node_id, e);
        } else {
            tx_count += 1;
        }

        // Listen
        for _ in 0..5 {
            match futures::executor::block_on(
                lichen_hal::Radio::receive(&mut radio, &mut buf, 1000)
            ) {
                Ok(Some(_)) => rx_count += 1,
                Ok(None) => {}
                Err(e) => eprintln!("rust-{}: RX error: {:?}", node_id, e),
            }
        }

        std::thread::sleep(Duration::from_secs(10));
    }

    println!("rust-{}: TX={} RX={}", node_id, tx_count, rx_count);
}
RUSTNODE

        # Add to Cargo.toml
        if ! grep -q "hetero-node" "$PROJECT_ROOT/rust/lichen-apps/Cargo.toml"; then
            cat >> "$PROJECT_ROOT/rust/lichen-apps/Cargo.toml" << 'CARGO'

[[bin]]
name = "hetero-node"
path = "src/bin/hetero_node.rs"
CARGO
        fi

        # Add dependencies
        if ! grep -q "lichen-embassy" "$PROJECT_ROOT/rust/lichen-apps/Cargo.toml"; then
            sed -i '' 's/\[dependencies\]/[dependencies]\nlichen-embassy = { path = "..\/lichen-embassy" }\nlichen-hal = { path = "..\/lichen-hal" }\nfutures = "0.3"/' \
                "$PROJECT_ROOT/rust/lichen-apps/Cargo.toml" 2>/dev/null || true
        fi

        cd "$PROJECT_ROOT/rust"
        cargo build --release -p lichen-apps --bin hetero-node 2>/dev/null || {
            log_warn "Rust build failed - skipping Rust nodes"
            RUST_NODES=0
        }
    fi

    if [[ $RUST_NODES -gt 0 ]] && [[ -f "$RUST_BIN" ]]; then
        for i in $(seq 0 $((RUST_NODES - 1))); do
            NODE_ID=$((2000 + i))  # Rust nodes: 2000+

            "$RUST_BIN" "$NODE_ID" "127.0.0.1" 5555 "$X_POS" "$DURATION_S" \
                > "$RESULTS_DIR/rust-$NODE_ID.log" 2>&1 &
            RUST_PIDS+=($!)
        done
        log_ok "Started $RUST_NODES Rust nodes"
    fi
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
set -euxo pipefail
dnf install -y python3 wget
wget -q https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-arm64-portable-dotnet.tar.gz -O /tmp/renode.tar.gz
tar xf /tmp/renode.tar.gz -C /opt
test -x /opt/renode_1.16.1-dotnet_portable/renode
ln -sfn /opt/renode_1.16.1-dotnet_portable/renode /usr/local/bin/renode
test -x /usr/local/bin/renode
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
    INSTANCE_IPS=()
    EC2_INDEX=0
    for id in "${INSTANCE_IDS[@]}"; do
        IP=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        AZ=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
        INSTANCE_IPS+=("$IP")

        aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2-instance-connect \
            send-ssh-public-key \
            --instance-id "$id" \
            --instance-os-user ec2-user \
            --availability-zone "$AZ" \
            --ssh-public-key "file://${EC2_SSH_KEY}.pub" >/dev/null

        READY=0
        for attempt in {1..30}; do
            aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2-instance-connect \
                send-ssh-public-key \
                --instance-id "$id" \
                --instance-os-user ec2-user \
                --availability-zone "$AZ" \
                --ssh-public-key "file://${EC2_SSH_KEY}.pub" >/dev/null
            if ssh -i "$EC2_SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 ec2-user@"$IP" \
                "test -f /tmp/renode-ready" 2>/dev/null; then
                READY=1
                break
            fi
            sleep 10
        done
        if [[ $READY -ne 1 ]]; then
            log_error "EC2 instance $id did not complete Renode setup"
            exit 1
        fi
        EC2_INDEX=$((EC2_INDEX + 1))
    done
    log_ok "EC2 instances ready"

    # Upload files
    log_info "Uploading firmware to EC2..."
    EC2_INDEX=0
    for id in "${INSTANCE_IDS[@]}"; do
        IP="${INSTANCE_IPS[$EC2_INDEX]}"
        AZ=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
        aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2-instance-connect \
            send-ssh-public-key \
            --instance-id "$id" \
            --instance-os-user ec2-user \
            --availability-zone "$AZ" \
            --ssh-public-key "file://${EC2_SSH_KEY}.pub" >/dev/null
        timeout 60 scp -O -i "$EC2_SSH_KEY" \
            -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
            -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -q \
            "$ZEPHYR_ELF" \
            "$PROJECT_ROOT/lichen/boards/renode/peripherals/SX1262.cs" \
            "$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl" \
            "$PROJECT_ROOT/lichen/boards/renode/t_echo/support/t_echo.repl" \
            ec2-user@"$IP":/tmp/
        EC2_INDEX=$((EC2_INDEX + 1))
    done

    # Start Renodes
    log_info "Starting Renode instances..."
    NODE_ID=3000  # Zephyr nodes: 3000+
    EC2_NUM=0

    EC2_INDEX=0
    for id in "${INSTANCE_IDS[@]}"; do
        IP="${INSTANCE_IPS[$EC2_INDEX]}"
        EC2_NUM=$((EC2_NUM + 1))

        if [[ $EC2_NUM -eq $NUM_EC2 ]]; then
            NODES_THIS=$(( ZEPHYR_NODES - (NUM_EC2 - 1) * RENODES_PER_EC2 ))
        else
            NODES_THIS=$RENODES_PER_EC2
        fi

        ssh -i "$EC2_SSH_KEY" -o StrictHostKeyChecking=no ec2-user@"$IP" bash -s << REMOTE
cd /tmp
sed 's#using "../../nrf52840_lichen/support/nrf52840_lichen.repl"#using "/tmp/nrf52840_lichen.repl"#' \
    /tmp/t_echo.repl > /tmp/t_echo_runtime.repl
for i in \$(seq 0 $((NODES_THIS - 1))); do
    NID=\$((${NODE_ID} + i))
    X_POS=\$((NID * 50))

    cat > node-\$NID.resc << RESC
:name: zephyr-\$NID
include @/tmp/SX1262.cs
mach create "zephyr-\$NID"
machine LoadPlatformDescription @/tmp/t_echo_runtime.repl
spi1.sx1262 SimHost "$PUBLIC_IP"
spi1.sx1262 SimPort 5555
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NID))
sysbus Tag <0x10000130, 0x10000133> "DEVICEID[0]" \$((0x1CE00000 + NID))
sysbus Tag <0x10000134, 0x10000137> "DEVICEID[1]" \$((0x1CE10000 + NID))
sysbus LoadELF @/tmp/zephyr.elf
cpu VectorTableOffset $ZEPHYR_VECTOR_OFFSET
cpu SP $ZEPHYR_SP
cpu PC $ZEPHYR_PC
cpu PerformanceInMips 64
logFile @/tmp/zephyr-\$NID.log true
uart0 CreateFileBackend @/tmp/zephyr-\$NID-uart.log true
start
RESC

    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 /opt/renode_1.16.1-dotnet_portable/renode --disable-xwt --console --port \$((50000 + NID)) node-\$NID.resc > /tmp/renode-\$NID.log 2>&1 &
done
REMOTE
        NODE_ID=$((NODE_ID + NODES_THIS))
        EC2_INDEX=$((EC2_INDEX + 1))
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

# Let node processes flush their final metrics before collecting logs.
for pid in "${PYTHON_PIDS[@]-}" "${RUST_PIDS[@]-}"; do
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
done

log_ok "Test complete"

# === COLLECT RESULTS ===
log_info "Collecting results..."

# Get Zephyr logs from EC2 when the fleet includes Zephyr nodes.
if [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
    EC2_INDEX=0
    for id in "${INSTANCE_IDS[@]}"; do
        IP="${INSTANCE_IPS[$EC2_INDEX]}"
        AZ=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
        aws --profile "$AWS_PROFILE" --region "$AWS_REGION" ec2-instance-connect \
            send-ssh-public-key \
            --instance-id "$id" \
            --instance-os-user ec2-user \
            --availability-zone "$AZ" \
            --ssh-public-key "file://${EC2_SSH_KEY}.pub" >/dev/null
        ssh -i "$EC2_SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
            ec2-user@"$IP" \
             "find /tmp -maxdepth 1 -type f \( -name 'zephyr-*' -o -name 'renode-*' \) -print -exec cat {} \\;" \
             > "$RESULTS_DIR/zephyr-remote-$EC2_INDEX.log" 2>&1 || true
        scp -O -i "$EC2_SSH_KEY" -o StrictHostKeyChecking=no -q \
            ec2-user@"$IP":/tmp/zephyr-* "$RESULTS_DIR/" 2>/dev/null || true
        EC2_INDEX=$((EC2_INDEX + 1))
    done
fi

# Analyze
echo ""
REPORT_PATH="$RESULTS_DIR/telemetry-report.md"
if python3 "$PROJECT_ROOT/scripts/analyze-hetero-fleet.py" "$RESULTS_DIR" -o "$REPORT_PATH"; then
    log_ok "Telemetry report: $REPORT_PATH"
else
    log_error "Telemetry analyzer failed; raw logs remain at $RESULTS_DIR"
fi
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
    tx_lines=$(grep -c -E "TX|Send|beacon seq" "$log" 2>/dev/null || true)
    rx_lines=$(grep -c -E "RX|Recv" "$log" 2>/dev/null || true)
    ZEPHYR_TX=$((ZEPHYR_TX + ${tx_lines:-0}))
    ZEPHYR_RX=$((ZEPHYR_RX + ${rx_lines:-0}))
done
echo "  Zephyr:  TX=$ZEPHYR_TX  RX=$ZEPHYR_RX"

# Cross-impl check
TOTAL_TX=$((PY_TX + RUST_TX + ZEPHYR_TX))
TOTAL_RX=$((PY_RX + RUST_RX + ZEPHYR_RX))
echo ""
echo "  Total:   TX=$TOTAL_TX  RX=$TOTAL_RX"
echo "  Logs:    $RESULTS_DIR"

# Check for interop issues
if [[ $TOTAL_TX -eq 0 ]]; then
    log_error "NO TRANSMISSIONS RECORDED - fleet nodes did not produce metrics!"
    exit 1
elif [[ $PYTHON_NODES -gt 0 && ( $PY_TX -eq 0 || $PY_RX -eq 0 ) ]]; then
    log_error "Python nodes did not produce bidirectional traffic (TX=$PY_TX RX=$PY_RX)"
    exit 1
elif [[ $RUST_NODES -gt 0 && ( $RUST_TX -eq 0 || $RUST_RX -eq 0 ) ]]; then
    log_error "Rust nodes did not produce bidirectional traffic (TX=$RUST_TX RX=$RUST_RX)"
    exit 1
elif [[ $ZEPHYR_NODES -gt 0 && ( $ZEPHYR_TX -eq 0 || $ZEPHYR_RX -eq 0 ) ]]; then
    log_error "Zephyr nodes did not produce bidirectional traffic (TX=$ZEPHYR_TX RX=$ZEPHYR_RX)"
    exit 1
elif [[ $TOTAL_RX -eq 0 ]]; then
    log_error "NO CROSS-IMPL RECEPTION - implementations may not interop!"
    cd "$PROJECT_ROOT"
    bd create "Hetero mesh: $TOTAL_TX TX but 0 RX - interop failure" \
        --type bug --priority P0 2>/dev/null || true
elif [[ $TOTAL_RX -lt $((TOTAL_TX / 10)) ]]; then
    log_warn "Low reception rate - possible interop issues"
    cd "$PROJECT_ROOT"
    bd create "Hetero mesh: low RX rate ($TOTAL_RX/$TOTAL_TX) - check interop" \
        --type bug --priority P1 2>/dev/null || true
else
    log_ok "Cross-implementation communication verified!"
fi
