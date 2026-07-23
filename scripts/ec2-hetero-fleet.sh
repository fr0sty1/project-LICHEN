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
AWS_PROFILE="${AWS_PROFILE:-personal}"
AWS_REGION="${AWS_REGION:-us-west-2}"
EXPECTED_AWS_ACCOUNT="210337117346"
AMI_ID="${EC2_AMI_ID:-ami-0764d1b512e22671f}"
KEY_NAME="${EC2_KEY_NAME:-markatwood}"
EC2_SSH_KEY="${EC2_SSH_KEY:-$HOME/.ssh/id_ed25519}"
ZEPHYR_ELF="${ZEPHYR_ELF:-$PROJECT_ROOT/build/t_echo_renode/zephyr/zephyr.elf}"
ZEPHYR_VECTOR_OFFSET="${ZEPHYR_VECTOR_OFFSET:-0x32200}"
ZEPHYR_SP="${ZEPHYR_SP:-0x2000d8c0}"
ZEPHYR_PC="${ZEPHYR_PC:-0x35f1d}"

aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

authenticate_ec2_host() {
    local instance_id=$1 host=$2 console expected="" scanned="" actual=""
    local attempt

    for attempt in {1..60}; do
        if console=$(aws_cmd ec2 get-console-output --instance-id "$instance_id" --latest \
                --query Output --output text 2>/dev/null); then
            expected=$(printf '%s\n' "$console" | sed -n \
                -e '/BEGIN SSH HOST KEY FINGERPRINTS/,/END SSH HOST KEY FINGERPRINTS/ {' \
                -e '/(ED25519)/ {' \
                -e 's/^.*\(SHA256:[A-Za-z0-9+\/=]*\).*$/\1/p' \
                -e '}' -e '}')
            if [[ -z "$expected" ]]; then
                expected=$(printf '%s\n' "$console" | sed -n \
                    -e '/Generating public\/private ed25519 key pair/,/Generating public\/private ecdsa key pair/ {' \
                    -e 's/^.*\(SHA256:[A-Za-z0-9+\/=]*\).*$/\1/p' \
                    -e '}')
            fi
            [[ -n "$expected" ]] && break
        fi
        sleep 5
    done
    if [[ -z "$expected" || "$expected" == *$'\n'* ]]; then
        log_error "No unique trusted ED25519 host fingerprint for $instance_id"
        return 1
    fi

    for attempt in {1..12}; do
        scanned=$(ssh-keyscan -T 5 -t ed25519 "$host" 2>/dev/null) || scanned=""
        [[ -n "$scanned" ]] && break
        sleep 5
    done
    if [[ -z "$scanned" || "$scanned" == *$'\n'* ]]; then
        log_error "No unique ED25519 host key from $host"
        return 1
    fi

    actual=$(printf '%s\n' "$scanned" | ssh-keygen -E sha256 -lf - 2>/dev/null |
        sed -n 's/^[0-9][0-9]* \(SHA256:[^ ]*\) .*$/\1/p')
    if [[ -z "$actual" || "$actual" != "$expected" ]]; then
        log_error "SSH host key mismatch for $instance_id ($host)"
        return 1
    fi
    printf '%s\n' "$scanned" >> "$KNOWN_HOSTS"
}

if [[ $ZEPHYR_NODES -gt 0 ]]; then
    CALLER_ACCOUNT=$(aws_cmd sts get-caller-identity --query Account --output text)
    if [[ "$CALLER_ACCOUNT" != "$EXPECTED_AWS_ACCOUNT" ]]; then
        log_error "AWS profile $AWS_PROFILE resolves to account $CALLER_ACCOUNT, expected $EXPECTED_AWS_ACCOUNT"
        exit 1
    fi
    read -r AMI_OWNER AMI_ARCH AMI_STATE AMI_PROJECT <<< "$(aws_cmd ec2 describe-images \
        --image-ids "$AMI_ID" \
        --query 'Images[0].[OwnerId,Architecture,State,Tags[?Key==`Project`].Value|[0]]' \
        --output text)"
    if [[ "$AMI_OWNER" != "$EXPECTED_AWS_ACCOUNT" || "$AMI_ARCH" != "arm64" || \
          "$AMI_STATE" != "available" || "$AMI_PROJECT" != "LICHEN" ]]; then
        log_error "AMI $AMI_ID is not an available account-owned ARM64 LICHEN runtime"
        exit 1
    fi
fi

# Check prerequisites
check_prereqs() {
    # Zephyr firmware
    if [[ $ZEPHYR_NODES -gt 0 ]]; then
        if [[ ! -f "$ZEPHYR_ELF" ]]; then
            log_error "Zephyr firmware not found. Build it:"
            log_error "  west build -b t_echo/nrf52840 lichen/apps/puck -d build/t_echo_renode -- -DEXTRA_DTC_OVERLAY_FILE=$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/renode_console.overlay -DEXTRA_CONF_FILE=$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/renode_console.conf"
            exit 1
        fi
        if nm -a "$ZEPHYR_ELF" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPIM|spi_nrfx_spim\.c)$' >/dev/null; then
            log_error "Zephyr firmware uses SPIM, which Renode 1.16.1 cannot run with this platform model"
            log_error "Rebuild with both renode_console.overlay and renode_console.conf"
            exit 1
        fi
        if ! nm -a "$ZEPHYR_ELF" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPI|spi_nrfx_spi\.c)$' >/dev/null; then
            log_error "Zephyr firmware does not contain the required legacy nRF SPI driver"
            log_error "Rebuild with both renode_console.overlay and renode_console.conf"
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
SG_ID=""
RUN_ID="$(date +%s)-$$-$RANDOM"
EC2_USED=false
[[ $ZEPHYR_NODES -gt 0 ]] && EC2_USED=true
SIM_PID=""
RUST_PIDS=()
PYTHON_PIDS=()
RESULTS_DIR="/tmp/hetero-fleet-$(date +%s)"
mkdir -p "$RESULTS_DIR"
KNOWN_HOSTS=$(mktemp "${TMPDIR:-/tmp}/lichen-hetero-known-hosts.XXXXXX")
SSH_OPTS=(
    -i "$EC2_SSH_KEY"
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=yes
    -o HostKeyAlgorithms=ssh-ed25519
    -o UpdateHostKeys=no
)
SCP_LEGACY=()
if ! scp -O 2>&1 | grep -E 'unknown option|illegal option' >/dev/null; then
    SCP_LEGACY=(-O)
fi

cleanup() {
    local original_status=$?
    local cleanup_failed=false
    trap - EXIT
    log_info "Cleaning up..."

    if [[ "$EC2_USED" == "true" ]]; then
        reconciled_ids=$(aws_cmd ec2 describe-instances \
            --filters "Name=tag:RunId,Values=$RUN_ID" \
                      "Name=tag:Project,Values=LICHEN" \
                      "Name=tag:LaunchedBy,Values=ec2-hetero-fleet.sh" \
                      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
            --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null) || {
            log_error "Could not reconcile instances for run $RUN_ID"
            reconciled_ids=""
            cleanup_failed=true
        }
        for id in $reconciled_ids; do
            tracked=false
            for tracked_id in "${INSTANCE_IDS[@]-}"; do
                [[ "$id" == "$tracked_id" ]] && tracked=true
            done
            [[ "$tracked" == "true" ]] || INSTANCE_IDS+=("$id")
        done
        if [[ -z "$SG_ID" ]]; then
            if ! SG_ID=$(aws_cmd ec2 describe-security-groups \
                    --filters "Name=group-name,Values=lichen-hetero-fleet-$RUN_ID" \
                              "Name=tag:RunId,Values=$RUN_ID" \
                              "Name=tag:Project,Values=LICHEN" \
                              "Name=tag:LaunchedBy,Values=ec2-hetero-fleet.sh" \
                    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null); then
                SG_ID=""
                cleanup_failed=true
            fi
            [[ "$SG_ID" == "None" ]] && SG_ID=""
        fi
    fi

    # Kill local processes
    [[ -n "$SIM_PID" ]] && kill "$SIM_PID" 2>/dev/null || true
    for pid in "${RUST_PIDS[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PYTHON_PIDS[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Terminate EC2
    ownership_ok=true
    for id in "${INSTANCE_IDS[@]-}"; do
        read -r project launched_by run_id <<< "$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].[Tags[?Key==`Project`].Value|[0],Tags[?Key==`LaunchedBy`].Value|[0],Tags[?Key==`RunId`].Value|[0]]' \
            --output text 2>/dev/null)" || ownership_ok=false
        if [[ "$project" != "LICHEN" || "$launched_by" != "ec2-hetero-fleet.sh" || "$run_id" != "$RUN_ID" ]]; then
            log_error "Refusing to terminate unverified instance $id"
            ownership_ok=false
        fi
    done
    if [[ ${#INSTANCE_IDS[@]} -gt 0 && "$ownership_ok" == "true" ]]; then
        log_info "Terminating ${#INSTANCE_IDS[@]} EC2 instances..."
        if ! aws_cmd ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null; then
            log_error "Failed to request instance termination: ${INSTANCE_IDS[*]}"
            cleanup_failed=true
        elif ! aws_cmd ec2 wait instance-terminated --instance-ids "${INSTANCE_IDS[@]}"; then
            log_error "Instances did not reach terminated state: ${INSTANCE_IDS[*]}"
            cleanup_failed=true
        fi
    elif [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
        cleanup_failed=true
    fi
    if [[ -n "$SG_ID" && "$cleanup_failed" == "false" ]]; then
        read -r sg_project sg_launched_by sg_run_id <<< "$(aws_cmd ec2 describe-security-groups --group-ids "$SG_ID" \
            --query 'SecurityGroups[0].[Tags[?Key==`Project`].Value|[0],Tags[?Key==`LaunchedBy`].Value|[0],Tags[?Key==`RunId`].Value|[0]]' \
            --output text 2>/dev/null)" || cleanup_failed=true
        if [[ "$sg_project" != "LICHEN" || "$sg_launched_by" != "ec2-hetero-fleet.sh" || "$sg_run_id" != "$RUN_ID" ]]; then
            log_error "Refusing to delete unverified security group $SG_ID"
            cleanup_failed=true
        fi
    fi
    if [[ -n "$SG_ID" && "$cleanup_failed" == "false" ]]; then
        deleted=false
        for _ in {1..6}; do
            if aws_cmd ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1; then
                deleted=true
                break
            fi
            sleep 5
        done
        if [[ "$deleted" != "true" ]]; then
            log_error "Failed to delete per-run security group $SG_ID"
            cleanup_failed=true
        fi
    fi
    if [[ $original_status -ne 0 ]]; then
        exit "$original_status"
    elif [[ "$cleanup_failed" == "true" ]]; then
        exit 1
    fi
    exit 0
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
    packet_hash = hashlib.sha256(payload).digest()[:16].hex()
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
fi

# === ZEPHYR NODES (EC2 + Renode) ===
if [[ $ZEPHYR_NODES -gt 0 ]]; then
    log_info "Launching EC2 instances for $ZEPHYR_NODES Zephyr nodes..."

    NUM_EC2=$(( (ZEPHYR_NODES + RENODES_PER_EC2 - 1) / RENODES_PER_EC2 ))

    SG_NAME="lichen-hetero-fleet-$RUN_ID"
    if ! SG_ID=$(aws_cmd ec2 create-security-group \
            --group-name "$SG_NAME" \
            --description "LICHEN heterogeneous Renode fleet" \
            --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=LICHEN},{Key=Purpose,Value=hetero-fleet},{Key=LaunchedBy,Value=ec2-hetero-fleet.sh},{Key=RunId,Value=$RUN_ID}]" \
            --query 'GroupId' --output text); then
        SG_ID=$(aws_cmd ec2 describe-security-groups \
            --filters "Name=group-name,Values=$SG_NAME" "Name=tag:RunId,Values=$RUN_ID" \
                      "Name=tag:Project,Values=LICHEN" \
                      "Name=tag:LaunchedBy,Values=ec2-hetero-fleet.sh" \
            --query 'SecurityGroups[0].GroupId' --output text)
    fi
    if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
        log_error "Could not create or reconcile security group for run $RUN_ID"
        exit 1
    fi
    aws_cmd ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${PUBLIC_IP}/32" >/dev/null

    # Launch EC2 instances
    NODE_OFFSET=0
    for ec2_num in $(seq 1 "$NUM_EC2"); do
        if [[ $ec2_num -eq $NUM_EC2 ]]; then
            NODES_THIS=$(( ZEPHYR_NODES - (NUM_EC2 - 1) * RENODES_PER_EC2 ))
        else
            NODES_THIS=$RENODES_PER_EC2
        fi

        INSTANCE_ID=""
        for _ in {1..3}; do
            if INSTANCE_ID=$(aws_cmd ec2 run-instances \
                    --client-token "$RUN_ID-$ec2_num" \
                    --image-id "$AMI_ID" \
                    --instance-type "c7g.xlarge" \
                    --key-name "$KEY_NAME" \
                    --security-group-ids "$SG_ID" \
                    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=hetero-zephyr-$ec2_num},{Key=Project,Value=LICHEN},{Key=LaunchedBy,Value=ec2-hetero-fleet.sh},{Key=RunId,Value=$RUN_ID},{Key=LaunchIndex,Value=$ec2_num}]" \
                    --query 'Instances[0].InstanceId' --output text); then
                break
            fi
            sleep 5
        done
        if [[ -z "$INSTANCE_ID" ]]; then
            INSTANCE_ID=$(aws_cmd ec2 describe-instances \
                --filters "Name=tag:RunId,Values=$RUN_ID" "Name=tag:LaunchIndex,Values=$ec2_num" \
                          "Name=tag:Project,Values=LICHEN" \
                          "Name=tag:LaunchedBy,Values=ec2-hetero-fleet.sh" \
                --query 'Reservations[0].Instances[0].InstanceId' --output text)
        fi
        if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
            log_error "Failed to launch or reconcile EC2 instance $ec2_num"
            exit 1
        fi

        INSTANCE_IDS+=("$INSTANCE_ID")
        log_info "  EC2 $ec2_num: $INSTANCE_ID (Zephyr nodes $NODE_OFFSET-$((NODE_OFFSET + NODES_THIS - 1)))"
        NODE_OFFSET=$((NODE_OFFSET + NODES_THIS))
    done

    if [[ ${#INSTANCE_IDS[@]} -ne $NUM_EC2 ]]; then
        log_error "Launched ${#INSTANCE_IDS[@]} of $NUM_EC2 required instances"
        exit 1
    fi

    # Wait for instances
    log_info "Waiting for EC2 instances..."
    aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"
    aws_cmd ec2 wait instance-status-ok --instance-ids "${INSTANCE_IDS[@]}"

    # Get IPs and wait for Renode
    INSTANCE_IPS=()
    EC2_INDEX=0
    for id in "${INSTANCE_IDS[@]}"; do
        IP=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        INSTANCE_IPS+=("$IP")
        authenticate_ec2_host "$id" "$IP"

        READY=0
        for attempt in {1..30}; do
            if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=5 ec2-user@"$IP" \
                "test -x /usr/local/bin/renode" 2>/dev/null; then
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
        scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" \
            -o ConnectTimeout=15 \
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

        ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash -s << REMOTE
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

    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 /usr/local/bin/renode --disable-xwt --console --port \$((50000 + NID)) node-\$NID.resc > /tmp/renode-\$NID.log 2>&1 &
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
        ssh "${SSH_OPTS[@]}" -o ConnectTimeout=15 \
            ec2-user@"$IP" \
             "find /tmp -maxdepth 1 -type f \( -name 'zephyr-*' -o -name 'renode-*' \) -print -exec cat {} \\;" \
             > "$RESULTS_DIR/zephyr-remote-$EC2_INDEX.log" 2>&1 || true
        scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -q \
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
    exit 1
elif [[ $TOTAL_RX -lt $((TOTAL_TX / 10)) ]]; then
    log_warn "Low reception rate - possible interop issues"
    cd "$PROJECT_ROOT"
    bd create "Hetero mesh: low RX rate ($TOTAL_RX/$TOTAL_TX) - check interop" \
        --type bug --priority P1 2>/dev/null || true
else
    log_ok "Cross-implementation communication verified!"
fi
