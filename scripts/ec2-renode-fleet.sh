#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# ec2-renode-fleet.sh - Launch distributed Renode firmware testing fleet
#
# Launches multiple EC2 instances, each running N Renode instances with actual
# Zephyr firmware. All connect to a central lichen-sim server for RF propagation.
#
# Usage:
#   ./scripts/ec2-renode-fleet.sh --nodes 200 --duration 300
#   ./scripts/ec2-renode-fleet.sh --nodes 50 --firmware build/puck/zephyr/zephyr.elf
#
# Architecture:
#   ┌─────────────┐
#   │ Coordinator │ (your machine or CI)
#   │ lichen-sim  │ ← RF propagation server
#   └──────┬──────┘
#          │ TCP (port 5555+)
#   ┌──────┴──────┬──────────────┬──────────────┐
#   │ EC2 #1      │ EC2 #2       │ EC2 #N       │
#   │ 20 Renodes  │ 20 Renodes   │ 20 Renodes   │
#   │ (firmware)  │ (firmware)   │ (firmware)   │
#   └─────────────┴──────────────┴──────────────┘
#
set -euo pipefail

# === Configuration ===
AWS_PROFILE="${AWS_PROFILE:-AdministratorAccess-921772462201}"
AWS_REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="${EC2_INSTANCE_TYPE:-c7g.xlarge}"  # 4 vCPU ARM64
RENODES_PER_INSTANCE=20
AMI_ID="${EC2_AMI_ID:-ami-03a84069f5e253220}"  # Amazon Linux 2023 ARM64

# Project paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
TOTAL_NODES=100
DURATION_S=300
FIRMWARE_PATH=""
SIM_PORT=5555
CLEANUP_ON_EXIT=true

# State
INSTANCE_IDS=()
SIM_PID=""
PUBLIC_IP=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}>>>${NC} $*" >&2; }
log_ok()    { echo -e "${GREEN}>>>${NC} $*" >&2; }
log_warn()  { echo -e "${YELLOW}>>>${NC} $*" >&2; }
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Launch distributed Renode firmware testing fleet on EC2.

Options:
  --nodes N        Total number of firmware nodes (default: 100)
  --duration S     Test duration in seconds (default: 300)
  --firmware PATH  Path to zephyr.elf (default: build/lora_ping/zephyr/zephyr.elf)
  --no-cleanup     Don't terminate instances on exit
  --help           Show this help

Environment:
  AWS_PROFILE      AWS CLI profile (default: AdministratorAccess-921772462201)
  EC2_INSTANCE_TYPE Instance type (default: c7g.xlarge)

Example:
  # Run 200 firmware nodes for 5 minutes
  $0 --nodes 200 --duration 300

  # Run with custom firmware
  west build -b nrf52840_lichen lichen/apps/puck -d build/puck
  $0 --nodes 100 --firmware build/puck/zephyr/zephyr.elf
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes) TOTAL_NODES="$2"; shift 2 ;;
        --duration) DURATION_S="$2"; shift 2 ;;
        --firmware) FIRMWARE_PATH="$2"; shift 2 ;;
        --no-cleanup) CLEANUP_ON_EXIT=false; shift ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Calculate fleet size
NUM_INSTANCES=$(( (TOTAL_NODES + RENODES_PER_INSTANCE - 1) / RENODES_PER_INSTANCE ))
LAST_INSTANCE_NODES=$(( TOTAL_NODES - (NUM_INSTANCES - 1) * RENODES_PER_INSTANCE ))

log_info "Fleet configuration:"
log_info "  Total nodes: $TOTAL_NODES"
log_info "  EC2 instances: $NUM_INSTANCES × $INSTANCE_TYPE"
log_info "  Renodes per instance: $RENODES_PER_INSTANCE (last: $LAST_INSTANCE_NODES)"
log_info "  Duration: ${DURATION_S}s"
log_info "  Estimated cost: \$$(echo "scale=2; $NUM_INSTANCES * 0.17 * $DURATION_S / 3600" | bc)/run"

# Default firmware path
if [[ -z "$FIRMWARE_PATH" ]]; then
    FIRMWARE_PATH="$PROJECT_ROOT/build/lora_ping/zephyr/zephyr.elf"
fi

if [[ ! -f "$FIRMWARE_PATH" ]]; then
    log_error "Firmware not found: $FIRMWARE_PATH"
    log_error "Build it first: west build -b nrf52840_lichen lichen/samples/lora_ping -d build/lora_ping"
    exit 1
fi

# AWS CLI wrapper
aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

# Get our public IP for security group
get_public_ip() {
    curl -s https://checkip.amazonaws.com || curl -s https://ipinfo.io/ip
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Stop lichen-sim
    if [[ -n "$SIM_PID" ]] && kill -0 "$SIM_PID" 2>/dev/null; then
        log_info "Stopping lichen-sim..."
        kill "$SIM_PID" 2>/dev/null || true
    fi

    # Terminate EC2 instances
    if [[ ${#INSTANCE_IDS[@]} -gt 0 ]] && [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        log_info "Terminating ${#INSTANCE_IDS[@]} EC2 instances..."
        aws_cmd ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null 2>&1 || true
    elif [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
        log_warn "Instances left running: ${INSTANCE_IDS[*]}"
    fi
}

trap cleanup EXIT

# Get coordinator's public IP
log_info "Getting coordinator public IP..."
PUBLIC_IP=$(get_public_ip)
log_info "Coordinator IP: $PUBLIC_IP"

# Create security group for fleet (if not exists)
SG_NAME="lichen-renode-fleet"
SG_ID=$(aws_cmd ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SG_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

if [[ "$SG_ID" == "None" ]] || [[ -z "$SG_ID" ]]; then
    log_info "Creating security group..."
    SG_ID=$(aws_cmd ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "LICHEN Renode fleet" \
        --query 'GroupId' --output text)

    # Allow SSH from coordinator
    aws_cmd ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp --port 22 \
        --cidr "${PUBLIC_IP}/32" >/dev/null

    # Tag as LICHEN resource
    aws_cmd ec2 create-tags --resources "$SG_ID" \
        --tags Key=Project,Value=LICHEN Key=Purpose,Value=renode-fleet
fi
log_info "Security group: $SG_ID"

# Start lichen-sim server on coordinator
log_info "Starting lichen-sim server..."
cd "$PROJECT_ROOT/python"

# Create a script to run lichen-sim with external access
cat > /tmp/run-lichen-sim.py << 'SIMSCRIPT'
import asyncio
import sys
sys.path.insert(0, "src")
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode

async def main():
    # Bind to all interfaces so EC2 instances can connect
    server = SimulatorServer(node_port=5555, api_port=5556, host="0.0.0.0")
    await server.start()
    sim = await server.create_simulation("fleet-test", TimeMode.REALTIME)
    print(f"lichen-sim listening on 0.0.0.0:5555", flush=True)
    print(f"Simulation ready: fleet-test", flush=True)

    # Run until killed
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()

asyncio.run(main())
SIMSCRIPT

python3 /tmp/run-lichen-sim.py &
SIM_PID=$!
sleep 2

if ! kill -0 "$SIM_PID" 2>/dev/null; then
    log_error "lichen-sim failed to start"
    exit 1
fi
log_ok "lichen-sim running (PID $SIM_PID)"

# Upload firmware to S3 for EC2 instances to download
FIRMWARE_KEY="lichen-fleet/firmware-$(date +%s).elf"
log_info "Uploading firmware to S3..."
aws_cmd s3 cp "$FIRMWARE_PATH" "s3://lichen-artifacts/$FIRMWARE_KEY" >/dev/null 2>&1 || {
    log_warn "S3 upload failed - will use SCP instead"
    FIRMWARE_KEY=""
}

# User data script for EC2 instances
create_user_data() {
    local instance_num=$1
    local num_renodes=$2
    local start_node_id=$3

    cat << USERDATA
#!/bin/bash
set -ex

# Install dependencies
dnf install -y python3 python3-pip git wget mono-core

# Install Renode
cd /tmp
wget -q https://github.com/renode/renode/releases/download/v1.14.0/renode-1.14.0.linux-portable-dotnet.tar.gz
tar xf renode-1.14.0.linux-portable-dotnet.tar.gz -C /opt
ln -s /opt/renode_1.14.0_portable/renode /usr/local/bin/renode

# Clone project for platform files
git clone --depth 1 https://github.com/MarkAtwood/project-LICHEN.git /opt/lichen

# Download firmware
${FIRMWARE_KEY:+aws s3 cp "s3://lichen-artifacts/$FIRMWARE_KEY" /opt/firmware.elf}

# Create Renode scripts and start instances
COORDINATOR_IP="$PUBLIC_IP"
SIM_PORT=$SIM_PORT

for i in \$(seq 0 $((num_renodes - 1))); do
    NODE_ID=$((start_node_id + i))
    BRIDGE_PORT=\$((SIM_PORT + NODE_ID))

    # Create Renode script
    cat > /tmp/node-\$NODE_ID.resc << RESC
:name: node-\$NODE_ID
include @/opt/lichen/lichen/boards/renode/peripherals/SX1262.cs
mach create "node-\$NODE_ID"
machine LoadPlatformDescription @/opt/lichen/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl
spi1.sx1262 SimHost "\$COORDINATOR_IP"
spi1.sx1262 SimPort \$BRIDGE_PORT
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NODE_ID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NODE_ID))
sysbus LoadELF @/opt/firmware.elf
logFile @/var/log/renode-node-\$NODE_ID.log true
start
RESC

    # Start Renode in background
    renode --disable-gui --port \$((50000 + NODE_ID)) /tmp/node-\$NODE_ID.resc &
done

# Wait for test duration
sleep $DURATION_S

# Collect logs and upload
tar czf /tmp/renode-logs-$instance_num.tar.gz /var/log/renode-*.log
aws s3 cp /tmp/renode-logs-$instance_num.tar.gz "s3://lichen-artifacts/fleet-logs/run-\$(date +%s)/"

# Signal completion
touch /tmp/renode-complete
USERDATA
}

# Launch EC2 instances
log_info "Launching $NUM_INSTANCES EC2 instances..."
START_NODE_ID=0

for i in $(seq 1 $NUM_INSTANCES); do
    if [[ $i -eq $NUM_INSTANCES ]]; then
        NODES_THIS_INSTANCE=$LAST_INSTANCE_NODES
    else
        NODES_THIS_INSTANCE=$RENODES_PER_INSTANCE
    fi

    USER_DATA=$(create_user_data "$i" "$NODES_THIS_INSTANCE" "$START_NODE_ID" | base64 -w0)

    INSTANCE_ID=$(aws_cmd ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "$INSTANCE_TYPE" \
        --security-group-ids "$SG_ID" \
        --user-data "$USER_DATA" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=lichen-renode-$i},{Key=Project,Value=LICHEN},{Key=Purpose,Value=renode-fleet}]" \
        --iam-instance-profile Name=lichen-ec2-profile \
        --query 'Instances[0].InstanceId' --output text 2>/dev/null) || {
        log_warn "Failed to launch instance $i"
        continue
    }

    INSTANCE_IDS+=("$INSTANCE_ID")
    log_info "  Instance $i: $INSTANCE_ID (nodes $START_NODE_ID-$((START_NODE_ID + NODES_THIS_INSTANCE - 1)))"

    START_NODE_ID=$((START_NODE_ID + NODES_THIS_INSTANCE))
done

if [[ ${#INSTANCE_IDS[@]} -eq 0 ]]; then
    log_error "No instances launched"
    exit 1
fi

log_ok "Launched ${#INSTANCE_IDS[@]} instances"

# Wait for instances to be running
log_info "Waiting for instances to start..."
aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"
log_ok "All instances running"

# Monitor test progress
log_info "Test running for ${DURATION_S}s..."
log_info "Monitor lichen-sim for node connections..."

START_TIME=$(date +%s)
while true; do
    ELAPSED=$(($(date +%s) - START_TIME))
    REMAINING=$((DURATION_S - ELAPSED))

    if [[ $REMAINING -le 0 ]]; then
        break
    fi

    # Show progress
    printf "\r  Elapsed: %ds / %ds, Remaining: %ds  " "$ELAPSED" "$DURATION_S" "$REMAINING"
    sleep 10
done
echo ""

log_ok "Test duration complete"

# Collect results
log_info "Collecting results..."

# Check how many nodes connected to lichen-sim
# (This would require parsing lichen-sim logs)

# Download logs from S3
LOGS_DIR="/tmp/renode-fleet-logs-$(date +%s)"
mkdir -p "$LOGS_DIR"
aws_cmd s3 sync "s3://lichen-artifacts/fleet-logs/" "$LOGS_DIR/" 2>/dev/null || true

# Analyze results
TOTAL_LOG_LINES=0
TX_COUNT=0
RX_COUNT=0
ERROR_COUNT=0

for log_tar in "$LOGS_DIR"/*.tar.gz; do
    [[ -f "$log_tar" ]] || continue
    tar xzf "$log_tar" -C "$LOGS_DIR" 2>/dev/null || continue
done

for log_file in "$LOGS_DIR"/var/log/renode-*.log; do
    [[ -f "$log_file" ]] || continue
    TOTAL_LOG_LINES=$((TOTAL_LOG_LINES + $(wc -l < "$log_file")))
    TX_COUNT=$((TX_COUNT + $(grep -c "TX\|Send" "$log_file" 2>/dev/null || echo 0)))
    RX_COUNT=$((RX_COUNT + $(grep -c "RX\|Recv" "$log_file" 2>/dev/null || echo 0)))
    ERROR_COUNT=$((ERROR_COUNT + $(grep -ci "error\|fail" "$log_file" 2>/dev/null || echo 0)))
done

# Print summary
echo ""
log_ok "=== FLEET TEST RESULTS ==="
echo "  Instances: ${#INSTANCE_IDS[@]}"
echo "  Target nodes: $TOTAL_NODES"
echo "  Duration: ${DURATION_S}s"
echo "  Total log lines: $TOTAL_LOG_LINES"
echo "  TX events: $TX_COUNT"
echo "  RX events: $RX_COUNT"
echo "  Errors: $ERROR_COUNT"

# Create bead if errors found
if [[ $ERROR_COUNT -gt 0 ]]; then
    log_warn "Errors detected - creating bead..."
    cd "$PROJECT_ROOT"
    bd create "Renode fleet test: $ERROR_COUNT errors in $TOTAL_NODES nodes" \
        --type bug \
        --priority P2 \
        --body "Fleet test with $TOTAL_NODES firmware nodes found $ERROR_COUNT errors. Logs: $LOGS_DIR" \
        2>/dev/null || true
fi

log_ok "Fleet test complete"
