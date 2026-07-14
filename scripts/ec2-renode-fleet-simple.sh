#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# ec2-renode-fleet-simple.sh - Simple distributed Renode fleet (no S3 required)
#
# Launches EC2 instances, SCPs firmware to each, runs Renode with actual Zephyr
# firmware connected to local lichen-sim.
#
# Usage:
#   ./scripts/ec2-renode-fleet-simple.sh 50    # 50 firmware nodes
#   ./scripts/ec2-renode-fleet-simple.sh 200   # 200 firmware nodes
#
set -euo pipefail

TOTAL_NODES="${1:-50}"
DURATION_S="${2:-300}"
RENODES_PER_INSTANCE=20

# Calculate fleet size
NUM_INSTANCES=$(( (TOTAL_NODES + RENODES_PER_INSTANCE - 1) / RENODES_PER_INSTANCE ))

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
log_info()  { echo -e "\033[0;34m>>>\033[0m $*" >&2; }
log_ok()    { echo -e "\033[0;32m>>>\033[0m $*" >&2; }
log_error() { echo -e "\033[0;31mERROR:\033[0m $*" >&2; }

# Check firmware exists
FIRMWARE="$PROJECT_ROOT/build/lora_ping/zephyr/zephyr.elf"
if [[ ! -f "$FIRMWARE" ]]; then
    log_error "Firmware not found. Build it first:"
    log_error "  west build -b nrf52840_lichen lichen/samples/lora_ping -d build/lora_ping"
    exit 1
fi

log_info "=== LICHEN Renode Fleet ==="
log_info "Total firmware nodes: $TOTAL_NODES"
log_info "EC2 instances: $NUM_INSTANCES × c7g.xlarge"
log_info "Duration: ${DURATION_S}s"
log_info "Estimated cost: \$$(echo "scale=2; $NUM_INSTANCES * 0.17 * $DURATION_S / 3600" | bc)"
echo ""

# AWS config
AWS_PROFILE="${AWS_PROFILE:-AdministratorAccess-921772462201}"
AWS_REGION="us-east-2"
AMI_ID="ami-03a84069f5e253220"  # Amazon Linux 2023 ARM64
KEY_NAME="lichen-ct4d-20260702232050"

aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

# Get our public IP
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com)
log_info "Coordinator IP: $PUBLIC_IP"

# State for cleanup
INSTANCE_IDS=()
SIM_PID=""

cleanup() {
    log_info "Cleaning up..."
    [[ -n "$SIM_PID" ]] && kill "$SIM_PID" 2>/dev/null || true
    if [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
        log_info "Terminating ${#INSTANCE_IDS[@]} instances..."
        aws_cmd ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Start lichen-sim bound to all interfaces
log_info "Starting lichen-sim server..."
cd "$PROJECT_ROOT/python"
uv run python3 -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode

async def main():
    server = SimulatorServer(node_port=5555, api_port=5556, host='0.0.0.0')
    await server.start()
    sim = await server.create_simulation('fleet', TimeMode.REALTIME)
    print('lichen-sim ready on 0.0.0.0:5555', flush=True)
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
" &
SIM_PID=$!
sleep 3

if ! kill -0 "$SIM_PID" 2>/dev/null; then
    log_error "lichen-sim failed to start"
    exit 1
fi
log_ok "lichen-sim running (PID $SIM_PID)"

# Find or create security group
SG_ID=$(aws_cmd ec2 describe-security-groups \
    --filters "Name=group-name,Values=lichen-renode-fleet" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

if [[ "$SG_ID" == "None" ]]; then
    log_info "Creating security group..."
    SG_ID=$(aws_cmd ec2 create-security-group \
        --group-name "lichen-renode-fleet" \
        --description "LICHEN Renode fleet" \
        --query 'GroupId' --output text)

    aws_cmd ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" --protocol tcp --port 22 --cidr "0.0.0.0/0" >/dev/null

    aws_cmd ec2 create-tags --resources "$SG_ID" \
        --tags Key=Project,Value=LICHEN
fi

# Launch instances
log_info "Launching $NUM_INSTANCES EC2 instances..."
NODE_OFFSET=0

for i in $(seq 1 "$NUM_INSTANCES"); do
    if [[ $i -eq $NUM_INSTANCES ]]; then
        NODES_THIS=$(( TOTAL_NODES - (NUM_INSTANCES - 1) * RENODES_PER_INSTANCE ))
    else
        NODES_THIS=$RENODES_PER_INSTANCE
    fi

    # User data to install Renode
    USER_DATA=$(cat << 'EOF' | base64 -w0
#!/bin/bash
dnf install -y python3 wget mono-core
cd /tmp
wget -q https://github.com/renode/renode/releases/download/v1.14.0/renode-1.14.0.linux-portable-dotnet.tar.gz
tar xf renode-1.14.0.linux-portable-dotnet.tar.gz -C /opt
ln -s /opt/renode_1.14.0_portable/renode /usr/local/bin/renode
touch /tmp/renode-ready
EOF
)

    INSTANCE_ID=$(aws_cmd ec2 run-instances \
        --image-id "$AMI_ID" \
        --instance-type "c7g.xlarge" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_ID" \
        --user-data "$USER_DATA" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=renode-$i},{Key=Project,Value=LICHEN}]" \
        --query 'Instances[0].InstanceId' --output text)

    INSTANCE_IDS+=("$INSTANCE_ID")
    log_info "  Instance $i: $INSTANCE_ID (nodes $NODE_OFFSET-$((NODE_OFFSET + NODES_THIS - 1)))"
    NODE_OFFSET=$((NODE_OFFSET + NODES_THIS))
done

log_ok "Launched ${#INSTANCE_IDS[@]} instances"

# Wait for instances
log_info "Waiting for instances to be ready..."
aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"

# Get public IPs
declare -A INSTANCE_IPS
for id in "${INSTANCE_IDS[@]}"; do
    IP=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    INSTANCE_IPS[$id]=$IP
done

# Wait for user-data to complete (Renode installed)
log_info "Waiting for Renode installation on instances..."
for id in "${INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$id]}"
    for attempt in {1..30}; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ec2-user@"$IP" \
            "test -f /tmp/renode-ready" 2>/dev/null; then
            break
        fi
        sleep 10
    done
done
log_ok "All instances ready"

# SCP firmware and platform files to each instance
log_info "Uploading firmware and platform files..."
for id in "${INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$id]}"
    scp -o StrictHostKeyChecking=no -q \
        "$FIRMWARE" \
        "$PROJECT_ROOT/lichen/boards/renode/peripherals/SX1262.cs" \
        "$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl" \
        ec2-user@"$IP":/tmp/ &
done
wait
log_ok "Files uploaded"

# Start Renode instances on each EC2
log_info "Starting Renode instances..."
NODE_ID=0
INSTANCE_NUM=0

for id in "${INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$id]}"
    INSTANCE_NUM=$((INSTANCE_NUM + 1))

    if [[ $INSTANCE_NUM -eq $NUM_INSTANCES ]]; then
        NODES_THIS=$(( TOTAL_NODES - (NUM_INSTANCES - 1) * RENODES_PER_INSTANCE ))
    else
        NODES_THIS=$RENODES_PER_INSTANCE
    fi

    # Create and run Renode instances on this EC2
    ssh -o StrictHostKeyChecking=no ec2-user@"$IP" bash -s << REMOTE_SCRIPT &
cd /tmp
for i in \$(seq 0 $((NODES_THIS - 1))); do
    NID=\$((${NODE_ID} + i))
    BRIDGE_PORT=\$((5555 + NID))

    cat > node-\$NID.resc << RESC
:name: node-\$NID
include @/tmp/SX1262.cs
mach create "node-\$NID"
machine LoadPlatformDescription @/tmp/nrf52840_lichen.repl
spi1.sx1262 SimHost "$PUBLIC_IP"
spi1.sx1262 SimPort \$BRIDGE_PORT
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NID))
sysbus LoadELF @/tmp/zephyr.elf
logFile @/tmp/node-\$NID.log true
start
RESC

    renode --disable-gui --port \$((50000 + NID)) node-\$NID.resc > /dev/null 2>&1 &
done
REMOTE_SCRIPT

    NODE_ID=$((NODE_ID + NODES_THIS))
done

wait
log_ok "All Renode instances started"

# Monitor test
log_info "Test running for ${DURATION_S}s..."
sleep "$DURATION_S"

# Collect results
log_info "Collecting results..."
RESULTS_DIR="/tmp/renode-fleet-$(date +%s)"
mkdir -p "$RESULTS_DIR"

for id in "${INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$id]}"
    scp -o StrictHostKeyChecking=no -q \
        ec2-user@"$IP":/tmp/node-*.log "$RESULTS_DIR/" 2>/dev/null || true
done

# Analyze
TX_COUNT=$(grep -l "TX\|Send" "$RESULTS_DIR"/*.log 2>/dev/null | wc -l || echo 0)
RX_COUNT=$(grep -l "RX\|Recv" "$RESULTS_DIR"/*.log 2>/dev/null | wc -l || echo 0)
ERROR_COUNT=$(grep -li "error\|fail" "$RESULTS_DIR"/*.log 2>/dev/null | wc -l || echo 0)

echo ""
log_ok "=== FLEET TEST RESULTS ==="
echo "  Total nodes: $TOTAL_NODES"
echo "  EC2 instances: ${#INSTANCE_IDS[@]}"
echo "  Nodes with TX: $TX_COUNT"
echo "  Nodes with RX: $RX_COUNT"
echo "  Nodes with errors: $ERROR_COUNT"
echo "  Logs: $RESULTS_DIR"

if [[ $ERROR_COUNT -gt 0 ]]; then
    log_error "$ERROR_COUNT nodes had errors - check logs"
    cd "$PROJECT_ROOT"
    bd create "Renode fleet: $ERROR_COUNT/$TOTAL_NODES nodes had errors" \
        --type bug --priority P2 2>/dev/null || true
fi

log_ok "Done"
