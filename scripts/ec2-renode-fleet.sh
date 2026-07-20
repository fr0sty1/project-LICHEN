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
AWS_PROFILE="${AWS_PROFILE:-personal}"
AWS_REGION="${AWS_REGION:-us-west-2}"
EXPECTED_AWS_ACCOUNT="210337117346"
INSTANCE_TYPE="${EC2_INSTANCE_TYPE:-c7g.xlarge}"  # 4 vCPU ARM64
RENODES_PER_INSTANCE=20
AMI_ID="${EC2_AMI_ID:-ami-0764d1b512e22671f}"  # LICHEN ARM64 fleet runtime
KEY_NAME="${EC2_KEY_NAME:-markatwood}"
EC2_SSH_KEY="${EC2_SSH_KEY:-$HOME/.ssh/id_ed25519}"

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
INSTANCE_NUMBERS=()
SIM_PID=""
PUBLIC_IP=""
SG_ID=""
RUN_ID="$(date +%s)-$$-$RANDOM"
METRICS_PATH="/tmp/lichen-renode-metrics-$$.json"
TUNNEL_PIDS=()
KNOWN_HOSTS=$(mktemp "${TMPDIR:-/tmp}/lichen-renode-known-hosts.XXXXXX")
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
  AWS_PROFILE      AWS CLI profile (default: personal)
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
    log_error "Build it first for t_echo/nrf52840 with the tracked Renode overlay and config"
    exit 1
fi

if nm -a "$FIRMWARE_PATH" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPIM|spi_nrfx_spim\.c)$' >/dev/null; then
    log_error "Firmware uses SPIM, which Renode 1.16.1 cannot run with this platform model"
    log_error "Rebuild with renode_console.overlay to select nordic,nrf-spi"
    exit 1
fi
if ! nm -a "$FIRMWARE_PATH" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPI|spi_nrfx_spi\.c)$' >/dev/null; then
    log_error "Firmware does not contain the required legacy nRF SPI driver"
    log_error "Rebuild with renode_console.overlay"
    exit 1
fi

# AWS CLI wrapper
aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

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

# Get our public IP for security group
get_public_ip() {
    curl -s https://checkip.amazonaws.com || curl -s https://ipinfo.io/ip
}

# Cleanup function
cleanup() {
    local original_status=$?
    local cleanup_failed=false
    trap - EXIT
    log_info "Cleaning up..."

    reconciled_ids=$(aws_cmd ec2 describe-instances \
        --filters "Name=tag:RunId,Values=$RUN_ID" \
                  "Name=tag:Project,Values=LICHEN" \
                  "Name=tag:LaunchedBy,Values=ec2-renode-fleet.sh" \
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
                --filters "Name=group-name,Values=lichen-renode-fleet-$RUN_ID" \
                          "Name=tag:RunId,Values=$RUN_ID" \
                          "Name=tag:Project,Values=LICHEN" \
                          "Name=tag:LaunchedBy,Values=ec2-renode-fleet.sh" \
                --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null); then
            SG_ID=""
            cleanup_failed=true
        fi
        [[ "$SG_ID" == "None" ]] && SG_ID=""
    fi

    # Stop lichen-sim
    if [[ -n "$SIM_PID" ]] && kill -0 "$SIM_PID" 2>/dev/null; then
        log_info "Stopping lichen-sim..."
        kill "$SIM_PID" 2>/dev/null || true
    fi
    for pid in "${TUNNEL_PIDS[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Terminate EC2 instances
    ownership_ok=true
    for id in "${INSTANCE_IDS[@]-}"; do
        read -r project launched_by run_id <<< "$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].[Tags[?Key==`Project`].Value|[0],Tags[?Key==`LaunchedBy`].Value|[0],Tags[?Key==`RunId`].Value|[0]]' \
            --output text 2>/dev/null)" || ownership_ok=false
        if [[ "$project" != "LICHEN" || "$launched_by" != "ec2-renode-fleet.sh" || "$run_id" != "$RUN_ID" ]]; then
            log_error "Refusing to terminate unverified instance $id"
            ownership_ok=false
        fi
    done
    if [[ ${#INSTANCE_IDS[@]} -gt 0 ]] && [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        if [[ "$ownership_ok" != "true" ]]; then
            cleanup_failed=true
        else
            log_info "Terminating ${#INSTANCE_IDS[@]} EC2 instances..."
            if ! aws_cmd ec2 terminate-instances --instance-ids "${INSTANCE_IDS[@]}" >/dev/null; then
                log_error "Failed to request instance termination: ${INSTANCE_IDS[*]}"
                cleanup_failed=true
            elif ! aws_cmd ec2 wait instance-terminated --instance-ids "${INSTANCE_IDS[@]}"; then
                log_error "Instances did not reach terminated state: ${INSTANCE_IDS[*]}"
                cleanup_failed=true
            fi
        fi
    elif [[ ${#INSTANCE_IDS[@]} -gt 0 ]]; then
        log_warn "Instances left running: ${INSTANCE_IDS[*]}"
    fi

    if [[ -n "$SG_ID" && ( "$CLEANUP_ON_EXIT" == "true" || ${#INSTANCE_IDS[@]} -eq 0 ) && \
          "$cleanup_failed" == "false" ]]; then
        read -r sg_project sg_launched_by sg_run_id <<< "$(aws_cmd ec2 describe-security-groups --group-ids "$SG_ID" \
            --query 'SecurityGroups[0].[Tags[?Key==`Project`].Value|[0],Tags[?Key==`LaunchedBy`].Value|[0],Tags[?Key==`RunId`].Value|[0]]' \
            --output text 2>/dev/null)" || cleanup_failed=true
        if [[ "$sg_project" != "LICHEN" || "$sg_launched_by" != "ec2-renode-fleet.sh" || "$sg_run_id" != "$RUN_ID" ]]; then
            log_error "Refusing to delete unverified security group $SG_ID"
            cleanup_failed=true
        fi
    fi
    if [[ -n "$SG_ID" && ( "$CLEANUP_ON_EXIT" == "true" || ${#INSTANCE_IDS[@]} -eq 0 ) && \
          "$cleanup_failed" == "false" ]]; then
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

# Get coordinator's public IP
log_info "Getting coordinator public IP..."
PUBLIC_IP=$(get_public_ip)
log_info "Coordinator IP: $PUBLIC_IP"

SG_NAME="lichen-renode-fleet-$RUN_ID"
log_info "Creating per-run security group..."
if ! SG_ID=$(aws_cmd ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "LICHEN Renode fleet" \
        --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=LICHEN},{Key=Purpose,Value=renode-fleet},{Key=LaunchedBy,Value=ec2-renode-fleet.sh},{Key=RunId,Value=$RUN_ID}]" \
        --query 'GroupId' --output text); then
    SG_ID=$(aws_cmd ec2 describe-security-groups \
        --filters "Name=group-name,Values=$SG_NAME" "Name=tag:RunId,Values=$RUN_ID" \
                  "Name=tag:Project,Values=LICHEN" \
                  "Name=tag:LaunchedBy,Values=ec2-renode-fleet.sh" \
        --query 'SecurityGroups[0].GroupId' --output text)
fi
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
    log_error "Could not create or reconcile security group for run $RUN_ID"
    exit 1
fi
aws_cmd ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --protocol tcp --port 22 \
    --cidr "${PUBLIC_IP}/32" >/dev/null
log_info "Security group: $SG_ID"

# Start lichen-sim server on coordinator
log_info "Starting lichen-sim server..."
cd "$PROJECT_ROOT/python"

# Create a script to run lichen-sim with external access
cat > /tmp/run-lichen-sim.py << 'SIMSCRIPT'
import asyncio
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, "src")
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode

async def main():
    server = SimulatorServer(node_port=5555, api_port=5556, bind_host="127.0.0.1")
    await server.start()
    sim = await server.create_simulation("fleet-test", TimeMode.REALTIME)
    metrics_path = Path(os.environ["LICHEN_METRICS_PATH"])
    print(f"lichen-sim listening on 127.0.0.1:5555", flush=True)
    print(f"Simulation ready: fleet-test", flush=True)

    # Run until killed
    try:
        while True:
            metrics_path.write_text(json.dumps(sim.metrics.snapshot()))
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()

asyncio.run(main())
SIMSCRIPT

LICHEN_METRICS_PATH="$METRICS_PATH" python3 /tmp/run-lichen-sim.py &
SIM_PID=$!
sleep 2

if ! kill -0 "$SIM_PID" 2>/dev/null; then
    log_error "lichen-sim failed to start"
    exit 1
fi
log_ok "lichen-sim running (PID $SIM_PID)"

# User data script for EC2 instances
create_user_data() {
    local instance_num=$1
    local num_renodes=$2
    local start_node_id=$3

    cat << USERDATA
#!/bin/bash
set -ex

test -x /usr/local/bin/renode

# Inputs are copied together so firmware and platform files come from one checkout.
while [[ ! -f /tmp/firmware.elf || ! -f /tmp/SX1262.cs || ! -f /tmp/nrf52840_lichen.repl ]]; do sleep 2; done
mkdir -p /opt/lichen/lichen/boards/renode/peripherals
mkdir -p /opt/lichen/lichen/boards/renode/nrf52840_lichen/support
mv /tmp/SX1262.cs /opt/lichen/lichen/boards/renode/peripherals/SX1262.cs
mv /tmp/nrf52840_lichen.repl /opt/lichen/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl
mv /tmp/firmware.elf /opt/firmware.elf

# Create Renode scripts and start instances
COORDINATOR_HOST="127.0.0.1"
SIM_PORT=$SIM_PORT
RENODE_PIDS=()

for i in \$(seq 0 $((num_renodes - 1))); do
    NODE_ID=$((start_node_id + i))

    # Create Renode script
    cat > /tmp/node-\$NODE_ID.resc << RESC
:name: node-\$NODE_ID
include @/opt/lichen/lichen/boards/renode/peripherals/SX1262.cs
mach create "node-\$NODE_ID"
machine LoadPlatformDescription @/opt/lichen/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl
spi1.sx1262 SimHost "\$COORDINATOR_HOST"
spi1.sx1262 SimPort \$SIM_PORT
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NODE_ID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NODE_ID))
sysbus LoadELF @/opt/firmware.elf
logFile @/var/log/renode-node-\$NODE_ID.log true
uart0 CreateFileBackend @/var/log/uart-node-\$NODE_ID.log true
start
RESC

    # Start Renode in background
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 /usr/local/bin/renode --disable-gui --port \$((50000 + NODE_ID)) /tmp/node-\$NODE_ID.resc &
    RENODE_PIDS+=(\$!)
done

# Wait for test duration
sleep $DURATION_S

for pid in "\${RENODE_PIDS[@]}"; do
    kill -0 "\$pid"
done
shopt -s nullglob
RENODE_LOGS=(/var/log/renode-node-*.log)
UART_LOGS=(/var/log/uart-node-*.log)
[[ \${#RENODE_LOGS[@]} -eq $num_renodes ]]
[[ \${#UART_LOGS[@]} -eq $num_renodes ]]

# Collect logs for the coordinator
tar czf /tmp/renode-logs-$instance_num.tar.gz "\${RENODE_LOGS[@]}" "\${UART_LOGS[@]}"

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

    USER_DATA=$(create_user_data "$i" "$NODES_THIS_INSTANCE" "$START_NODE_ID")

    INSTANCE_ID=""
    for _ in {1..3}; do
        if INSTANCE_ID=$(aws_cmd ec2 run-instances \
                --client-token "$RUN_ID-$i" \
                --image-id "$AMI_ID" \
                --instance-type "$INSTANCE_TYPE" \
                --key-name "$KEY_NAME" \
                --security-group-ids "$SG_ID" \
                --user-data "$USER_DATA" \
                --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=lichen-renode-$i},{Key=Project,Value=LICHEN},{Key=Purpose,Value=renode-fleet},{Key=LaunchedBy,Value=ec2-renode-fleet.sh},{Key=RunId,Value=$RUN_ID},{Key=LaunchIndex,Value=$i}]" \
                --query 'Instances[0].InstanceId' --output text 2>/dev/null); then
            break
        fi
        sleep 5
    done
    if [[ -z "$INSTANCE_ID" ]]; then
        INSTANCE_ID=$(aws_cmd ec2 describe-instances \
            --filters "Name=tag:RunId,Values=$RUN_ID" "Name=tag:LaunchIndex,Values=$i" \
                      "Name=tag:Project,Values=LICHEN" \
                      "Name=tag:LaunchedBy,Values=ec2-renode-fleet.sh" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text)
    fi
    if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
        log_error "Failed to launch or reconcile instance $i"
        exit 1
    fi

    INSTANCE_IDS+=("$INSTANCE_ID")
    INSTANCE_NUMBERS+=("$i")
    log_info "  Instance $i: $INSTANCE_ID (nodes $START_NODE_ID-$((START_NODE_ID + NODES_THIS_INSTANCE - 1)))"

    START_NODE_ID=$((START_NODE_ID + NODES_THIS_INSTANCE))
done

if [[ ${#INSTANCE_IDS[@]} -ne $NUM_INSTANCES ]]; then
    log_error "Launched ${#INSTANCE_IDS[@]} of $NUM_INSTANCES required instances"
    exit 1
fi

log_ok "Launched ${#INSTANCE_IDS[@]} instances"

# Wait for instances to be running
log_info "Waiting for instances to start..."
aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"
aws_cmd ec2 wait instance-status-ok --instance-ids "${INSTANCE_IDS[@]}"
log_ok "All instances running"

log_info "Copying firmware and platform files to instances..."
for i in "${!INSTANCE_IDS[@]}"; do
    instance_id="${INSTANCE_IDS[$i]}"
    ip=$(aws_cmd ec2 describe-instances --instance-ids "$instance_id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    authenticate_ec2_host "$instance_id" "$ip"
    ssh "${SSH_OPTS[@]}" -N -R "$SIM_PORT:127.0.0.1:$SIM_PORT" \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
        "ec2-user@$ip" &
    tunnel_pid=$!
    TUNNEL_PIDS+=("$tunnel_pid")
    sleep 1
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then
        log_error "Could not establish simulator tunnel to $instance_id"
        exit 1
    fi
    copied=false
    for _ in {1..12}; do
        if scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
            "$PROJECT_ROOT/lichen/boards/renode/peripherals/SX1262.cs" \
            "$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl" \
            "ec2-user@$ip:/tmp/" 2>/dev/null && \
            scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
            "$FIRMWARE_PATH" "ec2-user@$ip:/tmp/firmware.elf.upload" 2>/dev/null && \
            ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
                "ec2-user@$ip" 'mv /tmp/firmware.elf.upload /tmp/firmware.elf'; then
            copied=true
            break
        fi
        sleep 5
    done
    if [[ "$copied" != "true" ]]; then
        log_error "Could not copy firmware to instance $instance_id"
        exit 1
    fi
done

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

LOGS_DIR="/tmp/renode-fleet-logs-$(date +%s)"
mkdir -p "$LOGS_DIR"
RESULTS_OK=true
for i in "${!INSTANCE_IDS[@]}"; do
    ip=$(aws_cmd ec2 describe-instances --instance-ids "${INSTANCE_IDS[$i]}" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    deadline=$(($(date +%s) + 600))
    completed=false
    while (( $(date +%s) < deadline )); do
        if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=10 \
            "ec2-user@$ip" 'test -f /tmp/renode-complete' 2>/dev/null; then
            completed=true
            break
        fi
        sleep 10
    done
    if [[ "$completed" != "true" ]]; then
        log_error "Timed out waiting for instance ${INSTANCE_IDS[$i]} results"
        RESULTS_OK=false
        continue
    fi
    if ! scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" \
        "ec2-user@$ip:/tmp/renode-logs-${INSTANCE_NUMBERS[$i]}.tar.gz" "$LOGS_DIR/"; then
        log_error "Could not download results from instance ${INSTANCE_IDS[$i]}"
        RESULTS_OK=false
    fi
done

if [[ "$RESULTS_OK" != "true" ]]; then
    exit 1
fi

# Analyze results
TOTAL_LOG_LINES=0

for log_tar in "$LOGS_DIR"/*.tar.gz; do
    [[ -f "$log_tar" ]] || continue
    tar xzf "$log_tar" -C "$LOGS_DIR"
done

shopt -s nullglob
RENODE_LOGS=("$LOGS_DIR"/var/log/renode-node-*.log)
UART_LOGS=("$LOGS_DIR"/var/log/uart-node-*.log)
if [[ ${#RENODE_LOGS[@]} -ne $TOTAL_NODES || ${#UART_LOGS[@]} -ne $TOTAL_NODES ]]; then
    log_error "Collected ${#RENODE_LOGS[@]} Renode and ${#UART_LOGS[@]} UART logs for $TOTAL_NODES nodes"
    exit 1
fi
if ! kill -0 "$SIM_PID" 2>/dev/null; then
    log_error "lichen-sim exited before evidence collection"
    exit 1
fi
TX_COUNT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transmissions"])' "$METRICS_PATH")
if [[ $TX_COUNT -le 0 ]]; then
    log_error "Simulator observed no firmware transmissions"
    exit 1
fi
BOOT_COUNT=0
TX_DONE_COUNT=0
for log in "${UART_LOGS[@]}"; do
    grep -F "LoRa configured, starting ping loop" "$log" >/dev/null && BOOT_COUNT=$((BOOT_COUNT + 1))
    grep -F "TX done" "$log" >/dev/null && TX_DONE_COUNT=$((TX_DONE_COUNT + 1))
done
if [[ $BOOT_COUNT -ne $TOTAL_NODES || $TX_DONE_COUNT -ne $TOTAL_NODES ]]; then
    log_error "UART oracle failed: boot=$BOOT_COUNT tx_done=$TX_DONE_COUNT expected=$TOTAL_NODES"
    exit 1
fi

for log_file in "$LOGS_DIR"/var/log/renode-*.log; do
    [[ -f "$log_file" ]] || continue
    TOTAL_LOG_LINES=$((TOTAL_LOG_LINES + $(wc -l < "$log_file")))
done

# Print summary
echo ""
log_ok "=== FLEET TEST RESULTS ==="
echo "  Instances: ${#INSTANCE_IDS[@]}"
echo "  Target nodes: $TOTAL_NODES"
echo "  Duration: ${DURATION_S}s"
echo "  Total log lines: $TOTAL_LOG_LINES"
echo "  Simulator transmissions: $TX_COUNT"
echo "  Nodes booted: $BOOT_COUNT"
echo "  Nodes with completed TX: $TX_DONE_COUNT"

log_ok "Fleet test complete"
