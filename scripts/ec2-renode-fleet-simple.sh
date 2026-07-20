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
    log_error "  Build for t_echo/nrf52840 with the tracked Renode overlay and config"
    exit 1
fi

if nm -a "$FIRMWARE" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPIM|spi_nrfx_spim\.c)$' >/dev/null; then
    log_error "Firmware uses SPIM, which Renode 1.16.1 cannot run with this platform model"
    log_error "Rebuild with renode_console.overlay to select nordic,nrf-spi"
    exit 1
fi
if ! nm -a "$FIRMWARE" 2>/dev/null | grep -E '[[:space:]](CONFIG_SPI_NRFX_SPI|spi_nrfx_spi\.c)$' >/dev/null; then
    log_error "Firmware does not contain the required legacy nRF SPI driver"
    log_error "Rebuild with renode_console.overlay"
    exit 1
fi

log_info "=== LICHEN Renode Fleet ==="
log_info "Total firmware nodes: $TOTAL_NODES"
log_info "EC2 instances: $NUM_INSTANCES × c7g.xlarge"
log_info "Duration: ${DURATION_S}s"
log_info "Estimated cost: \$$(echo "scale=2; $NUM_INSTANCES * 0.17 * $DURATION_S / 3600" | bc)"
echo ""

# AWS config
AWS_PROFILE="${AWS_PROFILE:-personal}"
AWS_REGION="${AWS_REGION:-us-west-2}"
EXPECTED_AWS_ACCOUNT="210337117346"
AMI_ID="${EC2_AMI_ID:-ami-0764d1b512e22671f}"  # LICHEN ARM64 fleet runtime
KEY_NAME="${EC2_KEY_NAME:-markatwood}"
EC2_SSH_KEY="${EC2_SSH_KEY:-$HOME/.ssh/id_ed25519}"

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

# Get our public IP
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com)
log_info "Coordinator IP: $PUBLIC_IP"

# State for cleanup
INSTANCE_IDS=()
INSTANCE_IPS=()
SIM_PID=""
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

cleanup() {
    local original_status=$?
    local cleanup_failed=false
    trap - EXIT
    log_info "Cleaning up..."
    reconciled_ids=$(aws_cmd ec2 describe-instances \
        --filters "Name=tag:RunId,Values=$RUN_ID" \
                  "Name=tag:Project,Values=LICHEN" \
                  "Name=tag:LaunchedBy,Values=ec2-renode-fleet-simple.sh" \
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
                          "Name=tag:LaunchedBy,Values=ec2-renode-fleet-simple.sh" \
                --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null); then
            SG_ID=""
            cleanup_failed=true
        fi
        [[ "$SG_ID" == "None" ]] && SG_ID=""
    fi
    [[ -n "$SIM_PID" ]] && kill "$SIM_PID" 2>/dev/null || true
    for pid in "${TUNNEL_PIDS[@]-}"; do
        kill "$pid" 2>/dev/null || true
    done
    ownership_ok=true
    for id in "${INSTANCE_IDS[@]-}"; do
        read -r project launched_by run_id <<< "$(aws_cmd ec2 describe-instances --instance-ids "$id" \
            --query 'Reservations[0].Instances[0].[Tags[?Key==`Project`].Value|[0],Tags[?Key==`LaunchedBy`].Value|[0],Tags[?Key==`RunId`].Value|[0]]' \
            --output text 2>/dev/null)" || ownership_ok=false
        if [[ "$project" != "LICHEN" || "$launched_by" != "ec2-renode-fleet-simple.sh" || "$run_id" != "$RUN_ID" ]]; then
            log_error "Refusing to terminate unverified instance $id"
            ownership_ok=false
        fi
    done
    if [[ ${#INSTANCE_IDS[@]} -gt 0 && "$ownership_ok" == "true" ]]; then
        log_info "Terminating ${#INSTANCE_IDS[@]} instances..."
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
        if [[ "$sg_project" != "LICHEN" || "$sg_launched_by" != "ec2-renode-fleet-simple.sh" || "$sg_run_id" != "$RUN_ID" ]]; then
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

# Start lichen-sim bound to all interfaces
log_info "Starting lichen-sim server..."
cd "$PROJECT_ROOT/python"
LICHEN_METRICS_PATH="$METRICS_PATH" uv run python3 -c "
import asyncio
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, 'src')
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import TimeMode

async def main():
    server = SimulatorServer(node_port=5555, api_port=5556, bind_host='127.0.0.1')
    await server.start()
    sim = await server.create_simulation('fleet', TimeMode.REALTIME)
    metrics_path = Path(os.environ['LICHEN_METRICS_PATH'])
    print('lichen-sim ready on 127.0.0.1:5555', flush=True)
    while True:
        metrics_path.write_text(json.dumps(sim.metrics.snapshot()))
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

SG_NAME="lichen-renode-fleet-$RUN_ID"
log_info "Creating per-run security group..."
if ! SG_ID=$(aws_cmd ec2 create-security-group \
        --group-name "$SG_NAME" \
        --description "LICHEN Renode fleet" \
        --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=LICHEN},{Key=Purpose,Value=renode-fleet},{Key=LaunchedBy,Value=ec2-renode-fleet-simple.sh},{Key=RunId,Value=$RUN_ID}]" \
        --query 'GroupId' --output text); then
    SG_ID=$(aws_cmd ec2 describe-security-groups \
        --filters "Name=group-name,Values=$SG_NAME" "Name=tag:RunId,Values=$RUN_ID" \
                  "Name=tag:Project,Values=LICHEN" \
                  "Name=tag:LaunchedBy,Values=ec2-renode-fleet-simple.sh" \
        --query 'SecurityGroups[0].GroupId' --output text)
fi
if [[ -z "$SG_ID" || "$SG_ID" == "None" ]]; then
    log_error "Could not create or reconcile security group for run $RUN_ID"
    exit 1
fi
aws_cmd ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${PUBLIC_IP}/32" >/dev/null

# Launch instances
log_info "Launching $NUM_INSTANCES EC2 instances..."
NODE_OFFSET=0

for i in $(seq 1 "$NUM_INSTANCES"); do
    if [[ $i -eq $NUM_INSTANCES ]]; then
        NODES_THIS=$(( TOTAL_NODES - (NUM_INSTANCES - 1) * RENODES_PER_INSTANCE ))
    else
        NODES_THIS=$RENODES_PER_INSTANCE
    fi

    INSTANCE_ID=""
    for _ in {1..3}; do
        if INSTANCE_ID=$(aws_cmd ec2 run-instances \
                --client-token "$RUN_ID-$i" \
                --image-id "$AMI_ID" \
                --instance-type "c7g.xlarge" \
                --key-name "$KEY_NAME" \
                --security-group-ids "$SG_ID" \
                --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=renode-$i},{Key=Project,Value=LICHEN},{Key=LaunchedBy,Value=ec2-renode-fleet-simple.sh},{Key=RunId,Value=$RUN_ID},{Key=LaunchIndex,Value=$i}]" \
                --query 'Instances[0].InstanceId' --output text); then
            break
        fi
        sleep 5
    done
    if [[ -z "$INSTANCE_ID" ]]; then
        INSTANCE_ID=$(aws_cmd ec2 describe-instances \
            --filters "Name=tag:RunId,Values=$RUN_ID" "Name=tag:LaunchIndex,Values=$i" \
                      "Name=tag:Project,Values=LICHEN" \
                      "Name=tag:LaunchedBy,Values=ec2-renode-fleet-simple.sh" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text)
    fi
    if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
        log_error "Failed to launch or reconcile instance $i"
        exit 1
    fi

    INSTANCE_IDS+=("$INSTANCE_ID")
    log_info "  Instance $i: $INSTANCE_ID (nodes $NODE_OFFSET-$((NODE_OFFSET + NODES_THIS - 1)))"
    NODE_OFFSET=$((NODE_OFFSET + NODES_THIS))
done

if [[ ${#INSTANCE_IDS[@]} -ne $NUM_INSTANCES ]]; then
    log_error "Launched ${#INSTANCE_IDS[@]} of $NUM_INSTANCES required instances"
    exit 1
fi

log_ok "Launched ${#INSTANCE_IDS[@]} instances"

# Wait for instances
log_info "Waiting for instances to be ready..."
aws_cmd ec2 wait instance-running --instance-ids "${INSTANCE_IDS[@]}"
aws_cmd ec2 wait instance-status-ok --instance-ids "${INSTANCE_IDS[@]}"

# Get public IPs
for id in "${INSTANCE_IDS[@]}"; do
    IP=$(aws_cmd ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    INSTANCE_IPS+=("$IP")
    authenticate_ec2_host "$id" "$IP"
done

# Wait for the baked Renode runtime to become reachable.
log_info "Waiting for Renode on instances..."
for i in "${!INSTANCE_IDS[@]}"; do
    id="${INSTANCE_IDS[$i]}"
    IP="${INSTANCE_IPS[$i]}"
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
        log_error "EC2 instance $id did not become ready"
        exit 1
    fi
done
log_ok "All instances ready"

# SCP firmware and platform files to each instance
log_info "Uploading firmware and platform files..."
UPLOAD_PIDS=()
for i in "${!INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$i]}"
    ssh "${SSH_OPTS[@]}" -N -R "5555:127.0.0.1:5555" \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
        ec2-user@"$IP" &
    tunnel_pid=$!
    TUNNEL_PIDS+=("$tunnel_pid")
    sleep 1
    if ! kill -0 "$tunnel_pid" 2>/dev/null; then
        log_error "Could not establish simulator tunnel to ${INSTANCE_IDS[$i]}"
        exit 1
    fi
    scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -q \
        "$FIRMWARE" \
        "$PROJECT_ROOT/lichen/boards/renode/peripherals/SX1262.cs" \
        "$PROJECT_ROOT/lichen/boards/renode/nrf52840_lichen/support/nrf52840_lichen.repl" \
        ec2-user@"$IP":/tmp/ &
    UPLOAD_PIDS+=("$!")
done
for pid in "${UPLOAD_PIDS[@]}"; do
    if ! wait "$pid"; then
        log_error "Firmware/platform upload failed"
        exit 1
    fi
done
log_ok "Files uploaded"

# Start Renode instances on each EC2
log_info "Starting Renode instances..."
NODE_ID=0
INSTANCE_NUM=0

START_PIDS=()
for i in "${!INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$i]}"
    INSTANCE_NUM=$((INSTANCE_NUM + 1))

    if [[ $INSTANCE_NUM -eq $NUM_INSTANCES ]]; then
        NODES_THIS=$(( TOTAL_NODES - (NUM_INSTANCES - 1) * RENODES_PER_INSTANCE ))
    else
        NODES_THIS=$RENODES_PER_INSTANCE
    fi

    # Create and run Renode instances on this EC2
    ssh "${SSH_OPTS[@]}" ec2-user@"$IP" bash -s << REMOTE_SCRIPT &
cd /tmp
RENODE_PIDS=()
for i in \$(seq 0 $((NODES_THIS - 1))); do
    NID=\$((${NODE_ID} + i))

    cat > node-\$NID.resc << RESC
:name: node-\$NID
include @/tmp/SX1262.cs
mach create "node-\$NID"
machine LoadPlatformDescription @/tmp/nrf52840_lichen.repl
spi1.sx1262 SimHost "127.0.0.1"
spi1.sx1262 SimPort 5555
sysbus Tag <0x10000060, 0x10000063> "DEVICEID[0]" \$((0x1CE00000 + NID))
sysbus Tag <0x10000064, 0x10000067> "DEVICEID[1]" \$((0x1CE10000 + NID))
sysbus LoadELF @/tmp/zephyr.elf
logFile @/tmp/node-\$NID.log true
uart0 CreateFileBackend @/tmp/uart-node-\$NID.log true
start
RESC

    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 /usr/local/bin/renode --disable-gui --port \$((50000 + NID)) node-\$NID.resc > /dev/null 2>&1 &
    RENODE_PIDS+=(\$!)
done
printf '%s\n' "\${RENODE_PIDS[@]}" > /tmp/renode.pids
REMOTE_SCRIPT
    START_PIDS+=("$!")

    NODE_ID=$((NODE_ID + NODES_THIS))
done

for pid in "${START_PIDS[@]}"; do
    if ! wait "$pid"; then
        log_error "Failed to start Renode instances"
        exit 1
    fi
done
log_ok "All Renode instances started"

# Monitor test
log_info "Test running for ${DURATION_S}s..."
sleep "$DURATION_S"

# Collect results
log_info "Collecting results..."
RESULTS_DIR="/tmp/renode-fleet-$(date +%s)"
mkdir -p "$RESULTS_DIR"

for i in "${!INSTANCE_IDS[@]}"; do
    IP="${INSTANCE_IPS[$i]}"
    if ! ssh "${SSH_OPTS[@]}" ec2-user@"$IP" \
        'while read -r pid; do kill -0 "$pid" || exit 1; done < /tmp/renode.pids'; then
        log_error "A Renode process exited early on ${INSTANCE_IDS[$i]}"
        exit 1
    fi
    if ! scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -q \
        ec2-user@"$IP":/tmp/node-*.log ec2-user@"$IP":/tmp/uart-node-*.log "$RESULTS_DIR/"; then
        log_error "Failed to collect Renode logs from ${INSTANCE_IDS[$i]}"
        exit 1
    fi
done

shopt -s nullglob
NODE_LOGS=("$RESULTS_DIR"/node-*.log)
UART_LOGS=("$RESULTS_DIR"/uart-node-*.log)
if [[ ${#NODE_LOGS[@]} -ne $TOTAL_NODES || ${#UART_LOGS[@]} -ne $TOTAL_NODES ]]; then
    log_error "Collected ${#NODE_LOGS[@]} Renode and ${#UART_LOGS[@]} UART logs for $TOTAL_NODES nodes"
    exit 1
fi

# Analyze
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

echo ""
log_ok "=== FLEET TEST RESULTS ==="
echo "  Total nodes: $TOTAL_NODES"
echo "  EC2 instances: ${#INSTANCE_IDS[@]}"
echo "  Simulator transmissions: $TX_COUNT"
echo "  Nodes booted: $BOOT_COUNT"
echo "  Nodes with completed TX: $TX_DONE_COUNT"
echo "  Logs: $RESULTS_DIR"

log_ok "Done"
