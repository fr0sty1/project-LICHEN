#!/usr/bin/env bash
#
# ec2-claude.sh - Run Claude Code headlessly on an ephemeral EC2 instance
#
# Launches a Graviton instance in us-east-2a, attaches the LICHEN EBS volume
# containing Claude Code and credentials, runs a prompt, then cleans up.
#
# Usage:
#   ./ec2-claude.sh "Your prompt here"
#   ./ec2-claude.sh -f prompt.txt
#   ./ec2-claude.sh -f prompt.txt -o output.txt
#   echo "prompt" | ./ec2-claude.sh -
#
# Requirements:
#   - AWS CLI v2 configured
#   - SSH key pair in us-east-2
#   - EBS volume vol-017cfe48bd75340d0 in us-east-2a with Claude Code + env.sh
#
set -euo pipefail

# === Configuration ===
AWS_PROFILE="AdministratorAccess-921772462201"
AWS_REGION="us-east-2"
AVAILABILITY_ZONE="us-east-2a"
INSTANCE_TYPE="c7g.xlarge"
EBS_VOLUME_ID="vol-017cfe48bd75340d0"

# AMI: Amazon Linux 2023 ARM64 in us-east-2 (update periodically)
# Find latest: aws ec2 describe-images --owners amazon --filters "Name=name,Values=al2023-ami-*-arm64" --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId'
AMI_ID="${EC2_CLAUDE_AMI_ID:-ami-03a84069f5e253220}"

# SSH key - uses ec2-instance-connect by default (no persistent keypair needed)
# If you prefer a traditional key pair, set these:
KEY_NAME="${EC2_CLAUDE_KEY_NAME:-}"  # Empty = no key pair (use ec2-instance-connect)
SSH_KEY_PATH="${EC2_CLAUDE_SSH_KEY:-$HOME/.ssh/id_ed25519}"
USE_INSTANCE_CONNECT="${EC2_CLAUDE_USE_INSTANCE_CONNECT:-true}"

# Subnet in us-east-2a (same AZ as EBS volume) - discovered automatically if not set
SUBNET_ID="${EC2_CLAUDE_SUBNET:-}"

# EBS mount configuration
DEVICE_NAME="/dev/xvdf"
MOUNT_POINT="/mnt/lichen-zephyr"

# Git repo to clone (default: LICHEN)
REPO_URL="${EC2_CLAUDE_REPO:-git@github.com:MarkAtwood/project-LICHEN.git}"
REPO_BRANCH="${EC2_CLAUDE_BRANCH:-main}"
WORKSPACE_DIR="/mnt/lichen-zephyr/workspace"

# SSH options
SSH_USER="ec2-user"
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# Timeouts (seconds)
INSTANCE_TIMEOUT=300
VOLUME_TIMEOUT=120
SSH_TIMEOUT=180

# === State (for cleanup) ===
INSTANCE_ID=""
VOLUME_ATTACHED=false
CLEANUP_DONE=false
PUBLIC_IP=""
SQS_QUEUE_URL=""
ULTRACODE_MODE=false

# === Colors (if terminal) ===
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# === Logging ===
log_info()  { echo -e "${BLUE}>>>${NC} $*" >&2; }
log_ok()    { echo -e "${GREEN}>>>${NC} $*" >&2; }
log_warn()  { echo -e "${YELLOW}>>>${NC} $*" >&2; }
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }

# === AWS CLI wrapper with profile ===
aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

# === SQS Status Queue ===
create_sqs_queue() {
    local queue_name="ec2-claude-status-$(date +%s)-$$"
    log_info "Creating SQS status queue..."
    SQS_QUEUE_URL=$(aws_cmd sqs create-queue \
        --queue-name "$queue_name" \
        --attributes '{"MessageRetentionPeriod":"3600"}' \
        --query 'QueueUrl' --output text 2>/dev/null) || {
        log_warn "Failed to create SQS queue - status updates disabled"
        SQS_QUEUE_URL=""
        return 1
    }
    log_ok "Status queue created"
    echo "---"
    echo "SQS Queue URL (for --poll / --stop):"
    echo "  $SQS_QUEUE_URL"
    echo "---"
}

delete_sqs_queue() {
    if [[ -n "$SQS_QUEUE_URL" ]]; then
        aws_cmd sqs delete-queue --queue-url "$SQS_QUEUE_URL" 2>/dev/null || true
    fi
}

# Send status message (local caller)
sqs_status() {
    [[ -z "$SQS_QUEUE_URL" ]] && return 0
    local msg="$1"
    local ts
    ts=$(date -u +"%H:%M:%S")
    aws_cmd sqs send-message \
        --queue-url "$SQS_QUEUE_URL" \
        --message-body "{\"ts\":\"$ts\",\"src\":\"local\",\"msg\":\"$msg\"}" \
        >/dev/null 2>&1 || true
}

# === Cleanup Handler ===
cleanup() {
    local exit_code=$?

    [[ "$CLEANUP_DONE" == "true" ]] && return
    CLEANUP_DONE=true

    echo >&2  # newline after any interrupted output
    log_info "Cleaning up..."

    # Try to push any uncommitted changes before shutdown
    push_changes 2>/dev/null || true

    # Unmount volume on instance (best effort)
    if [[ -n "$PUBLIC_IP" && "$VOLUME_ATTACHED" == "true" ]]; then
        log_info "Unmounting volume on instance..."
        ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" \
            "sudo umount $MOUNT_POINT 2>/dev/null || true" 2>/dev/null || true
        sleep 2  # Give filesystem time to sync
    fi

    # Detach EBS if attached
    if [[ "$VOLUME_ATTACHED" == "true" && -n "$INSTANCE_ID" ]]; then
        log_info "Detaching EBS volume $EBS_VOLUME_ID..."
        aws_cmd ec2 detach-volume \
            --volume-id "$EBS_VOLUME_ID" \
            --instance-id "$INSTANCE_ID" \
            --force 2>/dev/null || true

        # Wait for detach (best effort, timeout after 60s)
        local elapsed=0
        while (( elapsed < 60 )); do
            local state
            state=$(aws_cmd ec2 describe-volumes \
                --volume-ids "$EBS_VOLUME_ID" \
                --query 'Volumes[0].State' --output text 2>/dev/null) || break
            [[ "$state" == "available" ]] && break
            sleep 5
            (( elapsed += 5 ))
        done
    fi

    # Terminate instance if created
    if [[ -n "$INSTANCE_ID" ]]; then
        log_info "Terminating instance $INSTANCE_ID..."
        aws_cmd ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null 2>&1 || true

        # Wait for termination to start (don't block forever)
        local elapsed=0
        while (( elapsed < 30 )); do
            local state
            state=$(aws_cmd ec2 describe-instances \
                --instance-ids "$INSTANCE_ID" \
                --query 'Reservations[0].Instances[0].State.Name' \
                --output text 2>/dev/null) || break
            [[ "$state" == "terminated" || "$state" == "shutting-down" ]] && break
            sleep 5
            (( elapsed += 5 ))
        done
    fi

    # Delete SQS queue
    delete_sqs_queue

    log_ok "Cleanup complete"
    exit $exit_code
}

# === Trap signals ===
trap cleanup EXIT
trap 'log_warn "Interrupted"; exit 130' INT TERM

# === Helper: Wait for instance state ===
wait_instance_state() {
    local target_state="$1"
    local timeout="${2:-$INSTANCE_TIMEOUT}"
    local elapsed=0

    while (( elapsed < timeout )); do
        local state
        state=$(aws_cmd ec2 describe-instances \
            --instance-ids "$INSTANCE_ID" \
            --query 'Reservations[0].Instances[0].State.Name' \
            --output text)
        [[ "$state" == "$target_state" ]] && return 0
        [[ "$state" == "terminated" || "$state" == "shutting-down" ]] && {
            log_error "Instance entered unexpected state: $state"
            return 1
        }
        sleep 5
        (( elapsed += 5 ))
        printf '.' >&2
    done

    echo >&2
    log_error "Timeout waiting for instance state '$target_state' (${timeout}s)"
    return 1
}

# === Helper: Wait for volume state ===
wait_volume_state() {
    local target_state="$1"
    local timeout="${2:-$VOLUME_TIMEOUT}"
    local elapsed=0

    while (( elapsed < timeout )); do
        local state
        state=$(aws_cmd ec2 describe-volumes \
            --volume-ids "$EBS_VOLUME_ID" \
            --query 'Volumes[0].State' --output text)
        [[ "$state" == "$target_state" ]] && return 0
        sleep 5
        (( elapsed += 5 ))
        printf '.' >&2
    done

    echo >&2
    log_error "Timeout waiting for volume state '$target_state' (${timeout}s)"
    return 1
}

# === Helper: Wait for volume attachment ===
wait_volume_attached() {
    local timeout="${1:-$VOLUME_TIMEOUT}"
    local elapsed=0

    while (( elapsed < timeout )); do
        local state
        state=$(aws_cmd ec2 describe-volumes \
            --volume-ids "$EBS_VOLUME_ID" \
            --query 'Volumes[0].Attachments[0].State' --output text)
        [[ "$state" == "attached" ]] && return 0
        sleep 5
        (( elapsed += 5 ))
        printf '.' >&2
    done

    echo >&2
    log_error "Timeout waiting for volume attachment (${timeout}s)"
    return 1
}

# === Helper: Send SSH key via EC2 Instance Connect ===
send_ssh_key() {
    if [[ "$USE_INSTANCE_CONNECT" != "true" ]]; then
        return 0  # Using traditional key pair
    fi

    aws_cmd ec2-instance-connect send-ssh-public-key \
        --instance-id "$INSTANCE_ID" \
        --instance-os-user "$SSH_USER" \
        --ssh-public-key "file://${SSH_KEY_PATH}.pub" >/dev/null
}

# === Helper: Wait for SSH ===
wait_ssh_ready() {
    local host="$1"
    local timeout="${2:-$SSH_TIMEOUT}"
    local elapsed=0

    while (( elapsed < timeout )); do
        # Refresh instance connect key (valid for 60s)
        send_ssh_key 2>/dev/null || true

        if ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${host}" 'true' 2>/dev/null; then
            return 0
        fi
        sleep 5
        (( elapsed += 5 ))
        printf '.' >&2
    done

    echo >&2
    log_error "Timeout waiting for SSH (${timeout}s)"
    return 1
}

# === Check prerequisites ===
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check AWS CLI
    if ! command -v aws &>/dev/null; then
        log_error "AWS CLI not found. Install it first."
        exit 1
    fi

    # Check SSH key exists
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        log_error "SSH key not found: $SSH_KEY_PATH"
        log_error "Set EC2_CLAUDE_SSH_KEY environment variable or create the key"
        exit 1
    fi

    # Check SSH key permissions
    local key_perms
    key_perms=$(stat -f '%A' "$SSH_KEY_PATH" 2>/dev/null || stat -c '%a' "$SSH_KEY_PATH" 2>/dev/null)
    if [[ "$key_perms" != "600" && "$key_perms" != "400" ]]; then
        log_warn "SSH key permissions should be 600 or 400 (currently $key_perms)"
        chmod 600 "$SSH_KEY_PATH"
    fi

    # Verify AWS credentials work
    if ! aws_cmd sts get-caller-identity &>/dev/null; then
        log_error "AWS credentials not configured or expired for profile: $AWS_PROFILE"
        log_error "Run: aws sso login --profile $AWS_PROFILE"
        exit 1
    fi

    # Verify EBS volume exists and is available
    local vol_state
    vol_state=$(aws_cmd ec2 describe-volumes \
        --volume-ids "$EBS_VOLUME_ID" \
        --query 'Volumes[0].State' --output text 2>/dev/null) || {
        log_error "EBS volume $EBS_VOLUME_ID not found in $AWS_REGION"
        exit 1
    }

    if [[ "$vol_state" != "available" ]]; then
        log_error "EBS volume $EBS_VOLUME_ID is not available (state: $vol_state)"
        log_error "It may be attached to another instance"
        exit 1
    fi

    # Auto-discover subnet in us-east-2a if not set
    if [[ -z "$SUBNET_ID" ]]; then
        log_info "Discovering subnet in $AVAILABILITY_ZONE..."
        SUBNET_ID=$(aws_cmd ec2 describe-subnets \
            --filters "Name=availability-zone,Values=$AVAILABILITY_ZONE" \
            --query 'Subnets[0].SubnetId' --output text 2>/dev/null) || {
            log_error "Could not find a subnet in $AVAILABILITY_ZONE"
            exit 1
        }
        log_info "Using subnet: $SUBNET_ID"
    fi

    log_ok "Prerequisites OK"
}

# === Launch Instance ===
launch_instance() {
    log_info "Launching $INSTANCE_TYPE in $AVAILABILITY_ZONE..."

    # Build run-instances args
    local run_args=(
        --image-id "$AMI_ID"
        --instance-type "$INSTANCE_TYPE"
        --subnet-id "$SUBNET_ID"
        --placement "AvailabilityZone=$AVAILABILITY_ZONE"
        --associate-public-ip-address
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=claude-runner-ephemeral},{Key=Purpose,Value=claude-headless},{Key=Project,Value=LICHEN},{Key=LaunchedBy,Value=ec2-claude-sh}]"
        --query 'Instances[0].InstanceId'
        --output text
    )

    # Add key pair only if specified (not needed with ec2-instance-connect)
    if [[ -n "$KEY_NAME" ]]; then
        run_args+=(--key-name "$KEY_NAME")
    fi

    INSTANCE_ID=$(aws_cmd ec2 run-instances "${run_args[@]}")

    log_info "Instance ID: $INSTANCE_ID"
    log_info "Waiting for instance to start..."
    wait_instance_state "running"

    # Get public IP
    PUBLIC_IP=$(aws_cmd ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text)

    log_ok "Instance running at $PUBLIC_IP"
}

# === Attach EBS Volume ===
attach_volume() {
    log_info "Attaching EBS volume $EBS_VOLUME_ID..."

    aws_cmd ec2 attach-volume \
        --volume-id "$EBS_VOLUME_ID" \
        --instance-id "$INSTANCE_ID" \
        --device "$DEVICE_NAME" >/dev/null

    VOLUME_ATTACHED=true

    log_info "Waiting for volume attachment..."
    wait_volume_attached
    log_ok "Volume attached"
}

# === Mount Volume on Instance ===
mount_volume() {
    log_info "Mounting volume on instance..."

    send_ssh_key
    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" bash <<'REMOTE_MOUNT'
        set -euo pipefail

        # Create mount point
        sudo mkdir -p /mnt/lichen-zephyr

        # Wait for device to appear (NVMe naming on Graviton/Nitro)
        DEVICE=""
        for i in {1..24}; do
            # Check NVMe devices first (Graviton instances)
            for dev in /dev/nvme1n1 /dev/nvme2n1 /dev/xvdf; do
                if [[ -b "$dev" ]]; then
                    DEVICE="$dev"
                    break 2
                fi
            done
            sleep 5
        done

        if [[ -z "$DEVICE" ]]; then
            echo "ERROR: Block device not found after 2 minutes" >&2
            exit 1
        fi

        # Mount the volume
        sudo mount "$DEVICE" /mnt/lichen-zephyr
        echo "Mounted $DEVICE at /mnt/lichen-zephyr"

        # Verify expected files exist
        if [[ ! -f /mnt/lichen-zephyr/env.sh ]]; then
            echo "WARNING: /mnt/lichen-zephyr/env.sh not found" >&2
        fi
REMOTE_MOUNT

    log_ok "Volume mounted"
}

# === Setup Workspace (clone repo, configure git) ===
setup_workspace() {
    local repo_url="$1"
    local branch="$2"

    log_info "Setting up workspace..."

    send_ssh_key
    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" "bash -s" << REMOTE_SETUP
set -euo pipefail

# Install git if not present (Amazon Linux 2023 minimal doesn't include it)
if ! command -v git &>/dev/null; then
    sudo dnf install -y git >/dev/null 2>&1
fi

# Source environment for GH_TOKEN
source /mnt/lichen-zephyr/env.sh

# Configure git
git config --global user.name "Claude Code (EC2)"
git config --global user.email "claude@ec2.local"
git config --global init.defaultBranch main

# Set up GitHub auth for pushing
mkdir -p ~/.ssh
ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null

# Use GH_TOKEN for HTTPS auth
git config --global credential.helper store
echo "https://x-access-token:\${GH_TOKEN}@github.com" > ~/.git-credentials
chmod 600 ~/.git-credentials

# Clone or update repo
WORKSPACE="/mnt/lichen-zephyr/workspace"
if [[ -d "\$WORKSPACE/.git" ]]; then
    echo "Updating existing workspace..."
    cd "\$WORKSPACE"
    git fetch origin
    git checkout "$branch" 2>/dev/null || git checkout -b "$branch" origin/"$branch"
    git pull --rebase origin "$branch" || true
else
    echo "Cloning repo..."
    rm -rf "\$WORKSPACE"
    # Convert SSH URL to HTTPS for token auth
    HTTPS_URL=\$(echo "$repo_url" | sed 's|git@github.com:|https://github.com/|' | sed 's|\.git\$||').git
    git clone --branch "$branch" "\$HTTPS_URL" "\$WORKSPACE"
    cd "\$WORKSPACE"
fi

# Install beads (markatwood flatfile fork) if not already installed
if ! command -v bd &>/dev/null; then
    if [[ -f "/mnt/lichen-zephyr/local-bin/bd" ]]; then
        export PATH="/mnt/lichen-zephyr/local-bin:\$PATH"
    elif [[ -f "\$WORKSPACE/tools/bd" ]]; then
        sudo cp "\$WORKSPACE/tools/bd" /usr/local/bin/
        sudo chmod +x /usr/local/bin/bd
    else
        echo "Installing beads (flatfile fork)..."
        # Install Go 1.26+ (required by beads fork)
        if [[ ! -d "/mnt/lichen-zephyr/go" ]]; then
            echo "Installing Go 1.26..."
            curl -fsSL https://dl.google.com/go/go1.26.4.linux-arm64.tar.gz | tar -C /mnt/lichen-zephyr -xz
        fi
        export PATH="/mnt/lichen-zephyr/go/bin:\$PATH"
        cd /tmp
        rm -rf beads-build
        git clone --depth 1 --branch pr/flatfile-backend https://github.com/MarkAtwood/beads.git beads-build
        cd beads-build
        CGO_ENABLED=0 go build -ldflags="-s -w" -o bd ./cmd/bd
        mv bd /mnt/lichen-zephyr/local-bin/
        chmod +x /mnt/lichen-zephyr/local-bin/bd
        cd /tmp && rm -rf beads-build
        export PATH="/mnt/lichen-zephyr/local-bin:\$PATH"
    fi
fi

# Initialize beads (flatfile fork - no Dolt)
cd "\$WORKSPACE"
# Clean up any Dolt artifacts from previous gastownhall beads
rm -rf .beads/embeddeddolt .beads/dolt 2>/dev/null || true
# Ensure flatfile backend
if [[ -f .beads/metadata.json ]]; then
    # Update backend to flatfile if needed
    if ! grep -q '"backend":"flatfile"' .beads/metadata.json 2>/dev/null; then
        echo '{"backend":"flatfile"}' > .beads/metadata.json
    fi
fi
bd status 2>/dev/null || (bd init --quiet 2>/dev/null && bd setup claude 2>/dev/null) || true

echo "Workspace ready at \$WORKSPACE"
git log --oneline -3
REMOTE_SETUP

    log_ok "Workspace ready"
}

# === Push changes before cleanup ===
push_changes() {
    if [[ -z "$PUBLIC_IP" ]]; then
        return
    fi

    log_info "Pushing any uncommitted changes..."

    send_ssh_key 2>/dev/null || true
    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" "bash -s" << 'REMOTE_PUSH' 2>/dev/null || true
set -e
source /mnt/lichen-zephyr/env.sh 2>/dev/null || true

cd /mnt/lichen-zephyr/workspace 2>/dev/null || exit 0

# Check if there are changes
if git diff --quiet && git diff --cached --quiet; then
    echo "No uncommitted changes"
else
    echo "Committing work-in-progress..."
    git add -A
    git commit -m "WIP: checkpoint before EC2 shutdown" || true
fi

# Push if we have commits ahead of origin
if git rev-list --count @{u}..HEAD 2>/dev/null | grep -q '^[1-9]'; then
    echo "Pushing to origin..."
    git push origin HEAD || echo "Push failed, changes preserved locally"
fi

# Close any open beads
bd close --all --reason="EC2 session ending" 2>/dev/null || true
REMOTE_PUSH

    log_ok "Changes pushed"
}

# === Run Claude Code ===
run_claude() {
    local prompt="$1"
    local output_file="${2:-}"

    log_info "Running Claude Code..."

    # Escape prompt for safe transmission via base64
    local escaped_prompt
    escaped_prompt=$(printf '%s' "$prompt" | base64 | tr -d '\n')

    # Build remote script that decodes and runs the prompt
    # Args: $1=base64_prompt, $2=sqs_queue_url
    local remote_script
    read -r -d '' remote_script <<'REMOTE_CLAUDE' || true
set -euo pipefail

# Source environment (API keys, PATH, etc.)
if [[ -f /mnt/lichen-zephyr/env.sh ]]; then
    source /mnt/lichen-zephyr/env.sh
fi

# Symlink ~/.claude to EBS config dir so Claude finds credentials
if [[ -d /mnt/lichen-zephyr/claude-config ]] && [[ ! -L ~/.claude ]]; then
    rm -rf ~/.claude 2>/dev/null || true
    ln -sf /mnt/lichen-zephyr/claude-config ~/.claude
fi

# Change to workspace if it exists
if [[ -d /mnt/lichen-zephyr/workspace ]]; then
    cd /mnt/lichen-zephyr/workspace
else
    cd /mnt/lichen-zephyr
fi

# Decode prompt from base64 (passed as $1)
PROMPT=$(printf '%s' "$1" | base64 -d)
SQS_QUEUE_URL="${2:-}"

# SQS helper functions
sqs_status() {
    [[ -z "$SQS_QUEUE_URL" ]] && return 0
    local msg="$1"
    local ts=$(date -u +"%H:%M:%S")
    aws sqs send-message \
        --queue-url "$SQS_QUEUE_URL" \
        --message-body "{\"ts\":\"$ts\",\"src\":\"ec2\",\"msg\":\"$msg\"}" \
        --region us-east-2 >/dev/null 2>&1 || true
}

check_stop_signal() {
    [[ -z "$SQS_QUEUE_URL" ]] && return 1
    local msg
    msg=$(aws sqs receive-message \
        --queue-url "$SQS_QUEUE_URL" \
        --max-number-of-messages 1 \
        --visibility-timeout 0 \
        --region us-east-2 \
        --query 'Messages[0].Body' --output text 2>/dev/null) || return 1
    [[ "$msg" == *'"cmd":"stop"'* ]] && return 0
    return 1
}

STOP_FLAG="/tmp/ec2-claude-stop"

# Note: Background beads sync disabled temporarily for simpler flow
# Beads can be synced after Claude completes

sqs_status "Claude starting"

# Build system prompt additions for resilience and quality
RESILIENCE_PROMPT="CRITICAL RULES (instance may terminate at any time):

RESILIENCE:
1. Use 'bd' (beads) for task tracking. Run 'bd ready' to see work, 'bd close <id>' when done.
2. Beads changes auto-sync to git every 30s. For code, commit and push frequently.
3. Use conventional commit messages (feat:, fix:, etc.).
4. If you hit an error 3 times, stop and document in a bead before proceeding.
5. Before any destructive action, commit and push current work first.
6. Work as if each commit could be your last.
7. Commit and push after completing each logical unit of work.

CODE QUALITY:
The orchestrator will run 3 independent code review passes after your implementation.
Each review focuses on different concerns (correctness, security, edge cases).
Issues found will be filed as beads prefixed with [review].
You will then be asked to fix those issues.
This cycle repeats until reviews find no new issues.

Your job: write clean code, commit frequently, and fix review issues when asked."

# Run Claude Code headlessly with unbuffered output
# stdbuf -oL forces line buffering so output streams through SSH
# -p / --print: non-interactive mode
# --permission-mode bypassPermissions: skip permission prompts
# --append-system-prompt: add resilience instructions
# --output-format text: plain text output for streaming
stdbuf -oL claude -p \
    --permission-mode bypassPermissions \
    --append-system-prompt "$RESILIENCE_PROMPT" \
    --output-format text \
    "$PROMPT" 2>&1 | {
    LINE_COUNT=0
    while IFS= read -r line; do
        echo "$line"
        # Send periodic status via SQS (every 50 lines)
        ((LINE_COUNT++))
        if (( LINE_COUNT % 50 == 0 )); then
            sqs_status "Output line $LINE_COUNT..."
        fi
    done
}

# Script done - cleanup runs via EXIT trap
sqs_status "Claude done - exiting"
exit 0
REMOTE_CLAUDE

    send_ssh_key
    sqs_status "Running Claude on EC2"
    if [[ -n "$output_file" ]]; then
        # Save output to file - use || true to prevent exit on non-zero from remote
        ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" \
            "bash -s -- '$escaped_prompt' '$SQS_QUEUE_URL'" <<< "$remote_script" > "$output_file" || true
        log_ok "Output saved to: $output_file"
    else
        # Stream output to stdout - use || true to prevent exit on non-zero from remote
        ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" \
            "bash -s -- '$escaped_prompt' '$SQS_QUEUE_URL'" <<< "$remote_script" || true
    fi
    sqs_status "Claude finished"
    log_info "run_claude complete, returning to main"
}

# === Get changed files on remote ===
get_changed_files() {
    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" \
        "cd /mnt/lichen-zephyr/workspace && git diff --name-only HEAD~1 HEAD 2>/dev/null | head -50" 2>/dev/null || true
}

# === Run a single code review pass ===
run_single_review() {
    local review_num="$1"
    local changed_files="$2"
    local review_focus=""

    case "$review_num" in
        1) review_focus="correctness, logic errors, off-by-one bugs, null/undefined handling" ;;
        2) review_focus="security vulnerabilities, input validation, injection risks, auth/authz" ;;
        3) review_focus="edge cases, error handling, resource leaks, race conditions" ;;
    esac

    local review_prompt="CODE REVIEW PASS $review_num - Focus: $review_focus

Review the following files that were just modified. Look ONLY for issues related to: $review_focus

Files to review:
$changed_files

For each issue found:
1. Run 'bd create --title=\"[review] <issue>\" --type=bug --priority=2 --description=\"<details>\"'
2. Be specific about file, line, and the problem

If no issues found for your focus area, say 'No issues found for $review_focus'

Do NOT fix issues - only identify and file them as beads."

    log_info "Review pass $review_num: $review_focus"
    sqs_status "Review $review_num: $review_focus"

    # Run review (simplified - reuse the remote script structure)
    local escaped_review
    escaped_review=$(printf '%s' "$review_prompt" | base64 | tr -d '\n')

    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" "bash -s" << REVIEW_SCRIPT
source /mnt/lichen-zephyr/env.sh 2>/dev/null || true
cd /mnt/lichen-zephyr/workspace
PROMPT=\$(printf '%s' "$escaped_review" | base64 -d)
stdbuf -oL claude -p --permission-mode bypassPermissions --output-format text "\$PROMPT" 2>&1
REVIEW_SCRIPT
}

# === Run 3 parallel code reviews ===
run_3_reviews() {
    local changed_files="$1"

    if [[ -z "$changed_files" ]]; then
        log_info "No changed files to review"
        return 0
    fi

    log_info "Running 3 parallel code reviews..."
    sqs_status "Starting 3 parallel reviews"

    # Run reviews in parallel, capture output
    local review1_out review2_out review3_out
    local pids=()

    run_single_review 1 "$changed_files" > /tmp/review1.out 2>&1 &
    pids+=($!)
    run_single_review 2 "$changed_files" > /tmp/review2.out 2>&1 &
    pids+=($!)
    run_single_review 3 "$changed_files" > /tmp/review3.out 2>&1 &
    pids+=($!)

    # Wait for all reviews
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # Check if any issues were filed (look for bd create in output)
    local issues_found=0
    for f in /tmp/review1.out /tmp/review2.out /tmp/review3.out; do
        if grep -q "bd create\|Created.*issue\|\[review\]" "$f" 2>/dev/null; then
            issues_found=1
        fi
        # Show review output
        cat "$f" 2>/dev/null || true
    done

    sqs_status "Reviews complete, issues_found=$issues_found"
    return $issues_found
}

# === Fix issues found in reviews ===
run_fix_pass() {
    log_info "Running fix pass for review issues..."
    sqs_status "Fixing review issues"

    local fix_prompt="FIX REVIEW ISSUES

Review issues were filed as beads. Find them with:
  bd list --status=open | grep '\[review\]'

For each review issue:
1. Read the issue details
2. Fix the code
3. Close the issue: bd close <id> --reason='Fixed: <what you did>'
4. Commit the fix: git add <files> && git commit -m 'fix: <description>'
5. Push: git push

Work through ALL open review issues until none remain."

    local escaped_fix
    escaped_fix=$(printf '%s' "$fix_prompt" | base64 | tr -d '\n')

    ssh $SSH_OPTS -i "$SSH_KEY_PATH" "${SSH_USER}@${PUBLIC_IP}" "bash -s" << FIX_SCRIPT
source /mnt/lichen-zephyr/env.sh 2>/dev/null || true
cd /mnt/lichen-zephyr/workspace
PROMPT=\$(printf '%s' "$escaped_fix" | base64 -d)
stdbuf -oL claude -p --permission-mode bypassPermissions --output-format text "\$PROMPT" 2>&1
FIX_SCRIPT
}

# === Orchestrated review loop (for ultracode mode) ===
run_review_loop() {
    local max_iterations=5
    local iteration=0

    while (( iteration < max_iterations )); do
        ((iteration++))
        log_info "=== Review cycle $iteration of $max_iterations ==="
        sqs_status "Review cycle $iteration/$max_iterations"

        # Get files changed since we started
        local changed_files
        changed_files=$(get_changed_files)

        if [[ -z "$changed_files" ]]; then
            log_info "No files changed, skipping review"
            break
        fi

        log_info "Files to review: $(echo "$changed_files" | wc -l | tr -d ' ') files"

        # Run 3 reviews
        if ! run_3_reviews "$changed_files"; then
            log_ok "All reviews passed - no issues found"
            break
        fi

        # Issues were found, run fix pass
        run_fix_pass

        # Next iteration will review the fixes
    done

    if (( iteration >= max_iterations )); then
        log_warn "Reached max review iterations ($max_iterations)"
    fi
}

# === Send stop signal to SQS queue ===
send_stop_signal() {
    local queue_url="$1"
    aws_cmd sqs send-message \
        --queue-url "$queue_url" \
        --message-body '{"cmd":"stop"}' \
        >/dev/null 2>&1 && log_ok "Stop signal sent" || log_error "Failed to send stop signal"
    exit 0
}

# === Poll SQS queue for status messages ===
poll_status() {
    local queue_url="$1"
    log_info "Polling status queue (Ctrl+C to stop)..."
    while true; do
        local result
        result=$(aws_cmd sqs receive-message \
            --queue-url "$queue_url" \
            --max-number-of-messages 10 \
            --wait-time-seconds 5 \
            --query 'Messages[*].[Body,ReceiptHandle]' \
            --output json 2>/dev/null) || continue

        if [[ "$result" != "null" && "$result" != "[]" ]]; then
            echo "$result" | jq -r '.[] | .[0]' 2>/dev/null | while read -r body; do
                local ts msg src
                ts=$(echo "$body" | jq -r '.ts // empty' 2>/dev/null)
                src=$(echo "$body" | jq -r '.src // "?"' 2>/dev/null)
                msg=$(echo "$body" | jq -r '.msg // .cmd // empty' 2>/dev/null)
                [[ -n "$msg" ]] && echo "[$ts][$src] $msg"
            done
            # Delete received messages
            echo "$result" | jq -r '.[] | .[1]' 2>/dev/null | while read -r handle; do
                aws_cmd sqs delete-message --queue-url "$queue_url" --receipt-handle "$handle" 2>/dev/null || true
            done
        fi
    done
}

# === Usage ===
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <prompt>
       $(basename "$0") [OPTIONS] -f <prompt-file>
       $(basename "$0") --stop <queue-url>
       $(basename "$0") --poll <queue-url>

Run Claude Code headlessly on an ephemeral EC2 instance.

Options:
  -f, --file FILE      Read prompt from file
  -o, --output FILE    Save output to file (default: stream to stdout)
  -t, --instance-type  Instance type (default: $INSTANCE_TYPE)
  -r, --repo URL       Git repo to clone (clones to workspace/)
  -b, --branch NAME    Branch to checkout (default: main)
  --no-repo            Skip repo clone (use existing workspace)
  --ultracode          Enable ultracode mode (workflow orchestration + 3x3 reviews)
  --stop <queue-url>   Send stop signal to running instance via SQS
  --poll <queue-url>   Poll status messages from SQS queue
  -h, --help           Show this help message

Environment Variables:
  EC2_CLAUDE_AMI_ID    AMI ID for the instance (default: Amazon Linux 2023 ARM64)
  EC2_CLAUDE_KEY_NAME  EC2 key pair name (default: claude-runner)
  EC2_CLAUDE_SSH_KEY   Path to SSH private key (default: ~/.ssh/claude-runner.pem)
  EC2_CLAUDE_SG        Security group ID (must allow SSH)
  EC2_CLAUDE_SUBNET    Subnet ID in us-east-2a

Examples:
  # Simple prompt
  $(basename "$0") "Analyze the Python code in src/ for potential bugs"

  # Read prompt from file
  $(basename "$0") -f task.txt

  # Save output to file
  $(basename "$0") -o results.md "Generate a test suite for the API module"

  # Poll status from another terminal
  $(basename "$0") --poll https://sqs.us-east-2.amazonaws.com/123/queue-name

  # Stop a running instance
  $(basename "$0") --stop https://sqs.us-east-2.amazonaws.com/123/queue-name

Notes:
  - The EBS volume ($EBS_VOLUME_ID) must contain:
    - env.sh: exports ANTHROPIC_API_KEY and any other needed env vars
    - Optionally: workspace/ directory as working directory
  - Instance is automatically terminated on completion or interrupt
  - SQS queue URL is printed at startup for use with --poll and --stop
  - Uses AWS profile: $AWS_PROFILE

EOF
    exit 0
}

# === Main ===
main() {
    local prompt=""
    local prompt_file=""
    local output_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -f|--file)
                [[ -z "${2:-}" ]] && { log_error "-f requires a filename"; exit 1; }
                prompt_file="$2"
                shift 2
                ;;
            -o|--output)
                [[ -z "${2:-}" ]] && { log_error "-o requires a filename"; exit 1; }
                output_file="$2"
                shift 2
                ;;
            -t|--instance-type)
                [[ -z "${2:-}" ]] && { log_error "-t requires an instance type"; exit 1; }
                INSTANCE_TYPE="$2"
                shift 2
                ;;
            -r|--repo)
                [[ -z "${2:-}" ]] && { log_error "-r requires a repo URL"; exit 1; }
                REPO_URL="$2"
                shift 2
                ;;
            -b|--branch)
                [[ -z "${2:-}" ]] && { log_error "-b requires a branch name"; exit 1; }
                REPO_BRANCH="$2"
                shift 2
                ;;
            --no-repo)
                REPO_URL=""
                shift
                ;;
            --ultracode)
                ULTRACODE_MODE=true
                shift
                ;;
            --stop)
                [[ -z "${2:-}" ]] && { log_error "--stop requires a queue URL"; exit 1; }
                send_stop_signal "$2"
                ;;
            --poll)
                [[ -z "${2:-}" ]] && { log_error "--poll requires a queue URL"; exit 1; }
                poll_status "$2"
                ;;
            -)
                # Read from stdin
                prompt=$(cat)
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                ;;
            *)
                prompt="$1"
                shift
                ;;
        esac
    done

    # Get prompt from file if specified
    if [[ -n "$prompt_file" ]]; then
        if [[ ! -f "$prompt_file" ]]; then
            log_error "Prompt file not found: $prompt_file"
            exit 1
        fi
        prompt=$(cat "$prompt_file")
    fi

    # Validate prompt
    if [[ -z "$prompt" ]]; then
        log_error "No prompt provided"
        echo >&2
        usage
    fi

    # Prepend ultracode keyword if enabled
    if [[ "$ULTRACODE_MODE" == "true" ]]; then
        prompt="ultracode $prompt"
        log_info "Mode: ULTRACODE (workflow orchestration enabled)"
    fi

    # Show what we're about to do
    local prompt_preview="${prompt:0:100}"
    (( ${#prompt} > 100 )) && prompt_preview+="..."
    log_info "Prompt: $prompt_preview"
    log_info "Instance type: $INSTANCE_TYPE"
    log_info "AWS Profile: $AWS_PROFILE"
    [[ -n "$REPO_URL" ]] && log_info "Repo: $REPO_URL ($REPO_BRANCH)"

    # Run the workflow
    check_prerequisites
    create_sqs_queue

    sqs_status "Launching instance"
    launch_instance

    sqs_status "Attaching EBS volume"
    attach_volume

    log_info "Waiting for SSH to become available..."
    sqs_status "Waiting for SSH"
    wait_ssh_ready "$PUBLIC_IP"
    log_ok "SSH ready"

    sqs_status "Mounting volume"
    mount_volume

    # Set up workspace with git repo if specified
    if [[ -n "$REPO_URL" ]]; then
        sqs_status "Setting up workspace"
        setup_workspace "$REPO_URL" "$REPO_BRANCH"
    fi

    run_claude "$prompt" "$output_file"
    log_info "Back from run_claude, ULTRACODE_MODE=$ULTRACODE_MODE"

    # Run orchestrated review loop if ultracode mode
    if [[ "$ULTRACODE_MODE" == "true" ]]; then
        log_info "=== ULTRACODE: Starting 3x3 review cycles ==="
        sqs_status "Starting review cycles"
        run_review_loop
    else
        log_info "Not ultracode mode, skipping reviews"
    fi

    # Cleanup happens via EXIT trap
    sqs_status "Task complete"
    log_ok "Task complete"
}

main "$@"
