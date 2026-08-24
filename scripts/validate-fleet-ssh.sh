#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# validate-fleet-ssh.sh - Validate EC2 fleet SSH authentication path
#
# This script launches exactly one EC2 instance and validates the full SSH
# authentication flow including:
#   1. Console fingerprint extraction (ED25519, falling back to ECDSA)
#   2. ssh-keyscan key retrieval
#   3. Fingerprint verification
#   4. SCP file transfer
#   5. Reverse SSH tunnel establishment
#   6. Clean termination
#
# Usage:
#   ./scripts/validate-fleet-ssh.sh           # Normal mode
#   ./scripts/validate-fleet-ssh.sh --verbose # Verbose diagnostics
#
set -euo pipefail

# === Configuration ===
AWS_PROFILE="${AWS_PROFILE:-personal}"
AWS_REGION="${AWS_REGION:-us-west-2}"
EXPECTED_AWS_ACCOUNT="210337117346"
INSTANCE_TYPE="${EC2_INSTANCE_TYPE:-c7g.medium}"
AMI_ID="${EC2_AMI_ID:-ami-0764d1b512e22671f}"
KEY_NAME="${EC2_KEY_NAME:-markatwood}"
EC2_SSH_KEY="${EC2_SSH_KEY:-$HOME/.ssh/id_ed25519}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse args
VERBOSE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v) VERBOSE=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--verbose]"
            echo ""
            echo "Validate EC2 fleet SSH authentication path."
            echo "Options:"
            echo "  --verbose, -v   Show detailed diagnostic output"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# State
INSTANCE_ID=""
SG_ID=""
RUN_ID="validate-ssh-$(date +%s)-$$"
KNOWN_HOSTS=$(mktemp "${TMPDIR:-/tmp}/lichen-validate-known-hosts.XXXXXX")
DIAG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lichen-validate-ssh-diag.XXXXXX")
TUNNEL_PID=""
KEY_TYPE_USED=""

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
log_diag()  { [[ "$VERBOSE" == "true" ]] && echo -e "${YELLOW}[DIAG]${NC} $*" >&2 || true; }

# AWS CLI wrapper
aws_cmd() {
    aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"
}

cleanup() {
    local exit_code=$?
    trap - EXIT
    log_info "Cleaning up..."

    # Kill tunnel
    [[ -n "$TUNNEL_PID" ]] && kill "$TUNNEL_PID" 2>/dev/null || true

    # Terminate instance
    if [[ -n "$INSTANCE_ID" ]]; then
        log_info "Terminating instance $INSTANCE_ID..."
        aws_cmd ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null 2>&1 || true
        aws_cmd ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" 2>/dev/null || true
    fi

    # Delete security group
    if [[ -n "$SG_ID" ]]; then
        for _ in {1..6}; do
            if aws_cmd ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1; then
                break
            fi
            sleep 5
        done
    fi

    # Cleanup temp files
    rm -f "$KNOWN_HOSTS"

    # Keep diagnostics on failure if verbose
    if [[ $exit_code -ne 0 && "$VERBOSE" == "true" ]]; then
        log_info "Diagnostic files preserved at: $DIAG_DIR"
    else
        rm -rf "$DIAG_DIR"
    fi

    exit $exit_code
}
trap cleanup EXIT

# Extract fingerprint from console for a given key type
# Args: $1=console_output, $2=key_type (ED25519|ECDSA|RSA)
extract_console_fingerprint() {
    local console=$1 key_type=$2 fp=""

    # Try standard SSH HOST KEY FINGERPRINTS section first
    fp=$(printf '%s\n' "$console" | sed -n \
        -e "/BEGIN SSH HOST KEY FINGERPRINTS/,/END SSH HOST KEY FINGERPRINTS/ {" \
        -e "/($key_type)/ {" \
        -e "s/^.*\(SHA256:[A-Za-z0-9+\/=]*\).*$/\1/p" \
        -e "}" -e "}")

    # Fallback: key generation output
    if [[ -z "$fp" ]]; then
        case "$key_type" in
            ED25519)
                fp=$(printf '%s\n' "$console" | sed -n \
                    -e '/Generating public\/private ed25519 key pair/,/Generating public\/private ecdsa key pair/ {' \
                    -e 's/^.*\(SHA256:[A-Za-z0-9+\/=]*\).*$/\1/p' \
                    -e '}')
                ;;
            ECDSA)
                fp=$(printf '%s\n' "$console" | sed -n \
                    -e '/Generating public\/private ecdsa key pair/,/Generating public\/private.*key pair/ {' \
                    -e 's/^.*\(SHA256:[A-Za-z0-9+\/=]*\).*$/\1/p' \
                    -e '}')
                ;;
        esac
    fi

    # Return single unique fingerprint or empty
    if [[ -n "$fp" && "$fp" != *$'\n'* ]]; then
        printf '%s' "$fp"
    fi
}

# Authenticate EC2 host with multi-key-type support
# Args: $1=instance_id, $2=host
# Sets: KEY_TYPE_USED (global)
authenticate_ec2_host() {
    local instance_id=$1 host=$2
    local console expected="" scanned="" actual=""
    local attempt key_type ssh_key_type
    local console_file="$DIAG_DIR/console-$instance_id.txt"
    local keyscan_file="$DIAG_DIR/keyscan-$instance_id.txt"

    log_info "Authenticating $instance_id ($host)..."

    # Get console output with fingerprints
    log_diag "Waiting for console output with SSH fingerprints..."
    for attempt in {1..60}; do
        if console=$(aws_cmd ec2 get-console-output --instance-id "$instance_id" --latest \
                --query Output --output text 2>/dev/null); then
            printf '%s' "$console" > "$console_file"

            # Try ED25519 first, then ECDSA
            for key_type in ED25519 ECDSA; do
                expected=$(extract_console_fingerprint "$console" "$key_type")
                if [[ -n "$expected" ]]; then
                    log_diag "Found $key_type fingerprint in console: $expected"
                    break 2
                fi
            done
        fi
        log_diag "Attempt $attempt/60: No fingerprint yet, waiting..."
        sleep 5
    done

    if [[ -z "$expected" ]]; then
        log_error "No trusted fingerprint found in console output for $instance_id"
        if [[ "$VERBOSE" == "true" ]]; then
            log_error "Console output saved to: $console_file"
            log_error "Available key types in console:"
            grep -E '(ED25519|ECDSA|RSA|SHA256:)' "$console_file" 2>/dev/null || echo "  (none found)"
        fi
        return 1
    fi

    # Map key type to ssh-keyscan format
    case "$key_type" in
        ED25519) ssh_key_type="ed25519" ;;
        ECDSA)   ssh_key_type="ecdsa" ;;
        *)       log_error "Unknown key type: $key_type"; return 1 ;;
    esac

    log_info "Using $key_type key for authentication"

    # Scan for host key
    log_diag "Scanning for $ssh_key_type host key from $host..."
    for attempt in {1..12}; do
        # Capture both stdout and stderr for diagnostics
        if scanned=$(ssh-keyscan -T 5 -t "$ssh_key_type" "$host" 2>"$keyscan_file.stderr"); then
            printf '%s' "$scanned" > "$keyscan_file"
            [[ -n "$scanned" ]] && break
        fi
        log_diag "Attempt $attempt/12: keyscan returned empty, waiting..."

        # Diagnostic: try all key types to see what's available
        if [[ "$VERBOSE" == "true" && $attempt -eq 6 ]]; then
            log_diag "Probing all key types from $host..."
            for probe_type in ed25519 ecdsa rsa; do
                probe_result=$(ssh-keyscan -T 5 -t "$probe_type" "$host" 2>/dev/null) || true
                if [[ -n "$probe_result" ]]; then
                    log_diag "  $probe_type: AVAILABLE"
                else
                    log_diag "  $probe_type: not available"
                fi
            done
        fi
        sleep 5
    done

    if [[ -z "$scanned" ]]; then
        log_error "Could not retrieve $ssh_key_type host key from $host"
        if [[ "$VERBOSE" == "true" ]]; then
            log_error "keyscan stderr:"
            cat "$keyscan_file.stderr" 2>/dev/null || echo "  (empty)"
            log_error "Probing all key types..."
            for probe_type in ed25519 ecdsa rsa; do
                probe_result=$(ssh-keyscan -T 5 -t "$probe_type" "$host" 2>/dev/null) || true
                if [[ -n "$probe_result" ]]; then
                    log_error "  $probe_type: $(printf '%s' "$probe_result" | ssh-keygen -E sha256 -lf - 2>/dev/null | head -1)"
                else
                    log_error "  $probe_type: not available"
                fi
            done
        fi
        return 1
    fi

    # Handle multiple lines (shouldn't happen with -t, but guard against it)
    if [[ "$scanned" == *$'\n'* ]]; then
        log_error "Received multiple keys from ssh-keyscan (expected unique)"
        return 1
    fi

    # Verify fingerprint
    actual=$(printf '%s\n' "$scanned" | ssh-keygen -E sha256 -lf - 2>/dev/null |
        sed -n 's/^[0-9][0-9]* \(SHA256:[^ ]*\) .*$/\1/p')

    if [[ -z "$actual" ]]; then
        log_error "Could not compute fingerprint from scanned key"
        return 1
    fi

    log_diag "Console fingerprint: $expected"
    log_diag "Scanned fingerprint: $actual"

    if [[ "$actual" != "$expected" ]]; then
        log_error "SSH host key mismatch for $instance_id ($host)"
        log_error "  Console: $expected"
        log_error "  Scanned: $actual"
        return 1
    fi

    # Add to known_hosts
    printf '%s\n' "$scanned" >> "$KNOWN_HOSTS"
    KEY_TYPE_USED="$ssh_key_type"

    log_ok "Host authenticated: $key_type fingerprint verified"
    return 0
}

# === Main ===
log_info "=== LICHEN Fleet SSH Validation ==="
log_info "Run ID: $RUN_ID"

# Verify AWS account
CALLER_ACCOUNT=$(aws_cmd sts get-caller-identity --query Account --output text)
if [[ "$CALLER_ACCOUNT" != "$EXPECTED_AWS_ACCOUNT" ]]; then
    log_error "AWS profile $AWS_PROFILE resolves to account $CALLER_ACCOUNT, expected $EXPECTED_AWS_ACCOUNT"
    exit 1
fi
log_ok "AWS account verified: $CALLER_ACCOUNT"

# Verify AMI
read -r AMI_OWNER AMI_ARCH AMI_STATE AMI_PROJECT <<< "$(aws_cmd ec2 describe-images \
    --image-ids "$AMI_ID" \
    --query 'Images[0].[OwnerId,Architecture,State,Tags[?Key==`Project`].Value|[0]]' \
    --output text)"
if [[ "$AMI_OWNER" != "$EXPECTED_AWS_ACCOUNT" || "$AMI_ARCH" != "arm64" || \
      "$AMI_STATE" != "available" || "$AMI_PROJECT" != "LICHEN" ]]; then
    log_error "AMI $AMI_ID is not an available account-owned ARM64 LICHEN runtime"
    exit 1
fi
log_ok "AMI verified: $AMI_ID"

# Get our public IP
PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || curl -s https://ipinfo.io/ip)
log_info "Coordinator IP: $PUBLIC_IP"

# Create security group
SG_NAME="lichen-validate-ssh-$RUN_ID"
log_info "Creating security group..."
SG_ID=$(aws_cmd ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "LICHEN SSH validation" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=LICHEN},{Key=Purpose,Value=validate-ssh},{Key=LaunchedBy,Value=validate-fleet-ssh.sh},{Key=RunId,Value=$RUN_ID}]" \
    --query 'GroupId' --output text)
aws_cmd ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${PUBLIC_IP}/32" >/dev/null
log_ok "Security group: $SG_ID"

# Launch instance
log_info "Launching EC2 instance ($INSTANCE_TYPE)..."
INSTANCE_ID=$(aws_cmd ec2 run-instances \
    --client-token "$RUN_ID" \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=validate-ssh},{Key=Project,Value=LICHEN},{Key=Purpose,Value=validate-ssh},{Key=LaunchedBy,Value=validate-fleet-ssh.sh},{Key=RunId,Value=$RUN_ID}]" \
    --query 'Instances[0].InstanceId' --output text)
log_ok "Instance launched: $INSTANCE_ID"

# Wait for instance
log_info "Waiting for instance to be running..."
aws_cmd ec2 wait instance-running --instance-ids "$INSTANCE_ID"
aws_cmd ec2 wait instance-status-ok --instance-ids "$INSTANCE_ID"
log_ok "Instance running"

# Get public IP
INSTANCE_IP=$(aws_cmd ec2 describe-instances --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
log_info "Instance IP: $INSTANCE_IP"

# === Test 1: SSH Authentication ===
log_info ""
log_info "=== Test 1: SSH Authentication ==="
if ! authenticate_ec2_host "$INSTANCE_ID" "$INSTANCE_IP"; then
    log_error "TEST 1 FAILED: SSH authentication"
    exit 1
fi
log_ok "TEST 1 PASSED: SSH authentication (key type: $KEY_TYPE_USED)"

# Build SSH options based on key type
SSH_OPTS=(
    -i "$EC2_SSH_KEY"
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=yes
    -o "HostKeyAlgorithms=ssh-$KEY_TYPE_USED"
    -o UpdateHostKeys=no
)

# SCP options
SCP_LEGACY=()
if ! scp -O 2>&1 | grep -E 'unknown option|illegal option' >/dev/null; then
    SCP_LEGACY=(-O)
fi

# === Test 2: SSH Connection ===
log_info ""
log_info "=== Test 2: SSH Connection ==="
if ! ssh "${SSH_OPTS[@]}" -o ConnectTimeout=30 "ec2-user@$INSTANCE_IP" 'echo "SSH connection successful"'; then
    log_error "TEST 2 FAILED: SSH connection"
    exit 1
fi
log_ok "TEST 2 PASSED: SSH connection"

# === Test 3: SCP File Transfer ===
log_info ""
log_info "=== Test 3: SCP File Transfer ==="
TEST_FILE=$(mktemp "${TMPDIR:-/tmp}/lichen-validate-test.XXXXXX")
echo "LICHEN SSH validation test file - $(date)" > "$TEST_FILE"

if ! scp "${SCP_LEGACY[@]}" "${SSH_OPTS[@]}" -o ConnectTimeout=30 "$TEST_FILE" "ec2-user@$INSTANCE_IP:/tmp/test-upload.txt"; then
    rm -f "$TEST_FILE"
    log_error "TEST 3 FAILED: SCP upload"
    exit 1
fi

# Verify the file arrived correctly
REMOTE_CONTENT=$(ssh "${SSH_OPTS[@]}" "ec2-user@$INSTANCE_IP" 'cat /tmp/test-upload.txt' 2>/dev/null)
LOCAL_CONTENT=$(cat "$TEST_FILE")
rm -f "$TEST_FILE"

if [[ "$REMOTE_CONTENT" != "$LOCAL_CONTENT" ]]; then
    log_error "TEST 3 FAILED: SCP content mismatch"
    exit 1
fi
log_ok "TEST 3 PASSED: SCP file transfer"

# === Test 4: Reverse SSH Tunnel ===
log_info ""
log_info "=== Test 4: Reverse SSH Tunnel ==="
TUNNEL_LOCAL_PORT=15555
TUNNEL_REMOTE_PORT=15555

# Start a simple listener on local machine
(echo "tunnel-test-marker"; sleep 60) | nc -l "$TUNNEL_LOCAL_PORT" &
LISTENER_PID=$!
sleep 1

# Create reverse tunnel
ssh "${SSH_OPTS[@]}" -N -R "$TUNNEL_REMOTE_PORT:127.0.0.1:$TUNNEL_LOCAL_PORT" \
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
    "ec2-user@$INSTANCE_IP" &
TUNNEL_PID=$!
sleep 2

if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
    log_error "TEST 4 FAILED: Reverse tunnel could not be established"
    exit 1
fi

# Test the tunnel by connecting from remote side
TUNNEL_RESULT=$(ssh "${SSH_OPTS[@]}" "ec2-user@$INSTANCE_IP" \
    "echo '' | nc -w 2 127.0.0.1 $TUNNEL_REMOTE_PORT | head -1" 2>/dev/null || true)

kill "$LISTENER_PID" 2>/dev/null || true
kill "$TUNNEL_PID" 2>/dev/null || true
TUNNEL_PID=""

if [[ "$TUNNEL_RESULT" != "tunnel-test-marker" ]]; then
    log_error "TEST 4 FAILED: Reverse tunnel data verification"
    log_error "  Expected: tunnel-test-marker"
    log_error "  Got: $TUNNEL_RESULT"
    exit 1
fi
log_ok "TEST 4 PASSED: Reverse SSH tunnel"

# === Summary ===
log_info ""
log_ok "=== ALL TESTS PASSED ==="
log_ok "SSH authentication path validated successfully"
log_ok "  Key type: $KEY_TYPE_USED"
log_ok "  Instance: $INSTANCE_ID ($INSTANCE_IP)"
log_ok "  AMI: $AMI_ID"

exit 0
