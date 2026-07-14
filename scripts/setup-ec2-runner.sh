#!/bin/bash
# Setup EC2 instance as GitHub Actions self-hosted runner
# Run this on the EC2 instance after launch

set -euo pipefail

REPO_URL="https://github.com/MarkAtwood/project-LICHEN"
RUNNER_VERSION="2.321.0"

echo "=== LICHEN EC2 GitHub Actions Runner Setup ==="

# Check if running as ec2-user
if [ "$(whoami)" != "ec2-user" ]; then
    echo "Run as ec2-user"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
sudo dnf update -y
sudo dnf install -y \
    git \
    cmake \
    ninja-build \
    gcc \
    gcc-c++ \
    python3 \
    python3-pip \
    protobuf-compiler \
    jq

# Install Rust
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install west
pip3 install --user west

# Mount EBS if not mounted
if [ ! -d /mnt/lichen ]; then
    echo "EBS not mounted. Mount with:"
    echo "  sudo mkdir -p /mnt/lichen"
    echo "  sudo mount /dev/xvdf /mnt/lichen"
    echo "  sudo chown ec2-user:ec2-user /mnt/lichen"
fi

# Setup runner directory
RUNNER_DIR="$HOME/actions-runner"
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

# Download runner if not present
if [ ! -f run.sh ]; then
    echo "Downloading GitHub Actions runner..."
    curl -o actions-runner-linux-arm64.tar.gz -L \
        "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz"
    tar xzf actions-runner-linux-arm64.tar.gz
    rm actions-runner-linux-arm64.tar.gz
fi

echo ""
echo "=== Runner downloaded ==="
echo ""
echo "To complete setup:"
echo "1. Go to: ${REPO_URL}/settings/actions/runners/new"
echo "2. Select 'Linux' and 'ARM64'"
echo "3. Copy the token from the 'Configure' section"
echo "4. Run:"
echo "   cd $RUNNER_DIR"
echo "   ./config.sh --url $REPO_URL --token YOUR_TOKEN --labels lichen,arm64"
echo ""
echo "5. To run as a service:"
echo "   sudo ./svc.sh install"
echo "   sudo ./svc.sh start"
echo ""
echo "6. Verify with: sudo ./svc.sh status"
