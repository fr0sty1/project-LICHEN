#!/bin/bash
# install-rpi-border-router.sh
# Installs LICHEN RPi border router with systemd, WireGuard, Prometheus scraping, and SSH hardening.
# Run as root on Raspberry Pi with LoRa HAT.

set -e

echo "=== LICHEN RPi Border Router Installer ==="

# Install dependencies
apt-get update
apt-get install -y wireguard wireguard-tools prometheus-node-exporter prometheus iptables-persistent

# Build and install binary (assumes Rust toolchain or prebuilt)
if command -v cargo >/dev/null 2>&1; then
  echo "Building lichend from source..."
  cargo install --path /path/to/rust/lichen-gateway --force
else
  echo "Downloading prebuilt lichend (replace with actual URL)..."
  curl -L -o /usr/local/bin/lichend https://example.com/lichend
  chmod +x /usr/local/bin/lichend
fi

# Create directories
mkdir -p /etc/lichen /etc/wireguard /var/log/lichen
chmod 700 /etc/wireguard

# Copy configs
cp deploy/lichend-rpi.service /etc/systemd/system/lichend.service
cp deploy/wg0.conf.example /etc/wireguard/wg0.conf
cp deploy/lichend.toml.example /etc/lichen/gateway.toml

# Generate WireGuard keys if not present
if [ ! -f /etc/wireguard/private.key ]; then
  wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
  chmod 600 /etc/wireguard/private.key
  sed -i "s|<your-private-key-here>|$(cat /etc/wireguard/private.key)|" /etc/wireguard/wg0.conf
fi

# SSH hardening
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Enable services
systemctl daemon-reload
systemctl enable --now wireguard@wg0.service
systemctl enable --now lichend.service
systemctl enable --now prometheus-node-exporter.service

echo "Installation complete. Edit /etc/lichen/gateway.toml and /etc/wireguard/wg0.conf."
echo "Check status with: systemctl status lichend"
echo "Metrics at http://localhost:9100/metrics"
