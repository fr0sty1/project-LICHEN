# RPi LoRa HAT Border Router Deployment

## Overview

The LICHEN border router on Raspberry Pi with a LoRa HAT bridges the LoRa IPv6 mesh to the internet. It uses the Rust `lichen-gateway` binary with SPI driver for concentrator HATs (SX1302/8-channel recommended) or single-channel SX1262 for testing. The BR acts as RPL root, 6LBR, and CoAP proxy.

It supports:
- Multi-channel LoRa reception
- RPL DODAG root with non-storing mode
- OSCORE termination for LCI and upstream
- Prometheus metrics for monitoring
- Node OTA proxying

## Hardware Requirements

- Raspberry Pi 4 or 5 (4GB RAM minimum, 8GB recommended for Grafana)
- LoRa HAT:
  - RAK2287 (SX1302 concentrator, 8 channels, recommended)
  - Waveshare SX1262 HAT (single channel for development)
  - RAK5146 USB variant (alternative)
- LoRa antenna (868/915 MHz, 5dBi+)
- Optional: u-blox GPS module for precise time (PPS + UART)
- Ethernet for upstream connectivity
- 32GB+ SD card, 5V/3A power supply

**BOM (approximate USD):**
- RPi 5: $60
- RAK2287 HAT: $120
- Antenna + pigtail: $15
- GPS module: $20
- Case, cables: $20
- Total: ~$235

Procurement: Seeed, RAK Wireless, DigiKey, Amazon. Verify SPI compatibility and kernel support.

## Wiring

1. Mount HAT on RPi 40-pin GPIO.
2. SPI0 (GPIO 7-11): MOSI, MISO, SCLK, CE0/1 for concentrator.
3. Reset (GPIO 17 or per HAT), IRQ (GPIO 22), Power En.
4. For GPS: UART0 (GPIO 14/15) + PPS (GPIO 18).
5. Antenna to u.FL or SMA on HAT.

See `lichen/boards/rpi/rpi4_lora_hat.overlay` for DeviceTree. Enable SPI/I2C/UART in `/boot/firmware/config.txt`:

```
dtparam=spi=on
dtparam=i2c_arm=on
enable_uart=1
```

Reboot after changes.

## OS Image Preparation

1. Download Raspberry Pi OS Lite (64-bit Bookworm) from raspberrypi.com/software/
2. Write to SD card using Raspberry Pi Imager (enable SSH, set username/password, configure WiFi/Ethernet).
3. Boot the Pi, login, run:
   ```
   sudo apt update && sudo apt full-upgrade -y
   sudo apt install -y git curl build-essential pkg-config libssl-dev libclang-dev prometheus prometheus-node-exporter grafana
   ```
4. Install Rust:
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source $HOME/.cargo/env
   rustup default stable
   ```
5. Clone LICHEN:
   ```
   git clone https://github.com/anomalyco/LICHEN.git
   cd LICHEN
   ```

## Installation

1. Build the gateway:
   ```
   cd rust
   cargo build --release -p lichen-gateway
   sudo cp target/release/lichend /usr/local/bin/
   ```
2. Create systemd service `/etc/systemd/system/lichen-border.service`:

```ini
[Unit]
Description=LICHEN Border Router
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lichend --hat rak2287 --freq 915 --prometheus 9091
WorkingDirectory=/home/pi/LICHEN
User=pi
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Enable and start:
   ```
   sudo systemctl daemon-reload
   sudo systemctl enable --now lichen-border
   ```
4. Configure HAT in command line flags or config.toml (SPI dev, power, channels, spreading factor).

## Configuration

- Edit `/etc/lichen-border.toml` for DODAG ID, OSCORE keys, upstream prefix, GPS serial.
- Prometheus: scrape localhost:9091/metrics
- Grafana: add Prometheus datasource, import LICHEN dashboard JSON for mesh metrics, RPL DODAG, packet rates, CPU/RSSI.

Example config snippet for RAK2287:

```toml
hat = "rak2287"
spi_dev = "/dev/spidev0.0"
reset_gpio = 17
irq_gpio = 22
frequency = 915000000
bandwidth = 125000
spreading_factor = 7
```

## Monitoring

- Prometheus at :9091/metrics exposes node count, TX/RX packets, RPL parents, memory, CPU.
- Grafana dashboard at localhost:3000 with panels for:
  - Mesh size and DODAG stability
  - Packet loss and latency
  - RSSI/SNR heat map
  - Border upstream bandwidth
- Alerts for high packet loss, DODAG instability, low battery on nodes.

Use `lichen-gateway --metrics` for JSON export.

## OTA and Node Management

The BR proxies SMP/DFU for nodes via CoAP or BLE.

- Use `smp-flash.py` with rfc2217 bridge for OTA.
- Nodes advertise via announce, BR maintains node DB.
- Command line: `lichend --ota-proxy` for automated firmware push.

## Troubleshooting

- SPI not detected: `ls /dev/spi*`, check dtoverlay.
- HAT not responding: check reset GPIO, power, antenna.
- High CPU: reduce channels or use single-channel HAT.
- Prometheus not scraping: check firewall, port 9091.
- GPS not locking: check UART, PPS pin, `gpsd` service.
- Merge conflicts in docs: rebase from main.

Logs: `journalctl -u lichen-border -f`

For full spec see `spec/07-border-router.md`.

## Procurement Notes

- RAK Wireless for production HATs (RAK2287 kit ~$130)
- Seeed Studio for Waveshare HATs (~$30 for single channel)
- Ensure FCC/CE certified antenna for region.
- Test with Heltec or T-Beam nodes for interop.

Updated: 2026-07-23
