<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Python Native TUI Support Matrix

This document describes what the Python native LCI TUI supports without
hardware, what requires firmware or host Bluetooth access, and how to run smoke
tests without hiding unsupported paths.

## Commands

| Command | Purpose | Hardware required |
|---------|---------|-------------------|
| `lichen-native-client --help` | Packaging and CLI smoke check. | No |
| `lichen-native-client` | Launch native TUI in disconnected demo mode. | No |
| `lichen-native-client --coap-base-uri 'coap://[fe80::7002:e7b4:4a75:c734%25en0]'` | Native LCI over IP/CoAP. | Requires reachable LCI CoAP endpoint for live traffic |
| `lichen-native-tui ...` | Backward-compatible alias for `lichen-native-client`. | Same as native client |
| `lichen-tui ...` | Simulator node TUI, not the native LCI client. | No |

## Host Support Matrix

| Host path | Current support | Assumptions | Validation |
|-----------|-----------------|-------------|------------|
| macOS, no hardware | Supported for unit, renderer, CLI-help, and fake transport tests. | Python 3.11+, `uv`, terminal with Textual support. | `uv run pytest tests/tui tests/client tests/test_packaging.py -q` |
| Linux, no hardware | Supported for unit, renderer, CLI-help, and fake transport tests. | Python 3.11+, `uv`; no BlueZ adapter access is required for default tests. | Same pytest command as macOS |
| IP/CoAP local node | Software path implemented. | Host can route to the node IPv6 address and the firmware exposes LCI CoAP resources such as `/status`, `/config`, `/msg/inbox`, `/logs`, and `/diag`. | Manual smoke below; physical validation tracked by `project-LICHEN-mg7z` |
| BLE native LCI | Packet discovery pieces exist, but the Python TUI cannot use BLE as an LCI `ResourceTransport` yet. | Needs BLE LCI UUID discovery plus CoAP-over-packet or equivalent ResourceTransport bridge. | Software bridge tracked by `project-LICHEN-q279`; physical smoke by `project-LICHEN-mg7z` |
| native_sim/fakes | Supported for client model, renderer, Observe, and key-flow tests. | Fake transports must remain the default CI path. | `tests/tui`, `tests/client`, `tests/test_packaging.py` |

## Firmware Prerequisites

For live IP/CoAP smoke testing, the firmware or simulator endpoint must expose
the LCI CoAP contract used by `LciClient`:

- `GET /.well-known/core`
- `GET /status`
- `GET /config`
- `GET /config/radio`
- `GET /config/identity`
- `GET /status/neighbors`
- `GET /status/routes`
- `GET /msg/inbox`
- `POST /msg/inbox`
- `GET /msg/sent`, when sent-message history is supported
- `POST /msg/ack`, when delivery/read/failure receipts are supported
- `GET /logs` with Observe, when logs are supported
- `GET /diag`, when diagnostics are supported

The Python native client follows the LCI IPv6 + CoAP contract in
`spec/11-lci.md`. It does not implement the historical CBOR native framing in
`spec/lichen-native/` for BLE, USB, serial, or IP LCI sessions.

Mesh-node access follows the same contract: baseline link-local clients send
requests to the node's RFC 7252 forward proxy with the target native address in
`Proxy-Uri`. Direct mesh routing requires a separately provisioned
client identity and participation profile; `/mesh` is not a native LCI proxy
endpoint.

The legacy Python demo/simulator `/messages` resource is not a native LCI
messaging contract. Native clients use `/msg/inbox`; `/messages` may be used
only when explicitly configured for legacy demo compatibility.

## Known Limitations

- There is no native TUI connection picker yet. The TUI can launch in demo mode
  or with `--coap-base-uri`; picker work is tracked by `project-LICHEN-xmrv`.
- BLE cannot drive the native TUI until a BLE-backed `ResourceTransport` exists.
  The bridge is tracked by `project-LICHEN-q279`.
- Config editing is intentionally allowlisted to `name`, `role`, `freq_mhz`,
  `bw_khz`, `sf`, `cr`, and `tx_power_dbm`. Read-only or unknown fields are
  rejected before transport writes.
- Raw diagnostics and key-like fields are redacted in the TUI. Current Python
  TUI diagnostics use the generic optional `/diag` CoAP resource; raw RX/TX
  controls under `/diag/raw/*` are not exposed until a Bead adds explicit UI
  arming, Observe, and transmit flows.
- Terminal visual target is a normal 80x24 or larger text terminal. Tests cover
  80x24, 100x30, and resize behavior through Textual screenshots and render
  assertions.

## No-Hardware Smoke Test

Run this before any manual hardware session:

```bash
cd python
uv run ruff check src/lichen/tui tests/tui tests/test_packaging.py pyproject.toml
uv run mypy src/lichen/tui tests/tui tests/test_packaging.py
uv run pytest tests/tui tests/client tests/test_packaging.py -q
uv run lichen-native-client --help
```

Expected result:

- Ruff passes.
- Mypy reports no issues.
- Pytest passes without BLE adapters, boards, radios, or BlueZ access.
- `uv run lichen-native-client --help` prints CLI usage and exits with status 0.

## IP/CoAP Manual Smoke Test

Use this only when a local LCI CoAP endpoint is reachable.

1. Record host OS, Python version, command line, firmware commit, board, and
   firmware config.
2. Confirm IPv6 reachability to the local node address.
3. Launch:

   ```bash
   lichen-native-client --coap-base-uri 'coap://[fe80::7002:e7b4:4a75:c734%25en0]'
   ```

   Replace `en0` with the host interface that reaches the node. For Linux this
   may be `wlan0`, `eth0`, or a bridge/tap interface. A native Yggdrasil
   address may be used when the host has a route to the LICHEN mesh.

4. Press `r` on Dashboard and confirm device, battery/time placeholders,
   resources, radio, and DODAG rows render without secret material.
5. Press `2`, then `r`, and confirm inbox rendering. Use `c` to compose a
   message, fill target/body, and press Enter from the body field.
6. Press `3` and `4`, then `r`, and confirm neighbor and route rows render or
   show explicit empty/unsupported state.
7. Press `5`, then `r`, and confirm config rows render. Use `/` to stage one
   allowlisted config edit. Press Enter to open confirmation, then Escape to
   cancel. Repeat and press `y` only when the Bead explicitly asks for a write.
8. Press `6`, then `o`, and confirm logs update or show an actionable
   unsupported/error state.
9. Press `7`, then `r`, and confirm diagnostics flattening and redaction.

Record all failures in the Bead that requested the smoke run. Do not close a
hardware-validation Bead from fake or simulator evidence alone.

## BLE Manual Smoke Test

BLE live smoke is blocked until `project-LICHEN-q279` provides a BLE-backed
LCI `ResourceTransport`.

When unblocked:

1. Install `uv pip install -e ".[native-client,ble]"`.
2. On macOS, grant Bluetooth permission to the terminal app when prompted.
3. On Linux, confirm BlueZ is running, the adapter is powered, and the test user
   has D-Bus Bluetooth access.
4. Record adapter, OS, firmware commit/config, advertised name, service UUIDs,
   pairing prompts, and MTU if visible.
5. Run the same Dashboard, Chats, Mesh, Config, Logs, and Diagnostics checks as
   the IP/CoAP smoke test.

If BLE discovery succeeds but CoAP resources cannot be reached through the BLE
transport, keep the result as a partial BLE transport smoke and file or update
the blocking Bead with exact evidence.
