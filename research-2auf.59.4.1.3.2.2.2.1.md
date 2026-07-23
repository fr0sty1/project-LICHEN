<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Research: Kconfig and overlays for native_posix BLE ingress excluding link layer

**Bead:** project-LICHEN-2auf.59.4.1.3.2.2.2.1
**Date:** 2026-07-23 (UTC)
**Consumed by:** beads .2 (conf/overlay creation), .3 (west build), .4 (validation summary)

## 1. Sources analyzed

| Source | Role | Key selections |
|--------|------|----------------|
| `lichen/tests/ble_ingress/prj.conf` | Unit/integration test for BLE ingress packet path | `ZTEST`, `NETWORKING`, `NET_IPV6=y` / `NET_IPV4=n`, ND/DAD/MLD off, `NET_L2_DUMMY=y`, entropy + test RNG, small pkt/buf pools (8/8/16/16) |
| `lichen/apps/gateway/prj.conf` | Full border-router image (the app under test) | LoRa radio (`SPI`, `LORA`), full LICHEN stack (`LICHEN_LINK`, `LICHEN_L2`, `LICHEN_LORA_L2`, `LICHEN_IPV6`, `LICHEN_RPL`, `LICHEN_OSCORE`), CoAP server, SLIP bridge, 8K main stack |
| `lichen/tests/ble_ipsp_transport/prj.conf` | BLE IPSP transport unit test | `BT=y`, `BT_PERIPHERAL`, `BT_MAX_CONN=1`, `LICHEN_BLE_TRANSPORT=y`, `LICHEN_BLE_SLIP=y`, explicit `LICHEN_IPV6=n` / `LICHEN_LORA_L2=n` / `LICHEN_L2=n`, MCUMGR/CoAP off to break a Kconfig dependency loop |

## 2. What the native_posix BLE-ingress image needs

Goal: run the gateway's BLE LCI (Local Client Interface) ingress path on a
host-native target with **no link.35.6 (LoRa link layer)**.

### 2.1 BLE — required

```
CONFIG_BT=y
CONFIG_BT_PERIPHERAL=y
CONFIG_BT_MAX_CONN=1
CONFIG_BT_DEVICE_NAME="LICHEN-BLE-INGRESS"
CONFIG_BT_HCI=y
CONFIG_BT_HCI_RAW=n
```

`LORA_LICHEN_BLE` (gateway `Kconfig`) is the LICHEN-native BLE LCI switch. It
`depends on BT && BT_PERIPHERAL && BT_MAX_CONN = 1` and
`select LICHEN_APP_INTERFACE + NET_L2_DUMMY`:

```
CONFIG_LORA_LICHEN_BLE=y
```

The gateway's own `ble_uart.c` provides the GATT service for this path, so the
separate transport module must stay off (duplicate `nus_svc` /
`attr_nus_svc` symbols otherwise — see validation summary bead .4, finding 6):

```
CONFIG_LICHEN_BLE_TRANSPORT=n
CONFIG_LICHEN_BLE_SLIP=n
CONFIG_LICHEN_BLE_TRANSPORT_REQUIRE_SECURE=n
```

### 2.2 IPSP — not available on this target

Verified empirically against the pinned Zephyr tree
(`/mnt/lichen-zephyr/work/zephyr`, VERSION 3.7.0):

- `subsys/net/l2/` contains **no** `bluetooth/` L2 directory.
- No `NET_L2_BT` symbol exists anywhere in `subsys/net/`.
- No IPSP references exist anywhere in `subsys/`.

Zephyr 3.7 therefore has no usable BT/IPSP network L2 for this target. The
BLE ingress path instead runs over `NET_L2_DUMMY` with the BLE LCI netif
code-driven via `NET_DEVICE_INIT(ble_lci…)` in `ble_lci_netif.c`. Required:

```
CONFIG_NET_L2_DUMMY=y
```

Consequence: real IPSP-attached L2 routing is not exercisable on the native
target; BLE ingress is validated at the LCI/netif boundary only.

### 2.3 Link layer (link.35.6) — excluded

Everything that pulls in the LoRa link, L2, radio models, routing, or GNSS:

```
CONFIG_LICHEN=y
CONFIG_LICHEN_LINK=n
CONFIG_LICHEN_LORA_L2=n
CONFIG_LICHEN_L2=n
CONFIG_LICHEN_IPV6=n
CONFIG_LICHEN_HAS_LORA=n
CONFIG_LICHEN_RADIO_MODEL_NONE=y
CONFIG_LICHEN_RADIO_MODEL_LOOPBACK=n
CONFIG_LORA_LOOPBACK=n
CONFIG_LORA=n
CONFIG_LICHEN_ROUTING=n
CONFIG_LICHEN_RPL=n
CONFIG_GNSS=n
CONFIG_GNSS_EMUL=n
```

The overlay (`boards/native_posix_ble_ingress.overlay`) complements this at
devicetree level: `/delete-node/ lora_sim;` plus empty `aliases`/`chosen` so
no `zephyr,lora` chosen node exists (with `LICHEN_HAS_LORA=n`, `hal.c` would
otherwise still BUILD_ASSERT on it).

### 2.4 Networking for the LCI path

```
CONFIG_NETWORKING=y
CONFIG_NET_IPV6=y
CONFIG_NET_IPV6_ND=y
CONFIG_NET_IPV6_NBR_CACHE=y
CONFIG_NET_UDP=y
CONFIG_NET_SOCKETS=y
CONFIG_NET_IF_MAX_IPV6_COUNT=2
CONFIG_NET_PKT_RX_COUNT=16
CONFIG_NET_PKT_TX_COUNT=16
CONFIG_NET_BUF_RX_COUNT=32
CONFIG_NET_BUF_TX_COUNT=32
```

Note: unlike the full gateway, `NET_ROUTE` must **not** be set — with routing
compiled out it is a stray assignment and aborts under Kconfig
warnings-as-errors (validation bead .4, finding 3).

### 2.5 Gateway services unrelated to BLE ingress — excluded

```
CONFIG_ZCBOR=y            # kept: needed by the LCI frame path
CONFIG_BASE64=n
CONFIG_MCUMGR=n
CONFIG_UART_MCUMGR=n
CONFIG_MCUMGR_TRANSPORT_UART=n
CONFIG_MCUMGR_GRP_FS=n
CONFIG_UART_CONSOLE=n
CONFIG_LICHEN_COAP=n
CONFIG_LICHEN_COAP_SERVER=n
CONFIG_LICHEN_COAP_CONFIG=n
CONFIG_LICHEN_COAP_KEYS=n
CONFIG_LICHEN_OSCORE=n
CONFIG_LICHEN_SENML=n
CONFIG_LICHEN_SLIP_TRANSPORT=n
CONFIG_FILE_SYSTEM=n
```

`MCUMGR=n` (and friends) additionally breaks the
`UART_INTERRUPT_DRIVEN <-> MCUMGR/CRC/ZCBOR/LICHEN_COAP_KEYS` dependency loop
documented in bead .3 / the ble_ipsp_transport test conf.

### 2.6 native_posix simulation support

```
CONFIG_ENTROPY_GENERATOR=y
CONFIG_TEST_RANDOM_GENERATOR=y
CONFIG_LOG=y
CONFIG_LOG_DEFAULT_LEVEL=3
CONFIG_MAIN_STACK_SIZE=4096
CONFIG_STACK_CANARIES=y       # C safety policy, spec/appendix-c-safety.md
CONFIG_STACK_SENTINEL=y
CONFIG_ASSERT=y
CONFIG_ASSERT_VERBOSE=y
```

Board target note: `native_posix` is **deprecated in Zephyr 3.7** and targets
32-bit x86 hosts only. On aarch64 (the EBS builder) and x86_64 hosts the
equivalent target is `native_sim/native/64`; plain `native_sim` hard-fails on
aarch64 with `CONFIG_64BIT=n but this Aarch64 machine has a 64-bit userspace`.

## 3. Resulting build invocation

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
west build -b native_sim/native/64 -p always -d build/ble-ingress \
  lichen/apps/gateway -- \
  -DDTC_OVERLAY_FILE=boards/native_posix_ble_ingress.overlay \
  -DEXTRA_CONF_FILE=boards/native_posix_ble_ingress.conf \
  -DZEPHYR_EXTRA_MODULES=$PWD/lichen \
  -DLICHEN_RELEASE_EPOCH_UNIX=1722470400
```

The concrete deliverables implementing this analysis are
`lichen/apps/gateway/boards/native_posix_ble_ingress.conf` and
`…/native_posix_ble_ingress.overlay`. Build outcome (187/187 steps, exit 0,
twister `net.lichen.ble_ingress` 4/4 PASS) is recorded in
`validation-summary-2auf.59.4.1.3.2.2.2.4.md`.
