<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Agent Instructions: LICHEN Protocol

**LICHEN** = **L**oRa **I**Pv6 **C**oAP **H**ybrid **E**xtended **N**etwork

A standards-based LoRa mesh networking protocol built on IPv6, SCHC, RPL, and CoAP.

**Licenses:**
- Documentation (specs, docs): **CC-BY-4.0**
- Software (reference implementations): **GPL-3.0**

## Task Tracking: Beads (NOT TodoWrite)

**CRITICAL:** This project uses **beads** (`bd`) for all task tracking.

**DO NOT USE:**
- `TodoWrite` tool
- `TaskCreate` / `TaskUpdate` / `TaskList` tools
- Markdown TODO lists or task files

**USE INSTEAD:**
```bash
bd ready                    # Find available work
bd create --title="..." --description="..." --type=task
bd update <id> --claim      # Claim work
bd close <id>               # Complete work
bd remember "insight"       # Persistent memory across sessions
```

Run `bd prime` for full command reference. See the Beads section at the end of this file for more details.

## Project Overview

**What we're building:** LICHEN — a LoRa mesh network that uses real IPv6 addressing (not proprietary node IDs), enabling direct communication with internet hosts via border routers. Think "Meshtastic but with proper IP."

**Relationship to Meshtastic:** LICHEN runs on the same hardware (reflash), but the protocol is **not backward compatible**. Different sync word (0x34 vs 0x2B), different framing, real IPv6 instead of proprietary addressing. A device runs one or the other, not both.

**Key specs:**
- `spec/` - Protocol specifications:
  - `spec/drafts/draft-lichen-schnorr-00.md` - **48-byte Schnorr signatures** (CRITICAL: test vectors in Appendix A)
  - `spec/01-introduction.md` through `spec/18-applications.md` - Full protocol spec
- `LICHEN-plan.md` - Implementation plan (the "how")
- `test/vectors/` - Canonical test vectors (JSON) for cross-implementation validation

## Architecture at a Glance

```
Application:  CoAP / MQTT-SN / Raw UDP
Security:     OSCORE (E2E) + Ed25519 link signatures
Transport:    UDP (compressed via SCHC)
Network:      IPv6 (link-local fe80::/10 or global /64)
Routing:      RPL (DODAG mesh formation)
Adaptation:   6LoWPAN + SCHC header compression
Link:         Custom frame format with truncated Ed25519 sigs
Physical:     LoRa CSS (SX126x/SX127x)
```

## Implementation Strategy

| Component | Technology | Location | Purpose |
|-----------|------------|----------|---------|
| **Embedded nodes** | Zephyr RTOS | `zephyr/` | ESP32, nRF52840, RP2040, STM32WL |
| **Linux gateway** | Rust | `rust/` | Border routers, simulators |
| **STM32WL fallback** | RIOT OS | `riot/` | Only if Zephyr doesn't fit |

**Why Zephyr, not Arduino?**
- Native IPv6, 6LoWPAN, CoAP (Arduino has none)
- Consistent RTOS API across all platforms
- Better power management
- We build on Zephyr's network stack, not from scratch

**STM32WL Risk:**
- 64KB RAM / 256KB Flash is tight
- Phase 0 validates memory fit
- RIOT fallback if needed (~10KB RAM for full stack)

**Critical rule:** All implementations MUST produce identical output for test vectors in `test/vectors/`.

**GPL-3.0 implications:**
- All distributed binaries must include source or offer to provide it
- Modifications must be released under GPL-3.0
- No proprietary forks; commercial use is fine if source is provided

## Key Technical Decisions

1. **Ed25519 truncated signatures (32 bytes)** - Non-standard but necessary for LoRa bandwidth. Security analysis required.

2. **SCHC compression** - Header compression from 48+ bytes to 3-6 bytes. Rules are pre-provisioned, not negotiated.

3. **RPL Non-Storing Mode** - Border router holds all routes, uses 6LoRH source routing for downward traffic.

4. **No TCP** - UDP only. Use CoAP Observe or MQTT-SN for reliable messaging.

5. **OSCORE for CoAP** - End-to-end encryption, not just link-layer.

6. **Decentralized trust model:**
   - **No PSK** - each node has its own keypair, no "network password"
   - **No mandatory CA** - works without enterprise PKI
   - **TOFU baseline** - accept keys on first contact, pin them (SSH-style)
   - **DANE optional** - verify keys via DNSSEC when internet available
   - **PKIX/ACME optional** - CA certificates fetched out-of-band or via CoAP
   - Trust is per-peer, not per-network

7. **Local Client Interface (LCI)** - see spec section 17:
   - Local client (phone app, etc.) is just another IPv6 neighbor
   - Communicates via CoAP over SLIP/BLE/IPC
   - Same protocol as mesh traffic (no separate API)
   - Node acts as router to mesh
   - Standard CoAP tools work for debugging/testing

8. **SenML for sensor data** - see spec Appendix F:
   - RFC 8428 SenML over CBOR (Content-Format 112)
   - Standard profiles for: location, battery, temp, humidity, pressure, IMU, air quality
   - Observable resources for streaming
   - Base name = `urn:dev:mac:<EUI-64>:`
   - Timestamps support batching (relative to base time)

9. **Standard applications** - see spec section 18:
   - Messaging (unicast, multicast, broadcast, canned messages, store-and-forward)
   - Position sharing (beacons, blue force tracking, privacy controls)
   - Waypoints and routes (shareable POIs, GeoJSON-like)
   - Emergency/SOS (priority alerts, automatic relay, hardware button)
   - Presence/status (available/away/busy, activity hints)
   - Check-in/roll call (group accountability)
   - Range testing (extended ping with RSSI/SNR, traceroute)
   - Groups/channels (multicast addressing, optional OSCORE group encryption)

## Development Phases

| Phase | Focus | Key Deliverables |
|-------|-------|------------------|
| 0 | Foundation | Workspace setup, first I-D drafts |
| 1 | PHY + Link | LoRa radio abstraction, Ed25519 frames |
| 2 | SCHC | Header compression engine, fragmentation |
| 3 | IPv6 | 6LoWPAN dispatch, ICMPv6 |
| 4 | RPL | DODAG formation, Trickle timers |
| 5 | Security | OSCORE, key management |
| 6 | Application | CoAP server/client, MQTT-SN |
| 7 | Border Router | 6LBR, gateway functions |
| 8 | Tooling | Simulator, Wireshark dissector |

## Code Organization

```
rust/
├── lora-phy/        # Radio abstraction (SX126x, SX127x, simulated)
├── lora-link/       # Link layer (framing, LLSec, replay protection)
├── schc/            # SCHC compression + fragmentation
├── sixlowpan/       # 6LoWPAN dispatch, IPv6 minimal
├── rpl/             # RPL routing, Trickle, MRHOF
├── coap/            # CoAP + OSCORE
├── mqtt-sn/         # MQTT-SN client
├── mesh-node/       # Full node binary
├── mesh-gateway/    # Border router binary
├── mesh-sim/        # Network simulator
└── ffi/             # C bindings (cbindgen)

c/
├── include/lora_mesh/  # Public headers
├── src/                # Implementation
└── port/               # Platform-specific (esp32, nrf52, rp2040, stm32wl)

docs/
└── draft-*.md       # IETF-style Internet-Drafts
```

## Subsystem Initialization (Zephyr C)

The LICHEN Zephyr subsystems in `lichen/subsys/lichen/` have **implicit initialization dependencies**. Follow this order to avoid use-before-init crashes, silent failures, or undefined behavior.

### Initialization Dependency Graph

```
    LoRa Driver (Zephyr device)
         |
         v
    lichen_link_init()  ──────────────────┐
         |                                |
         v                                v
    lichen_link_load_key()     lichen_rpl_dodag_init()
         |                                |
         v                                v
    [Signing available]        [RPL routing + TDMA]
         |                                |
         └─────────────┬──────────────────┘
                       v
                  lichen_tdma_init(&tdma_ctx, &link_ctx) (after link_load_key per spec/02a-coordinated-capacity.md and hash-based slot)

                       |
                       v
                 oscore_init()
                       |
                       v
                 oscore_ctx_create()
                       |
                       v
            lichen_coap_client_init()  [auto-initializes on first request]
```

### Subsystem Requirements

| Subsystem | Init Function | Prerequisites | Thread-Safety |
|-----------|--------------|---------------|---------------|
| **Link Layer** | `lichen_link_init(ctx, eui64)` | None | Per-context (no global state) |
| **TDMA** | `lichen_tdma_init(tdma_ctx, link_ctx)` | `lichen_link_load_key()` | Per-context |
| **Link Keys** | `lichen_link_load_key(ctx, seed)` | `lichen_link_init()` | Per-context |
| **RPL DODAG** | `lichen_rpl_dodag_init(d, ...)` | None | Per-DODAG (caller must synchronize) |
| **OSCORE** | `oscore_init()` | None | Thread-safe (internal mutex) |
| **OSCORE Contexts** | `oscore_ctx_create(...)` | `oscore_init()` | Thread-safe |
| **CoAP Client** | `lichen_coap_client_init()` | Network stack up | Thread-safe (auto-init on first use) |

### Example: Full Node Initialization

```c
#include <lichen/link_ctx.h>
#include <lichen/oscore.h>
#include <lichen/rpl_dodag.h>
#include <lichen/coap_client.h>
#ifdef CONFIG_LICHEN_TDMA
#include <lichen/link.h>
#endif

int lichen_node_init(const uint8_t eui64[8], const uint8_t seed[32])
{
    int ret;

    static struct lichen_link_ctx link_ctx;
    ret = lichen_link_init(&link_ctx, eui64);
    if (ret < 0) return ret;

    ret = lichen_link_load_key(&link_ctx, seed);
    if (ret < 0) return ret;

#ifdef CONFIG_LICHEN_TDMA
    static struct lichen_tdma_ctx tdma_ctx;
    lichen_tdma_init(&tdma_ctx, &link_ctx);  /* after link_init per graph */
    if (ret < 0) return ret;  /* placeholder */
#endif

    ret = oscore_init();
    if (ret < 0) return ret;

    static struct lichen_rpl_dodag dodag;
    uint8_t dodag_id[16] = {0};
    lichen_rpl_dodag_init(&dodag, 0x00, dodag_id, 0);

    return 0;
}
```


## Agent Work Ethic: NO LAZINESS

**CRITICAL: When asked to fix issues, fix ALL of them. Not just "the important ones."**

### Rules for Issue Resolution

1. **"All issues" means ALL issues** — P0, P1, P2, P3, P4, every single one. Treat all priorities including P4 as real work — implement full fixes, do not close as low priority/opinion. The user asked for all of them.

2. **Fix completely** — Don't half-fix an issue. Don't say "this could be improved further." Make all necessary code changes, run tests, close the issue.

3. **No excuses** — Don't say:
   - "This is low priority, skipping"
   - "This would require significant refactoring"
   - "This is a style preference"
   - "I'll leave this for later"
   
   Instead: **FIX IT NOW.**

4. **Run codereview after every fix** — When instructed to run codereview passes, actually run them. 3 passes means 3 independent reviews, not one review with 3 paragraphs.

5. **Use subagents aggressively** — When fixing many issues, parallelize. Don't do them one at a time when you can do 20 at once.

6. **Close issues when done** — Every fix should end with `bd close <id>`. If the issue isn't closed, it isn't done.

### What "Thorough" Means

- Read the full issue description
- Find ALL files that need changes
- Make ALL the changes
- Run the appropriate tests (cargo test, pytest, ruff, mypy)
- Verify the fix actually works
- Close the issue

### Anti-Patterns (DO NOT DO THESE)

- ❌ "I fixed 5 of the 50 issues, the rest are lower priority"
- ❌ "This P3 issue is just polish, skipping"
- ❌ "I ran out of context, stopping here"
- ❌ "This would require too many changes"
- ❌ Closing issues without actually fixing them
- ❌ Saying "fixed" when you only added a TODO comment

### The Standard

When the user says "fix all issues," the correct response is to fix **every single issue** until `bd list --status=open` returns zero issues.

---

## Coding Guidelines

### Rust
- Use `no_std` by default; `std` only in simulator and gateway
- Prefer `heapless` collections over `Vec` in core crates
- All public APIs must be `#![forbid(unsafe_code)]` except FFI
- Run `cargo clippy` and `cargo fmt` before commits

### C
- Target: C11, no dynamic allocation in hot paths
- **Naming prefixes**: Subsystem prefixes follow RFC/spec names (`SCHC_`, `SENML_`, `EDHOC_`, `OSCORE_`). Use `LICHEN_` only for project-specific constructs with no external spec (e.g., `LICHEN_RPL_*` for our RPL extensions, `LICHEN_LINK_*` for link layer).
- Memory budget varies by platform:
  - ESP32: 320KB+ SRAM, 4MB+ Flash (comfortable)
  - nRF52840: 256KB RAM, 1MB Flash (comfortable)
  - STM32WL: 64KB RAM, 256KB Flash (constrained baseline)
- Use `static` for all file-scoped symbols
- No recursive functions (stack overflow risk on smaller stacks)

### Both
- Every packet format must have test vectors
- Crypto primitives from vetted libraries only (no hand-rolled crypto)
- Bit-level protocol parsing must be fuzzed

## Testing Requirements

1. **Unit tests** - Each crate/module in isolation
2. **Integration tests** - Multi-node scenarios in simulator
3. **Interop tests** - Rust ↔ C produce identical output
4. **Hardware tests** - Real LoRa radios on real MCUs. Bench inventory,
   port-safety rules, flash/OTA procedures, over-the-air verification, and
   findings are in [`docs/bench-operations.md`](docs/bench-operations.md).
   **Read the port-safety rules before opening any device port** — several
   ports wedge the node or block forever on the wrong access.
5. **Fuzz tests** - All parsing code (SCHC, CoAP, RPL messages)

Test vectors live in `test/vectors/` as JSON. Both implementations read and verify against these.

If a Zephyr build or test is Linux-only and cannot run on the local host, use AWS EC2 via the AWS CLI instead of skipping it. See the **AWS EC2 Access** section below for authentication and safety rules.

## AWS EC2 Access

### Authentication

Use the personal AWS CLI profile:

```bash
# Profile name (already configured in ~/.aws/config)
export AWS_PROFILE=personal

# Region for LICHEN resources
export AWS_REGION=us-west-2

# Verify access:
aws sts get-caller-identity
```

The profile MUST resolve to personal account `210337117346`.
EC2 Serial Console access is enabled for the account in `us-west-2`; callers
still need `ec2-instance-connect:SendSerialConsoleSSHPublicKey` permission.

### CRITICAL: Resource Isolation

**This AWS account contains resources for multiple projects.** You MUST only interact with LICHEN resources.

#### Identifying LICHEN Resources

LICHEN resources are tagged:
- `Project=LICHEN`
- `LaunchedBy=ec2-claude-sh` (for instances launched by the script)

The copied Zephyr builder EBS volume is the sole untagged exception. Identify it
by the exact volume ID and `Name=lichen-zephyr-arm64` listed below.

Before ANY destructive operation (terminate, delete, stop), verify the resource belongs to LICHEN:

```bash
# Check instance tags before terminating
aws ec2 describe-tags --filters "Name=resource-id,Values=<instance-id>" \
  --query 'Tags[?Key==`Project`].Value' --output text
# Must return "LICHEN" or be an instance YOU launched this session

# List only LICHEN instances
aws ec2 describe-instances --filters "Name=tag:Project,Values=LICHEN" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0],State.Name]' \
  --output table
```

#### Resources You MUST NOT Touch

The following are NOT LICHEN resources — do not terminate, stop, modify, or delete:

- Any instance without `Project=LICHEN` tag
- Any EBS volume not explicitly listed in this document
- Any security group, VPC, or subnet you didn't create

#### Safe Operations

You MAY:
- Launch new instances with `Project=LICHEN` and `LaunchedBy=<your-identifier>` tags
- Terminate instances YOU launched in the current session (track instance IDs)
- Attach/detach the LICHEN EBS volume (`vol-0a95eee8d1d8461eb`)
- Create/delete temporary security groups tagged with `Project=LICHEN`

You MUST NOT:
- Terminate instances found via `describe-instances` unless you have the launch record
- Delete or modify EBS volumes other than attaching/detaching the LICHEN cache volume
- Modify VPCs, subnets, or route tables
- Create resources without proper LICHEN tags

### Launching EC2 Instances

Use `./scripts/ec2-claude.sh` for standard LICHEN EC2 operations — it handles tagging, volume attachment, and cleanup automatically.

For manual launches, always include tags:

```bash
aws ec2 run-instances \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=LICHEN},{Key=LaunchedBy,Value=claude-session},{Key=Name,Value=lichen-grinder-<task>}]' \
  ...
```

### AWS Zephyr Builder EBS Cache

Always use the persistent single-AZ EBS builder cache for EC2 Zephyr builds/tests:

- Volume: `vol-0a95eee8d1d8461eb`
- Region/AZ: `us-west-2` / `us-west-2c`
- Size/type: 400 GiB `gp3`
- Name tag: `lichen-zephyr-arm64`
- Filesystem label: `LICHEN_ZEPHYR`
- Mount point: `/mnt/lichen-zephyr`
- Prepared contents: Zephyr SDK `0.16.8`, repo west workspace pinned to Zephyr `v3.7.0`, Zephyr Python venv, west modules, ccache, pip/uv cache directories, and helper scripts.
- Validation: `west build -b native_sim ... lichen/tests/link_crypto` plus `west build -t run` passed with `link_crypto` 2/2.

Workflow for a fresh EC2 instance in `us-west-2c`:

```bash
aws ec2 attach-volume --profile personal --region us-west-2 \
  --volume-id vol-0a95eee8d1d8461eb --instance-id <instance-id> --device /dev/sdf

sudo /mnt/lichen-zephyr/scripts/mount-volume.sh vol-0a95eee8d1d8461eb /mnt/lichen-zephyr
/mnt/lichen-zephyr/scripts/bootstrap-host.sh  # idempotent; installs git + Zephyr deps via dnf on Amazon Linux 2023
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN
```

For validation against uncommitted or branch-specific changes, use a clean
worktree prepared by `tools/zephyr-clean-worktree.sh` instead of building from
the dirty primary cache workspace:

```bash
tools/zephyr-clean-worktree.sh create project-LICHEN-validate origin/main
cd /mnt/lichen-zephyr/work/project-LICHEN-validate
# apply patch or switch/ref as needed, then pass:
#   -DZEPHYR_EXTRA_MODULES=$PWD/lichen
# After each build or Twister scenario, run:
tools/zephyr-clean-worktree.sh verify "$PWD" <build-dir>
```

The volume is single-attach. Before terminating a builder, run `sync`, unmount `/mnt/lichen-zephyr`, detach the volume, and wait for it to return to `available` so the next builder can attach it.

### AWS Fleet Runtime AMI

Use the fleet AMI for parallel Renode, Rust, and Python simulation workers. Do
not attach the single-use Zephyr builder EBS cache to fleet instances.

- AMI: `ami-0764d1b512e22671f`
- Region/architecture: `us-west-2` / ARM64
- Root snapshot: `snap-084be3acfc62d508a` (30 GiB encrypted)
- Contents: Renode `1.16.1`, Rust/Cargo `1.97.0`, Python `3.11.15`, `uv` `0.11.18`, and locked LICHEN Python runtime dependencies
- Source policy: no repository checkout or credentials are baked into the image; provide current source and artifacts at launch
- Validation: clean-boot SSH and Serial Console API, headless Renode, locked `hetero-node` build/invocation, and LICHEN Python package import passed

The `ec2-renode-fleet.sh`, `ec2-renode-fleet-simple.sh`, and
`ec2-hetero-fleet.sh` launchers default to this AMI. Override with `EC2_AMI_ID`
only for an explicitly validated replacement image.

## IETF I-D Documents

We're writing protocol docs in IETF Internet-Draft style:

| Document | Content |
|----------|---------|
| `draft-lora-link-*.md` | Link layer frame format, LLSec |
| `draft-lora-schc-*.md` | SCHC compression profile |
| `draft-lora-rpl-*.md` | RPL configuration for LoRa |
| `draft-lora-security-*.md` | Ed25519 truncation, OSCORE |
| `draft-lora-coap-*.md` | CoAP usage, Resource Directory |
| `draft-lora-border-*.md` | Border router behavior |

Use RFC 2119 keywords (MUST, SHOULD, MAY) consistently.

## Open Questions (Check Before Implementing)

1. **SCHC rule distribution** - Pre-provisioned vs. negotiated
2. **Time synchronization** - NTP over CoAP, GPS, or piggyback on DIO?
3. **DANE record format** - Exact TLSA record structure for `_25519._mesh.<name>`

Check `bd list` for issues tracking these decisions.

## Resolved Crypto

- **48-byte Schnorr signatures** - See `spec/drafts/draft-lichen-schnorr-00.md`
  - Curve25519/Ed25519, SHA-512, 16-byte truncated challenge + 32-byte response
  - Reference impl: `python/src/lichen/crypto/schnorr48.py`
  - Test vectors: `test/vectors/schnorr48.json`

## Resolved Decisions

- **Trust model**: TOFU baseline, DANE/PKIX optional upgrades (see spec 8.5)
- **License**: CC-BY-4.0 (docs), GPL-3.0 (code)
- **Hardware**: Meshtastic-compatible devices (reflash)
- **Embedded RTOS**: Zephyr (primary), RIOT (STM32WL fallback if needed)
- **Why not Arduino**: No native IPv6/6LoWPAN/RPL/CoAP; Zephyr has all
- **IPv6 addressing** (see spec 6.1, 12):
  - Link-local always (fe80:: + IID)
  - ULA default when DODAG root present (fd00::/8)
  - GUA optional when BR has upstream prefix
  - Isolated meshes work (self-elected root generates ULA)
  - Multiple BRs tolerated (no coordination required)
- **Local Client Interface** (see spec 17):
  - IPv6 + CoAP over SLIP/BLE/IPC (not proprietary protobuf)
  - Client gets link-local address, node routes to mesh
  - Resources: /config, /status, /keys, mesh proxy

## Hardware Targets

**We target all hardware that Meshtastic already supports.** This is a reflash, not new hardware. Users with existing Meshtastic devices can flash our firmware.

### Seeed SenseCAP T1000-E

The T1000-E is the primary development target. It uses nRF52840 + LR1110 (LoRa + GNSS) + AG3335 (standalone GNSS).

**Bootloader:** Adafruit nRF52 UF2 bootloader v0.9.1 (Seeed build, family ID `0x28860057`)
- `APP_START_ADDR = 0x1000` — immediately after the Nordic MBR, no SoftDevice
- Serial number visible at `/dev/serial/by-id/usb-Seeed_Studio_T1000-E_<serial>-if00`

**Flash layout (LICHEN, no SoftDevice):**

| Partition | Address | Size | Notes |
|-----------|---------|------|-------|
| Nordic MBR | `0x0000` | 4 KB | Factory, do not touch |
| `boot_partition` (MCUboot) | `0x1000` | 48 KB | `APP_START_ADDR` |
| `slot0_partition` (active app) | `0xD000` | 356 KB | |
| `slot1_partition` (OTA staging) | `0x66000` | 356 KB | SMP writes here |
| `storage_partition` | `0xBF000` | 16 KB | |
| UF2 bootloader | `0xF4000` | ~48 KB | Factory, do not touch |
| `0xFF000` | `0xFF000` | 4 KB | DFU settings (CRC + image_size) |

**USB enumeration:**

| State | Product string | ttyACM0 | ttyACM1 |
|-------|---------------|---------|---------|
| UF2 bootloader | `T1000-E` (Seeed Studio) | DFU CDC | — |
| LICHEN firmware | `LICHEN Node` (LICHEN Project) | LICHEN Native / console | SMP OTA |

**Why UF2 drag-and-drop cannot be used for initial flash:**
After the first serial DFU, the bootloader stores `image_size` (the size of what was flashed) in `0xFF000`. The UF2 writer silently rejects writes to addresses above `APP_START_ADDR + image_size`. If that image is 16 KB (a bare MCUboot), writes to `0xD000+` are ignored. Serial DFU is the only reliable initial-flash path.

**Build:**
```bash
./build-t1000e.sh              # build puck app (MCUboot auto-built if missing)
./build-t1000e.sh --mcuboot    # force MCUboot rebuild
./build-t1000e.sh --clean      # clean and rebuild everything
```

**Initial flash** (requires UF2 bootloader mode — double-tap reset):
```bash
./flash-t1000e.sh              # build if needed, then flash via serial DFU
./flash-t1000e.sh --rebuild    # force rebuild before flash
# Override port: T1000E_PORT=/dev/ttyACM1 ./flash-t1000e.sh
```

**OTA app update** (no reset, LICHEN firmware must be running):
```bash
# Start rfc2217 bridge first (port 4005 = ttyACM1 = SMP transport):
./rfc2217-servers.sh &
# Then upload:
python3 smp-flash.py rfc2217://localhost:4005 \
    build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
```

**Expected boot sequence:**
1. `PRE_KERNEL_1` — 3 blinks on P0.24 (LED), via raw GPIO before any driver init
2. `APPLICATION` — 1 beep (USB CDC init reached)
3. `APPLICATION` — 2 beeps (LR1110 + GNSS ready, LICHEN Native transport starting)
4. USB CDC enumerates: `LICHEN Node` on ttyACM0 (console) + ttyACM1 (SMP)

**Board DTS:** `lichen/boards/seeed/t1000_e/t1000_e_nrf52840.dts`
**App config:** `lichen/apps/puck/boards/t1000_e_nrf52840.conf`
**Native lib:** `lichen/lib/native/native.c` — USB init, buzzer, PRE_KERNEL_1 blink

Meshtastic-compatible boards include:

| Family | Examples | Radio |
|--------|----------|-------|
| **ESP32 + SX127x** | TTGO T-Beam, Heltec LoRa 32 V2 | SX1276/78 |
| **ESP32-S3 + SX126x** | Heltec LoRa 32 V3, T-Beam Supreme | SX1262 |
| **nRF52840 + SX126x** | RAK4631, T-Echo | SX1262 |
| **RP2040 + SX126x** | RAK11310 | SX1262 |
| **STM32WL** | RAK3172, Seeed Wio-E5 | Integrated SX126x |

See [Meshtastic Supported Hardware](https://meshtastic.org/docs/hardware/devices/) for the full list.

**Development boards** (for contributors):
- Heltec LoRa 32 V3 - cheap, widely available
- T-Beam Supreme - GPS + SX1262
- RAK4631 - nRF52840 for BLE gateway work
- Any STM32WL board - for integrated radio testing

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** to avoid hanging on prompts:

```bash
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file
rm -rf directory            # NOT: rm -r directory
```

---

## Beads Issue Tracking

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking (not TodoWrite, TaskCreate, or markdown lists)
- Use `bd remember` for persistent knowledge (not MEMORY.md files)
- Run `bd prime` for detailed command reference
- Beads constantly creates/updates flat-file issue exports under `.beads/`; always add and commit those Beads flat files with the work that produced them.

### Session Completion

**When ending work**, complete ALL steps:

1. File issues for remaining work
2. Run quality gates (tests, linters, builds)
3. Close finished issues
4. **PUSH TO REMOTE** (mandatory):
   ```bash
   git pull --rebase && git push
   git status  # Must show "up to date"
   ```
5. Provide handoff context for next session

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues are stored as flat JSON files in `.beads/issues/`, tracked by git. Sync is via standard git operations.
<!-- END BEADS CODEX SETUP -->


<!-- BEGIN BEADS INTEGRATION v:1 profile:full hash:d327e327 -->
## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

### Why bd?

- Dependency-aware: Track blockers and relationships between issues
- Git-friendly: flat-file JSON storage tracked by git
- Agent-optimized: JSON output, ready work detection, discovered-from links
- Prevents duplicate tracking systems and confusion

### Quick Start

**Check for ready work:**

```bash
bd ready --json
```

**Create new issues:**

```bash
bd create "Issue title" --description="Detailed context" -t bug|feature|task -p 0-4 --json
bd create "Issue title" --description="What this issue is about" -p 1 --deps discovered-from:bd-123 --json
```

**Claim and update:**

```bash
bd update <id> --claim --json
bd update bd-42 --priority 1 --json
```

**Complete work:**

```bash
bd close bd-42 --reason "Completed" --json
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

### Workflow for AI Agents

1. **Check ready work**: `bd ready` shows unblocked issues
2. **Claim your task atomically**: `bd update <id> --claim`
3. **Work on it**: Implement, test, document
4. **Discover new work?** Create linked issue:
   - `bd create "Found bug" --description="Details about what was found" -p 1 --deps discovered-from:<parent-id>`
5. **Complete**: `bd close <id> --reason "Done"`

### Quality
- Use `--acceptance` and `--design` fields when creating issues
- Use `--validate` to check description completeness

### Lifecycle
- `bd defer <id>` / `bd supersede <id>` for issue management
- `bd stale` / `bd orphans` / `bd lint` for hygiene
- `bd human <id>` to flag for human decisions
- `bd formula list` / `bd mol pour <name>` for structured workflows

### Storage

Issues are stored as flat JSON files in `.beads/issues/`, tracked by git. Each write updates these files directly. Sync is via standard git operations (commit, push, pull).

### Important Rules

- ✅ Use bd for ALL task tracking
- ✅ Always use `--json` flag for programmatic use
- ✅ Link discovered work with `discovered-from` dependencies
- ✅ Check `bd ready` before asking "what should I work on?"
- Before `bd update` or `bd close`, verify issue is not already closed by human (owner/created_by contains "Mark" or "ec2-user", or closed_at predates session). If so, create new follow-up with `discovered-from:<id>` dependency instead of rewriting to preserve audit trail.
- ❌ Do NOT create markdown TODO lists
- ❌ Do NOT use external issue trackers
- ❌ Do NOT duplicate tracking systems

For more details, see README.md and docs/QUICKSTART.md.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits or git pushes unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.

<!-- END BEADS INTEGRATION -->
