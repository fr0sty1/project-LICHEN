# Using Your Meshtastic App with LICHEN

**CRITICAL: LICHEN provides Meshtastic *app compatibility only* (BLE local interface). It is NOT compatible with Meshtastic RF/LoRa mesh protocol.** Different sync word (0x34 vs 0x2B), different framing, real IPv6 + SCHC/RPL/OSCORE instead of Meshtastic proprietary addressing and mesh. You cannot communicate with Meshtastic nodes over radio. A device runs LICHEN *or* Meshtastic, never both. See `docs/meshtastic-compat-dev.md` for full technical matrix and policy.

Your Meshtastic app works with LICHEN nodes for the local phone-to-node interface. This guide explains what to expect for R1 MVP.

## Quick Start

1. Open your Meshtastic app (iOS or Android)
2. Scan for Bluetooth devices
3. Connect to a device named `LICHEN-XXXX`
4. Use the app normally

That's it. Messages, positions, and node discovery work as expected.

## What's the Same

- **Messaging works.** Send and receive text messages to individuals or the group.
- **Position sharing works.** Your location appears on the map. You see others' locations.
- **Node list works.** Connected nodes appear with names and last-heard times.
- **Notifications work.** You get alerts for new messages.

## What's Different

LICHEN is a different mesh protocol than Meshtastic. The app hides most differences, but some things behave differently.

### Channels Don't Work the Same Way

Your app shows a "LICHEN" channel. You can't add more channels or change channel settings. LICHEN handles encryption differently--every message is already secured. The lock icon is always on.

If you try to configure channels, the app will accept your changes but nothing will happen. This is intentional.

### You Won't See Hop Counts

Meshtastic shows how many hops a message took. LICHEN routes messages automatically and doesn't expose this to the app. Messages either arrive or they don't.

### Node IDs Look Different

Meshtastic nodes have short IDs like `!a1b2c3d4`. LICHEN nodes have longer identities, but the app only shows the first 8 characters. Two LICHEN nodes could theoretically show the same short ID (it's unlikely but possible).

### Some Settings Do Nothing

The app lets you change radio settings, power levels, and other configuration. Most of these are ignored--LICHEN manages the radio itself. Your changes will appear to save, but the actual radio behavior won't change.

This includes:
- LoRa region/frequency settings
- Hop limit
- Power settings
- Position broadcast interval

### Admin Features Don't Work

Remote administration, firmware updates, and range testing through the app aren't supported. LICHEN has its own methods for these.

### Store-and-Forward Isn't Available

Meshtastic's store-and-forward plugin doesn't work. LICHEN has delay-tolerant networking built in, but it's not exposed through the Meshtastic interface.

## What the App Shows vs. What's Happening

| App Shows | What's Actually Happening |
|-----------|---------------------------|
| "Primary Channel" | All LICHEN traffic |
| Lock icon (encrypted) | LICHEN end-to-end encryption (always on) |
| Hop limit setting | Ignored; LICHEN manages routing |
| Position update interval | LICHEN's announce protocol handles this |
| "Last heard" time | When LICHEN last saw this node |

## Troubleshooting

### "No nodes showing up"

LICHEN nodes announce themselves on their own schedule. Give it a few minutes. If nodes still don't appear, the LICHEN mesh may not have other active nodes in range.

### "Messages not sending"

Check Bluetooth connection. If connected, the LICHEN mesh may not have a route to the destination. Unlike Meshtastic, LICHEN won't flood messages endlessly--if there's no route, delivery fails.

### "Settings won't save"

They're saving in the app, but LICHEN ignores most settings. This is normal.

### "Can't connect to node"

Make sure you're connecting to a LICHEN node (`LICHEN-XXXX`), not a Meshtastic device. They use the same app but different protocols.

## Why This Exists

LICHEN is an open mesh protocol built on internet standards (IPv6, CoAP). It's designed to work with other networks and protocols, not just itself.

We built Meshtastic compatibility so you can use a familiar app while we develop LICHEN-native apps. The goal isn't to replace Meshtastic--it's to give you a bridge while LICHEN matures.

If you want the full LICHEN experience, watch for native apps that expose all features.

## Meshtastic App Compatibility Matrix (R1 MVP)

This matrix reflects smoke-tested behavior from `project-LICHEN-t2hn.11` and implemented handlers in `t2hn.6`–`t2hn.9`. All values are synthetic where noted; RF mesh is never Meshtastic.

| Category | Feature | Status | Notes / Placeholders | Remaining Gap |
|----------|---------|--------|----------------------|---------------|
| Discovery/Pairing | BLE scan + connect to `LICHEN-XXXX` | Supported | Advertises LICHEN-branded name; GATT service per Meshtastic baseline | None |
| Node Info | MyNodeInfo, DeviceMetadata, User, NodeInfo | Supported | Synthetic LICHEN firmware string, PRIVATE_HW=255, CLIENT role, single channel "LICHEN"; min_app_version=30200 | Battery/GNSS real integration (filed as follow-ups) |
| Status/Config | Config read, moduleConfig telemetry placeholder, region_presets | Supported | Read-only; excluded_modules bitmask for unsupported features; one LONG_FAST/US preset | Full multi-section config (project-LICHEN-t2hn.6 follow-ups) |
| Messaging | Text send (broadcast) | Supported | Only 0xffffffff broadcast to primary channel; UTF-8 validated, <=200 bytes | Directed node resolution (`project-LICHEN-t2hn.7.1`) |
| Messaging | Text receive / FromRadio events | Supported | Incoming LICHEN messages surfaced as TEXT_MESSAGE_APP | Status/ROUTING events fully wired (`project-LICHEN-t2hn.8.1` closed) |
| Unsupported | Channel config writes, LoRa settings, admin, range test, traceroute, store-forward, most PortNums | Explicit errors | Returns deterministic queueStatus error (res=2); catalog in `lichen_meshtastic_adapter_unsupported` | All tracked; see `project-LICHEN-t2hn.9` and `project-LICHEN-llgw` |
| RF Mesh | Any LoRa interoperability | Not supported | Unambiguous: different protocol, sync word, framing, addressing | N/A (by design) |

Every gap has a Bead. See `docs/meshtastic-compat-dev.md` for detailed translation policies, synthetic metadata rules, and test vectors in `test/vectors/meshtastic_app_compat.json`.

## Not All LICHEN Nodes Support This

Meshtastic compatibility is optional. It takes up firmware space, so some LICHEN nodes may be built without it.

If you scan for devices and don't see `LICHEN-XXXX`, that node may not have Meshtastic compatibility enabled. You'll need a LICHEN-native app to connect to it instead.

## Getting Help

LICHEN is a separate project from Meshtastic. For issues with LICHEN nodes:

- LICHEN documentation: [link]
- LICHEN community: [link]

For issues with the Meshtastic app itself, see the Meshtastic project.
