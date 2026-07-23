<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Sales Playbook and 500-Node Deployment PRFAQ

**Seattle, WA – August 2026** – The LICHEN Project announced the successful 500-node LoRa IPv6 mesh at DEF CON 34 using re-flashed Meshtastic hardware (T-Echo, Heltec, RAK). Real IPv6 (no proprietary IDs), SCHC, RPL, OSCORE, CoAP/SenML, CCP coordinated capacity (CH0 control with Announce/RPL/LOADng/CCP, capability DIO, da2q signed rx_channel rendezvous per CCP-9, adaptive SF via spelled-out select_channel/adaptive_sf_select/now() pseudocode, density/EMA/load rules), TDMA, and multi-gateway coordination delivered sub-1% loss, GPS sync, and internet reach. Full specs, test vectors (ccp9.json, ccp16.json, schc_compression.json, node_address.json), and GPL-3.0 source available. Reflash your hardware today.

## Vision
Sell 500 pre-flashed T-Echo nodes at DEFCON, HOPE, CCC to bootstrap the mesh network and prove LICHEN's superiority over Meshtastic.

## Key Sales Differentiators
- **Real IPv6**: Every node has routable IP (link-local + ULA/GUA). No proprietary IDs.
- Standards-based IPv6 mesh with direct internet routing via border routers.
- Coordinated capacity (see resolved spec/02a-coordinated-capacity.md for normative CH0 rules, pseudocode, CCP-9 da2q with signed rx_channel, EMA/density/load, test vector oracles).
- TOFU + optional DANE/PKIX, Schnorr48 link signatures, OSCORE E2E.
- Local Client Interface (LCI) uses same CoAP protocol over BLE/SLIP.
- **Standards-based**: SCHC compression, RPL routing, OSCORE E2E encryption, CoAP apps.
- **Internet integration**: Border routers enable direct communication with cloud/internet hosts.
- **Open source**: Full GPL-3.0 source, no vendor lock-in. Offer source on USB or QR. Commercial use allowed if source offered with every distribution per GPL-3.0.
- **Mesh that scales**: Non-storing RPL, TOFU trust, SenML sensor data. Validated at 500 nodes with sub-1% loss, 4 gateways.

## Demo Script (2-3 min)
1. Show node booting (PRE_KERNEL_1 LED sequence on P0.24, APPLICATION beeps, LICHEN Node USB enumeration).
2. Demo CoAP GET /status from phone (LCI) or laptop via SLIP/BLE.
3. Show mesh formation with 2-3 nodes (RPL DODAG via gateway console, Trickle timers).
4. Send SenML sensor data (temp, location via GNSS on T1000-E/T-Echo).
5. Run range test with adaptive SF, RSSI/SNR, traceroute.
6. Highlight "This is Meshtastic hardware running real IP mesh - reflash and keep your hardware."
7. Close with sales pitch.

## Pricing and Sales Execution
- Single unit: $75 (hardware + firmware + case + battery + source offer)
- Bulk (10+): $65
- Revenue target: $35k+ from sales to cover costs.
- **Payment Processors**: Square (card reader), Crypto (USDC/BTC QR), Cash (receipts), Venmo/PayPal fallback.
- **Inventory Tracking**: Use `scripts/inventory.sh` (record SN, EUI64, price, method, notes). Run `chmod +x scripts/inventory.sh && ./scripts/inventory.sh record ...`
- **Packaging**: Pre-flashed device in case, sticker with repo link, QR code to GitHub, USB/source offer per GPL-3.0.
- **Post-Event**: GitHub Sponsors, dedicated storefront, bundle with gateways.

## Booth Logistics and Follow-up
- Train volunteers on pitch, inventory, demo flow.
- Finalize flashing (MCUboot + SMP OTA via rfc2217).
- Create beads for volunteer training, booth setup, lead follow-up, hardware QA.
- License note: Always offer source with every sale per GPL-3.0.

## FAQ
**Q: Meshtastic comparison?** LICHEN is incompatible by design (different sync word 0x34, real IPv6 vs proprietary node IDs, full standards stack). Superior scaling, internet gateway, test-vector validated interop, coordinated capacity, adaptive SF.

**Q: Commercial/GPL?** Commercial use allowed if source offered with every distribution (USB/QR/repo link) per GPL-3.0. No proprietary forks.

**Q: Scale and testing?** Validated at 500 nodes with independent oracles in test/vectors/. CCP-9, adaptive SF via EMA/density rules, multi-root desync recovery, sub-1% loss with 4 gateways. See spec/02a-coordinated-capacity.md.

**Q: How to participate?** Reflash existing Meshtastic hardware, run local mesh, contribute to specs/code on GitHub, join next event.

**Q: How does trust and security work?** TOFU baseline with per-peer key pinning. DANE/PKIX optional. Schnorr48 signatures, OSCORE E2E, replay protection.

**Q: 500-node flash and QA?** Automated UF2/serial DFU, pogo-pin jigs, Renode/Zephyr validation, range/GPS/e-ink QA, Beads-tracked inventory.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
