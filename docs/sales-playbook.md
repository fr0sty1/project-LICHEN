<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Sales Playbook and 500-Node Deployment PRFAQ

**Seattle, WA – August 2026** – The LICHEN Project announced the successful 500-node LoRa IPv6 mesh at DEF CON 34 using re-flashed Meshtastic hardware (T-Echo, Heltec, RAK). Real IPv6 (no proprietary IDs), SCHC, RPL, OSCORE, CoAP/SenML, CCP coordinated capacity (CH0 control with Announce/RPL/LOADng/CCP, capability DIO, da2q signed rx_channel rendezvous per CCP-9, adaptive SF via spelled-out select_channel/adaptive_sf_select/now() pseudocode, density/EMA/load rules), TDMA, and multi-gateway coordination delivered sub-1% loss, GPS sync, and internet reach. Full specs, test vectors (ccp9.json, ccp16.json, schc_compression.json, node_address.json), and GPL-3.0 source available. Reflash your hardware today.

## Key Sales Differentiators
- Standards-based IPv6 mesh with direct internet routing via border routers.
- Coordinated capacity (see resolved spec/02a-coordinated-capacity.md for normative CH0 rules, pseudocode, CCP-9 da2q with signed rx_channel, EMA/density/load, test vector oracles).
- TOFU + optional DANE/PKIX, Schnorr48 link signatures, OSCORE E2E.
- Local Client Interface (LCI) uses same CoAP protocol over BLE/SLIP.
- Open licensing: CC-BY-4.0 docs, GPL-3.0 code (source offered with every sale).

## Demo and Pricing
Demo: Boot sequence, CoAP /status via LCI, RPL mesh formation, SenML position sharing, range test with adaptive SF. Pricing: $75 single / $65 bulk (includes hardware, case, battery, firmware, source offer per GPL). Use Square/crypto/cash; track with inventory scripts and Beads. Packaging with QR to repo. Post-event: GitHub Sponsors, storefront. License note: always offer source.

## FAQ
**Q: Meshtastic comparison?** LICHEN is incompatible by design (different sync word 0x34, real IPv6 vs proprietary node IDs, full standards stack). Superior scaling, internet gateway, and test-vector validated interop.

**Q: Commercial/GPL?** Commercial use allowed if source offered with every distribution (USB/QR/repo link) per GPL-3.0. No proprietary forks.

**Q: Scale and testing?** Validated at 500 nodes with independent oracles in test/vectors/; CCP-9, adaptive SF via EMA/density rules, multi-root desync recovery, sub-1% loss with 4 gateways. See spec/02a-coordinated-capacity.md.

**Q: How to participate?** Reflash existing Meshtastic hardware, run local mesh, contribute to specs/code on GitHub, join next event.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
