<<<<<<< HEAD
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
Demo: Boot sequence, CoAP /status via LCI, RPL mesh formation, SenML position sharing, range test with adaptive SF. Pricing: $75 single / $65 bulk (includes hardware, case, battery, firmware, source offer per GPL). Use Square/crypto/cash; track with inventory scripts and Beads.

## FAQ
(See resolved key sections below for details on specs.)

**Q: Meshtastic comparison?** LICHEN is incompatible by design (different sync word 0x34, real IPv6, full stack). Superior scaling and standards.

**Q: Commercial/GPL?** Allowed with source offer.

**Q: Scale and testing?** 500-node validated with independent test vector oracles; CCP gates passed in simulator.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
=======
# LICHEN Sales Playbook / PRFAQ: 500-Node Mesh at DEF CON

**Seattle, WA – August 2026** – The LICHEN Project today announced the successful deployment of a 500-node LoRa mesh network at DEF CON 34, demonstrating real-world scalability for open-source IPv6-based mesh networking using re-flashed Meshtastic hardware (T-Echo, etc.). Attendees used standards-based IPv6, SCHC, RPL, OSCORE, CoAP/SenML for position sharing, messaging, emergency check-ins, with border router internet integration. 4 gateways with RAK2287 provided coordination. All under GPL-3.0 (code) / CC-BY-4.0 (docs). LICHEN available for reflash now.

Key differentiators: real IPv6 (no proprietary IDs), standards compliance, decentralized TOFU trust with Schnorr48/OSCORE, scalable non-storing RPL + TDMA/adaptive SF/CH0 control, full interop with test vectors. Demo: boot sequence, CoAP/LCI status, mesh formation, SenML data, "reflash your hardware."

**Pricing/Sales:** $75 single / $65 bulk (includes case, battery, source offer per GPL). Use Square, crypto, cash at events. Inventory via scripts/inventory.sh. Packaging with QR to repo. Post-event: GitHub Sponsors, storefront. License note: always offer source.

## FAQ
**Q: Compare to Meshtastic?** Not backward compatible (different sync word, real IP vs proprietary). Adds routing, sensors, scale, internet gateway.

**Q: GPL for sales?** Commercial OK if source offered (USB/QR/repo). No closed forks.

**Q: Scale/Deployment?** 500 nodes with <1% loss, adaptive SF (per 02a-coordinated-capacity.md pseudocode), GNSS-PPS, multi-SF gateways. Test vectors in test/vectors/ are oracles.

**Q: How to participate?** Reflash existing hardware, contribute to specs/code, run local mesh or next event.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.

(Merge conflicts from worker3 resolved into combined playbook/PRFAQ. Coordinated capacity pseudocode/CH0/DIO references included. CC-BY-4.0. Duplicates removed.)
>>>>>>> origin/worktree-worker24
