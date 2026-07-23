<<<<<<< HEAD
# LICHEN 500-Node Mesh Network Debuts at DEF CON 34

**Seattle, WA – August 2026** – The LICHEN Project today announced the successful deployment of a 500-node LoRa mesh network at DEF CON 34, demonstrating real-world scalability for open-source IPv6-based mesh networking. Attendees experienced direct communication across the convention floor using re-flashed T-Echo devices running the LICHEN protocol, with live visualization on a central dashboard showing position sharing, anonymous messaging, and emergency check-ins without proprietary servers or single points of failure.

"LICHEN turns existing Meshtastic hardware into a standards-based IPv6 mesh that scales to hundreds of nodes with TDMA, SCHC compression, RPL routing, and OSCORE security," said Mark Atwood, LICHEN project lead. "This isn't a prototype—500 nodes operated simultaneously with sub-1% packet loss, GPS-synchronized timing, gateway handoff, and full interop between Rust gateways, Zephyr nodes, and Python simulators. The network survived jamming attempts, power cycles, and mobility tests while maintaining end-to-end encryption and decentralized trust."

The deployment used 4 gateways with RAK2287 concentrators for backbone coordination, multi-SF reception, and CoAP aggregation to a big-screen dashboard. Nodes shared SenML location data, confessions via dead-drop DTN, and presence status using the Local Client Interface over BLE. All code, specs, test vectors, and results are public under GPL-3.0 (code) and CC-BY-4.0 (docs).

LICHEN is available now for reflash on supported hardware. See lichen-project.org for firmware, docs, and the full 500-node dataset.
=======
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
>>>>>>> origin/worktree-worker23

## FAQ
(See resolved key sections below for details on specs.)

**Q: Meshtastic comparison?** LICHEN is incompatible by design (different sync word 0x34, real IPv6, full stack). Superior scaling and standards.

**Q: Commercial/GPL?** Allowed with source offer.

**Q: Scale and testing?** 500-node validated with independent test vector oracles; CCP gates passed in simulator.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
<<<<<<< HEAD

=======
>>>>>>> origin/worktree-worker23
