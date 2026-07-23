# LICHEN 500-Node Mesh Deployment at Hacker Conferences

**Press Release**

**LICHEN Successfully Deploys 500-Node LoRa IPv6 Mesh at DEFCON, HOPE, and CCC, Delivering Scalable, Standards-Based Off-Grid Networking**

Seattle, WA – August 2026 – The LICHEN project today announced the successful real-world deployment of a 500-node mesh network across major hacker conferences, proving that standards-based LoRa networking with native IPv6, SCHC compression, RPL routing, OSCORE security, and CoAP applications can scale to high-density environments where proprietary alternatives fail.

Conference attendees received pre-flashed T-Echo nodes that automatically joined the mesh, shared positions with blue-force tracking, exchanged encrypted messages, and routed traffic to the internet via multiple RAK2287-powered border routers. The network survived gateway failures, high packet loads, and desync events through TDMA slotting, adaptive spreading factors, and density-aware channel selection. Total convergence time under 5 minutes even at peak density of 50 nodes/km².

"This validates our vision of Meshtastic-but-with-real-IP," said the LICHEN team. "500 nodes, full interop between Rust, Zephyr, and Python implementations, and every packet matched our test vectors. The Q4 budget landed at $28,500 including $2,500 shipping, $1,000 tariffs/duties, and $2,000 contingency—under the original $30k projection."

The deployment used the T-Echo as primary hardware (nRF52840 + LR1110/SX1262 + GPS + e-ink), with RPi + RAK2287 gateways running the updated mesh-gateway with multi-channel packet forwarding. All code, vectors, and PRFAQ are open source under GPL-3.0 and CC-BY-4.0.

**Frequently Asked Questions**

**Q: What was the final Q4 budget and how did landed costs factor in?**

A: The Q4 budget landed at $28,500, below the $30k projection. Breakdown:
- Hardware (500× T-Echo @ ~$45 landed): $22,500
- Gateways, jigs, SDR, misc: $2,500
- Shipping and logistics: $2,500
- Tariffs/duties (international components): $1,000
- Contingency/travel/buffer: $2,000 (used for conference booth fees)

Landed cost per node was $48 (including shipping/tariffs), enabling resale at $75+ for cost recovery. Findings from standalone budget analysis (node procurement, bulk pricing negotiations with LilyGO, Renode validation costs) have been fully integrated into this Q4 section rather than maintained separately. No proprietary forks; all modifications released under GPL-3.0.

**Q: How did the mesh perform under conference conditions?**

A: The network handled 50+ nodes/km² with <5% loss using CCP-16 TDMA, adaptive SF (SF9-12 based on SNR/density), and multi-gateway coordination. Position sharing, messaging, and SOS features worked end-to-end with OSCORE. Border routers provided IPv6 routing to the internet. Failover was automatic via RPL.

**Q: What hardware was used and why T-Echo?**

A: Primary: 500× Seeed T-Echo (nRF52840 + LR1110 GNSS + e-ink). Gateways: Raspberry Pi 5 + RAK2287 HATs (multi-channel SX1302). The T-Echo was chosen for built-in GPS (critical for time sync/TDMA), e-ink status display, and Meshtastic-compatible form factor for easy reflash. All Renode/Zephyr support validated pre-deployment.

**Q: Is the code and data public?**

A: Yes. Full source (GPL-3.0), specs (CC-BY-4.0), test vectors, PRFAQ, and deployment logs are at github.com/MarkAtwood/project-LICHEN. Interop tests between Rust gateway, Zephyr nodes, and Python sim passed 100%.

**Q: What are the next steps after this deployment?**

A: Scale to 2000 nodes, add LR-FHSS for longer range, production OTA with MCUmgr, mobile LCI apps, and IETF draft submission for the protocol. Commercial partners can build on the open source without proprietary lock-in (source must be provided).

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
