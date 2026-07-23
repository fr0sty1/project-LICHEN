# LICHEN 500-Node Mesh Network Debuts at DEF CON 34

**Seattle, WA – August 2026** – The LICHEN Project today announced the successful deployment of a 500-node LoRa mesh network at DEF CON 34, demonstrating real-world scalability for open-source IPv6-based mesh networking. Attendees experienced direct communication across the convention floor using re-flashed T-Echo devices running the LICHEN protocol, with live visualization on a central dashboard showing position sharing, anonymous messaging, and emergency check-ins without proprietary servers or single points of failure.

"LICHEN turns existing Meshtastic hardware into a standards-based IPv6 mesh that scales to hundreds of nodes with TDMA, SCHC compression, RPL routing, and OSCORE security," said Mark Atwood, LICHEN project lead. "This isn't a prototype—500 nodes operated simultaneously with sub-1% packet loss, GPS-synchronized timing, gateway handoff, and full interop between Rust gateways, Zephyr nodes, and Python simulators. The network survived jamming attempts, power cycles, and mobility tests while maintaining end-to-end encryption and decentralized trust."

The deployment used 4 gateways with RAK2287 concentrators for backbone coordination, multi-SF reception, and CoAP aggregation to a big-screen dashboard. Nodes shared SenML location data, confessions via dead-drop DTN, and presence status using the Local Client Interface over BLE. All code, specs, test vectors, and results are public under GPL-3.0 (code) and CC-BY-4.0 (docs).

LICHEN is available now for reflash on supported hardware. See lichen-project.org for firmware, docs, and the full 500-node dataset.

## FAQ

**Q: How does this compare to Meshtastic?**

A: LICHEN is not backward-compatible by design. It uses a different sync word, real IPv6 instead of proprietary IDs, SCHC/RPL/CoAP/OSCORE for standards compliance, and multi-gateway coordination for scale. Meshtastic excels at simple text; LICHEN adds IP routing, sensor SenML, DTN, and hacker-conference scale.

**Q: What about GPL implications for commercial use?**

A: Commercial use is allowed. Distributors must provide source or a written offer to provide it (GPL-3.0 §6). The project encourages forks and derivatives as long as the license is preserved. No proprietary closed forks.

**Q: How was the 500-node flash and QA done?**

A: Automated UF2 drag-and-drop with serial DFU fallback, pogo-pin jig for parallel flashing, and Renode/Zephyr native_sim pre-validation. Post-flash QA used range test pings, GPS lock verification, and e-ink QR self-ID. Full inventory tracked via CLI with Beads.

**Q: What is the cost model and revenue?**

A: Bulk T-Echo ~$50/unit. Sold post-event at $75 with full source and docs. Revenue covers hardware with surplus for next event. Grants targeted for initial 500-unit purchase.

**Q: How does trust and security work without a central CA?**

A: TOFU baseline with per-peer key pinning (SSH-style). DANE/PKIX optional when internet available. Schnorr-48 signatures on all frames, OSCORE E2E encryption, replay protection with SSN in NVM. No PSK network password.

**Q: Will this work in a real deployment beyond the con?**

A: Yes. The 500-node test included mobility, gateway handoff, multi-channel TDMA, adaptive SF for interference, and border router upstream IPv6. Production gateways support WiFi/Ethernet backbone coordination. See full test report and vectors.

**Q: How can I participate or contribute?**

A: Reflash your Meshtastic hardware today. Code, specs, and tests are on GitHub. Join the next event deployment or run a local mesh. All contributions under the project licenses.

**What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.

