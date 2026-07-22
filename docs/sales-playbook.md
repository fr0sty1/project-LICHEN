<<<<<<< HEAD
# LICHEN Sales Playbook for Hacker Conferences

## Vision
Sell 500 pre-flashed T-Echo nodes at DEFCON, HOPE, CCC to bootstrap the mesh network and prove LICHEN's superiority over Meshtastic.

## Key Differentiators (use in pitch)
- **Real IPv6**: Every node has routable IP (link-local + ULA/GUA). No proprietary IDs.
- **Standards-based**: SCHC compression, RPL routing, OSCORE E2E encryption, CoAP apps.
- **Internet integration**: Border routers enable direct communication with cloud/internet hosts.
- **Open source**: Full GPL-3.0 source, no vendor lock-in. Offer source on USB or QR.
- **Mesh that scales**: Non-storing RPL, TOFU trust, SenML sensor data.

**Demo Script (2-3 min):**
1. Show node booting (LED/beep sequence).
2. Demo CoAP GET /status from phone (LCI) or laptop.
3. Show mesh formation with 2-3 nodes (RPL DODAG via gateway console).
4. Send SenML sensor data (temp, location via GNSS).
5. Highlight "This is Meshtastic hardware running real IP mesh - reflash and keep your hardware."
6. Close with "Buy one for $75, includes case, battery, firmware, source. GPL compliant."

## Pricing
- Single unit: $75 (hardware + firmware + case + battery)
- Bulk (10+): $65
- Includes GPL source offer (USB stick or QR to repo).
- Revenue target: $35k+ from sales to cover costs.

## Payment Processors for Conferences
- **Square**: Card reader for in-booth sales (low fees, instant).
- **Crypto**: USDC/BTC wallet with QR (for hacker crowd).
- **Cash**: Receipts for tax compliance.
- Fallback: Venmo/PayPal for online follow-up.

**Inventory Tracking Script**: See `scripts/inventory.sh` (improved with error handling, portable shebang, total command, and CSV init).
Run `chmod +x scripts/inventory.sh` and use `./scripts/inventory.sh record SN1234 00:11:22:33:44:55:66:77 75 square "DEFCON booth demo"`.

## Packaging
- Pre-flashed T-Echo in protective case.
- Sticker: "LICHEN IPv6 LoRa Mesh - GPL-3.0 - Source: github.com/anomalyco/opencode or project-LICHEN repo"
- QR code: `qrencode -o lichen-qr.png -s 6 "https://github.com/anomalyco/project-LICHEN"` (links to repo + build docs).
- Include USB with source tarball or offer per GPL-3.0.

## Post-Event Online Sales
- GitHub Sponsors for firmware/support.
- Dedicated storefront (Shopify or GitHub pages with Stripe).
- Bundle with gateway hardware.

## Booth Logistics Follow-up Beads
- Create beads for volunteer training, booth setup, demo hardware kit, lead follow-up.

## Next Steps
1. Bulk order T-Echo from LilyGO.
2. Finalize flashing pipeline (MCUboot + SMP OTA).
3. Train volunteers on pitch and inventory script.
4. Test full demo flow with current firmware.

**License Note**: All sales must offer source code per GPL-3.0.

This playbook makes conference sales immediately executable.
=======
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
>>>>>>> origin/integration/worker3-20260722
