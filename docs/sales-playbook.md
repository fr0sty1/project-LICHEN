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
