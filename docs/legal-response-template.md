<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Border Router Operator Legal Response Template

This document provides template language for LICHEN border router operators
responding to legal process (subpoenas, preservation orders, lawful access
orders, wiretap demands, etc.).

**This is not legal advice. Consult a lawyer in your jurisdiction.**

## What a LICHEN Border Router Is

A border router (BR) forwards IPv6 packets between a local LoRa mesh and the
internet. It is functionally equivalent to a home router or VPN endpoint -- it
routes packets but does not operate a communications service, does not have
user accounts, and does not store message content.

The reference implementation stores the router's cryptographic keypair in a
hardware security module (HSM) with no key export capability.

## What We Have

| Data | Availability |
|------|--------------|
| Packet payloads | **No** -- end-to-end encrypted (OSCORE), we cannot decrypt |
| Decryption keys | **No** -- each node generates its own keys, we only have ours |
| Our own private key | **No** -- stored in HSM, not exportable by design |
| User identities | **No** -- addresses derived from self-generated cryptographic keys, no registration |
| User accounts | **No** -- none exist |
| Historical messages | **No** -- not stored, forwarded in transit only |
| Real-time intercept capability | **No** -- not technically possible, payloads encrypted |
| IP address logs | **[YES/NO]** -- *[edit based on your setup]* |
| Traffic volume/timing metadata | **[YES/NO]** -- *[edit based on your setup]* |

## Template Response

> **Re: [Reference Number]**
>
> I operate a LICHEN border router, which forwards encrypted IPv6 packets
> between a local radio mesh and the internet. This is packet routing
> infrastructure, not a communications service.
>
> **Data I do not possess and cannot provide:**
>
> - Message content (end-to-end encrypted by senders; I do not hold
>   decryption keys)
> - Decryption keys for any node other than my own router
> - My own router's private key -- the reference implementation stores this
>   in a hardware security module (HSM) with no export capability; I cannot
>   extract it even under compulsion
> - User identities, accounts, or registration records (none exist; the
>   protocol uses self-provisioned cryptographic identities)
> - Historical message logs (messages are forwarded in transit, not stored)
>
> **Technical interception capability:**
>
> None. The protocol does not include any intercept capability. Payload
> encryption occurs at the sending device using keys I do not possess. I
> cannot comply with a prospective wiretap order because I have no technical
> means to decrypt traffic.
>
> **Data I may possess:**
>
> - *[If you keep logs]:* IP address logs and connection timestamps for
>   devices connecting to this router, covering [retention period]. I will
>   preserve/produce these as directed.
> - *[If you don't keep logs]:* I do not retain logs of IP addresses,
>   connection times, or traffic metadata.
> - The HSM hardware itself (which can sign/verify but not export the
>   private key)
>
> **Regarding key disclosure orders:**
>
> The private key is stored in an HSM designed to prevent extraction. This
> is a technical limitation, not a policy choice. Compelling disclosure of a
> key I cannot access is not possible to satisfy.
>
> Physical seizure of the HSM would provide signing capability but not the
> key material itself, and would not enable decryption of other nodes'
> traffic.
>
> **Regarding data preservation:**
>
> I will preserve any data I actually possess as of [date] per your
> instruction. I cannot preserve data I do not have and have no means to
> collect.
>
> I am not in a position to modify the protocol or deploy surveillance
> capabilities. The protocol is open-source and decentralized; any modified
> version would be detectable and undeployable without physical access to
> end-user devices I do not control.
>
> Please direct questions about the protocol itself to the public
> specification at [repo URL].
>
> [Signature]

## Operator Notes

### Before You Receive an Order

1. Decide your logging policy now. Less data = less to produce. Retention of
   IP logs may create obligations.
2. Know your jurisdiction's data retention laws (if any).
3. Have a lawyer's contact info ready.
4. Verify your HSM is configured with key export disabled (reference config
   default).

### When You Receive an Order

1. Verify it's real (call the court/agency directly, not numbers on the
   document).
2. Note any gag order provisions before discussing with others.
3. Consult a lawyer before responding.
4. Respond honestly about what you have. Do not overclaim capabilities you
   lack.

### Do Not

- Attempt to build intercept capability to comply -- you'd likely violate
  wiretap laws by intercepting others' communications.
- Lie about what you have.
- Ignore valid orders (consequences are yours, not the protocol's).
- Disable HSM protections to enable key export (this would compromise the
  network, not just comply with one order).

### HSM Seizure Scenarios

If the HSM is seized, the adversary gains signing capability for *this
router's identity only*. They cannot:

- Decrypt any traffic (BR key is for link auth, not payload encryption)
- Impersonate other nodes
- Retroactively decrypt captured traffic

Mesh nodes using TOFU will continue trusting the seized identity until
manually revoked.

## Protocol Author Response Template

If you maintain the LICHEN protocol or reference implementations (but do not
operate network infrastructure), use this template:

> **Re: [Reference Number]**
>
> We publish open-source protocol specifications and reference
> implementations for the LICHEN mesh networking protocol.
>
> We do not operate any network infrastructure, do not have user accounts,
> do not collect or store any user data, communications, or metadata, and do
> not possess decryption keys. The protocol uses self-provisioned
> cryptographic identities with no central authority.
>
> We are unable to comply because we do not possess the requested data and
> have no technical capability to intercept communications on networks we do
> not operate.
>
> The protocol specification and all source code are publicly available at:
> [repo URL]
>
> [Signature]

## The Honest Truth

A LICHEN border router is closer to a Tor relay or VPN endpoint than a phone
company. It forwards encrypted packets. The operator's own key is in
tamper-resistant hardware. There is no wiretap capability to invoke because
none was built.

Legal responses should reflect this technical reality.

---

*Document version: 2026-08-27*
