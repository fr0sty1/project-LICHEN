<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Acknowledgments

## In Memoriam

**Dave Täht** (1963–2023)

Dave dedicated years to understanding and fixing bufferbloat — the network
latency crisis caused by oversized buffers throughout the internet. His work
on fq_codel, CAKE, and the make-wifi-fast project transformed how we think
about queue management. He proved that "more buffer" is not the answer; that
latency matters as much as throughput; and that good queue discipline makes
networks feel fast even when they're slow.

LICHEN's queue management design draws directly from Dave's insights:
- Small, bounded queues with backpressure
- Time-based packet expiry over byte-based limits
- Fair queuing to prevent single-flow starvation
- "It's not about the bandwidth, it's about the latency"

His Bufferbloat.net project remains essential reading for anyone building
networked systems: https://www.bufferbloat.net/

Dave showed that one determined engineer with the right ideas can fix
problems that entire industries ignored for decades. We honor his memory
by not repeating the mistakes he spent his life correcting.

---

## Pioneers

**Hedy Lamarr and George Antheil**

A Hollywood actress and an avant-garde composer invented spread spectrum
communication in 1942. Their frequency-hopping patent (US 2,292,387) was
designed to make radio-guided torpedoes unjammable. The Navy ignored it
for decades, but the core idea — spreading a signal across frequencies to
resist interference and interception — underlies everything from WiFi to
Bluetooth to GPS to LoRa. Every chirp LICHEN transmits descends from Hedy
and George's wartime invention. She should be as famous for this as for
her films.

**Claude Shannon**

Information theory. The mathematical proof that reliable communication is
possible over noisy channels, and the formula for how much. Shannon's 1948
paper created the field. When we talk about channel capacity, error
correction, or bits per symbol, we're using Shannon's framework. LoRa's
ability to pull signals out of the noise floor is Shannon's theory made
silicon.

---

## Tactical Systems

**The TAK Team (AFRL / TAK Product Center)**

Team Awareness Kit — ATAK, WinTAK, iTAK — started at the Air Force Research
Laboratory and became the situational awareness standard for US military,
first responders, and wildland firefighters. TAK proved that geospatial
common operating pictures could run on phones, not just million-dollar
command posts. LICHEN's position sharing and mesh architecture draw from
the same operational need: "where is everyone, and can they hear me?"
The TAK ecosystem showed what's possible when tactical software escapes
the defense contractors.

**MIL-STD and SINCGARS Heritage**

Decades of military radio development — frequency hopping, COMSEC, mesh
networking under fire — inform what "reliable" means in hostile RF
environments. LICHEN isn't military gear, but the problems are the same:
range, battery, interference, and the assumption that someone may be
listening. The hams and the military have been solving these problems
in parallel for a century.

---

## Foundational Work

**Phil Karn, KA9Q**

Phil created AX.25 and the KA9Q TCP/IP stack in the 1980s, proving that
real IP networking could work over radio links. Before LoRa, before the
internet as we know it, Phil was running TCP/IP over packet radio. His
work on forward error correction (the "Karn algorithm" for RTT estimation)
and amateur radio networking laid the foundation for everything we build.
LICHEN's use of UDP/IPv6 over LoRa is a direct descendant of Phil's vision:
real protocols, not proprietary ones.

**Dan Bernstein (djb)**

The cryptographic primitives LICHEN uses — Curve25519, Ed25519, ChaCha20,
Poly1305 — all trace back to djb. His insistence on simple, fast, secure
primitives with no hidden constants or unexplained magic numbers gave us
NaCl and libsodium. LICHEN's 48-byte Schnorr signatures are built on his
Ed25519 work. When we say "no RSA, no negotiation, just one good curve,"
we're following djb's philosophy.

**Carsten Bormann**

Carsten's IETF work on constrained devices is foundational: CoAP (RFC 7252),
CBOR (RFC 8949), SCHC (RFC 8724), and countless related drafts. LICHEN's
entire application layer — CoAP over UDP, CBOR payloads, SCHC header
compression — comes from specifications Carsten co-authored. His focus on
making protocols work in kilobytes, not megabytes, made IoT practical.

**Pascal Thubert**

RPL (RFC 6550), 6LoWPAN (RFC 4944), and the broader vision of IPv6 for
constrained networks came largely from Pascal's work at Cisco and the IETF.
LICHEN's three-tier routing (RPL for BR traffic, announce for peers, LOADng
for fallback) builds on RPL's Non-Storing Mode. The idea that tiny devices
can speak real IPv6 — that's Pascal's work made real.

**Kevin Hester and the Meshtastic Community**

Meshtastic proved that LoRa mesh networking could escape the lab and work
in people's hands. Kevin's decision to build on commodity hardware and
release everything open source created a community that didn't exist before.
LICHEN runs on Meshtastic-compatible hardware because that hardware exists
and works — and it exists because Meshtastic made the market.

**Semtech**

LoRa modulation itself — the chirp spread spectrum magic that lets us talk
kilometers on milliwatts — came from Semtech's engineers. Without LoRa,
there's no LICHEN. The SX126x and LR1110 chips we target are Semtech silicon.

**Antmicro and the Renode Team**

Renode lets us test firmware without burning hardware. The ability to
simulate nRF52840, ESP32, and STM32WL in software, with our custom SX1262
and LR1110 peripherals, means we can run CI on mesh networks that don't
physically exist. Embedded development without simulation is embedded
development in the dark.

---

## Standards Bodies

The IETF's process — rough consensus, running code, two interoperable
implementations — keeps protocols honest. LICHEN uses:

- **6LoWPAN/SCHC**: RFC 4944, RFC 8724
- **RPL**: RFC 6550
- **CoAP**: RFC 7252, RFC 7641 (Observe), RFC 8613 (OSCORE)
- **IPv6**: RFC 8200
- **Ed25519**: RFC 8032
- **EDHOC**: RFC 9528

We stand on the shoulders of hundreds of IETF contributors who spent years
arguing about packet formats so we don't have to.

---

[Index](README.md)
