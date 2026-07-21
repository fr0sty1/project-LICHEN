<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Brand Concept

## Status

This document defines a direction for the LICHEN brand. It is not a final logo
standard. No symbol, drawing, font file, or production color has been adopted
until it is tested in the applications described here and approved separately.

The narrative is intentionally aspirational and written from the target state
in which LICHEN is production-ready. It describes the finished brand promise,
not the chronology of engineering work needed to reach it.

The concept is intended to remain useful if individual protocols, radios, or
implementations change. Technical standards belong in supporting proof, not in
the timeless brand promise.

## Core Idea

**Where infrastructure ends, LICHEN grows.**

Lichen survives on exposed surfaces where little else can establish itself. It
is persistent, efficient, decentralized, and formed by cooperation between
different organisms. LICHEN networks should feel the same way: quiet
infrastructure that people and devices can establish in places where dependable
communications are absent, damaged, unaffordable, or out of reach.

The brand leads with **where it works**, then explains **how it works**.

## Positioning

### Brand Promise

LICHEN provides resilient, low-power communications among people and devices
operating beyond dependable infrastructure.

### Audience

- Communities building their own local infrastructure
- Field researchers and environmental monitoring teams
- Emergency and mutual-aid operators
- Backcountry groups and remote workers
- Radio, networking, and open-hardware builders
- Organizations deploying sensors or communications in difficult terrain

### Distinction

LICHEN is not presented as another chat gadget, environmental lifestyle brand,
or proprietary radio ecosystem. It is open, standards-based field
infrastructure designed to continue operating locally without a cloud service.

The first sentence should communicate place and purpose. Terms such as LoRa,
IPv6, CoAP, RPL, and Yggdrasil may substantiate the claim in technical copy,
but should not appear in the primary tagline or define the visual identity.

## Tagline System

### Primary

> **Where infrastructure ends, LICHEN grows.**

This is the preferred public-facing line. It names the operating environment,
connects directly to the biological metaphor, and does not depend on a current
technology.

### Supporting Lines

- **Connected where coverage ends.**
- **Built for places networks do not reach.**
- **Quietly connected in hard places.**
- **Carry the network into the field.**

Supporting lines may be selected for context. “Coverage” is appropriate for a
general audience; “field” is appropriate for hardware and deployment material;
“quietly connected” is appropriate for low-power products.

### Usage

- Lead with one tagline, not a stack of slogans.
- Follow it with one plain sentence describing the product or deployment.
- Put protocol names and performance claims in the evidence that follows.
- Do not claim universal coverage, guaranteed delivery, zero collisions, or
  independence from all infrastructure.

### Sample Introduction

> **Where infrastructure ends, LICHEN grows.**
>
> LICHEN is a resilient, low-power network for people and devices in remote,
> disrupted, and underserved places. It works locally first and connects
> outward when a gateway is available.

## Visual Concept: Signal on Stone

The visual system pairs an organic lichen form with the restraint of field and
scientific equipment. It should look established rather than futuristic: a
small, persistent signal growing across a durable surface.

### Symbol Brief

Explore an asymmetric crustose-lichen mark with an open, branching edge. The
form may suggest several cooperating lobes or paths, but it must not contain a
dominant central node. The silhouette should feel grown rather than plotted.

The mark must:

- Work in solid black or solid white with no gradients
- Remain recognizable inside a 16 by 16 pixel favicon and at 24 by 24 pixels on
  the T-Echo's 200 by 200 pixel e-ink display at a 30-60 cm viewing distance
- Reproduce in PCB silkscreen, laser engraving, embroidery, and a rubber stamp
- Read as a durable patch or colony rather than a flower, leaf, or tree
- Have a simple outer silhouette and generous internal negative space
- Pair cleanly with the uppercase wordmark `LICHEN`

The mark should not depend on an IPv6 colon, radio waves, an antenna, or another
current protocol symbol. Those motifs may appear in technical illustrations,
but not as the core identity.

### Wordmark

Use `LICHEN` in uppercase Atkinson Hyperlegible Bold as the starting point. The
initial wordmark should use the unmodified typeface. Any later custom lettering
must improve distinctiveness without reducing the letter differentiation that
makes the typeface readable.

LICHEN began as the technical acronym “LoRa IPv6 CoAP Hybrid Extended Network.”
The public brand treats LICHEN as a standalone name so the identity can outlive
individual stack choices. Do not expand the acronym in the primary lockup; keep
the canonical expansion in technical and organizational material.

### Lockups To Explore

1. Symbol beside `LICHEN`
2. Symbol above `LICHEN` for square applications
3. Wordmark alone for narrow hardware and terminal surfaces
4. One-color symbol alone for favicon, button, boot screen, and silkscreen

## Color

Color should evoke stone, mineral surfaces, and real lichen rather than generic
“technology green.” Orange is a signal: visible, warm, and rare.

| Role | Name | Starting value | Use |
|------|------|----------------|-----|
| Dark foundation | Basalt | `#202521` | Dark backgrounds, hardware, primary text |
| Light foundation | Mineral | `#F1EEE6` | Light backgrounds, paper, diagrams |
| Secondary neutral | Lichen gray | `#717968` | Secondary surfaces and supporting graphics |
| Quiet boundary | Fog | `#CBD0C5` | Decorative rules and non-semantic diagram structure |
| Focal accent | Signal orange | `#F07C22` | Key action, physical accent, sparse emphasis |
| Provisional dark accent | Burnt orange | `#A94712` | Candidate text/link accent on Mineral after testing |

These are concept values, not production specifications. Final values require
screen, print, enclosure, and accessibility testing.

### Orange Discipline

- Orange should normally occupy no more than about five percent of a composition.
- Use it to establish one focal action or point of attention per composition.
- Do not use orange as a full-page background or routine body-text color.
- Do not make every button orange; reserve it for the primary action.
- Never use orange alone to communicate alarm, trust, link state, or priority.
- Signal orange on Mineral and Fog on Mineral are decorative combinations only;
  they MUST NOT define meaningful text, control boundaries, or status.
- A meaningful orange control pairs an icon or label with the state and uses a
  contrast-tested foreground/background pair, such as Basalt text on an orange
  fill, rather than an orange outline alone.
- On hardware, one orange control, gasket, label, or fastener is stronger than
  an orange enclosure.
- Field radios may exceed the five-percent guideline with one replaceable band
  of fluorescent or retroreflective high-visibility orange tape when visibility,
  recovery, or team identification is the purpose. This operational exception
  does not make broad orange coverage appropriate for general brand layouts.

The brand must remain complete in black and white. Orange adds signal, not
identity.

## Typography

Use **Atkinson Hyperlegible** as the primary brand and product typeface. Its
purpose aligns with LICHEN: information should remain distinguishable under
imperfect viewing conditions, on small displays, and in the field.

| Application | Style |
|-------------|-------|
| Wordmark | Atkinson Hyperlegible Bold, uppercase |
| Headings | Bold, sentence case |
| Body and documentation | Regular |
| Labels and controls | Bold or Regular, sentence case |
| Addresses and diagnostics | Atkinson Hyperlegible Mono when available; otherwise a tested system monospace |

Typography rules:

- Digital body text SHOULD default to at least 16 CSS pixels, a line height of
  at least 1.4, and lines between approximately 45 and 80 characters.
- Fixed e-ink body text SHOULD render at least 16 pixels high at a 30-60 cm
  viewing distance; validate smaller labels on the actual display.
- Do not use all caps for paragraphs, warnings, or long labels.
- Prefer real weights over outlines, shadows, or simulated bold.
- Do not introduce a condensed display face merely to appear technical.
- Package font files only after confirming the applicable open-font license and
  defining web, firmware, and document subsets.

## Voice

LICHEN speaks like a calm field engineer: direct, observant, and honest about
conditions. It does not sound militarized, apocalyptic, mystical, or
evangelical.

### Principles

- Lead with human or operational benefit.
- Use concrete places and conditions.
- Explain technical evidence without turning the headline into a standards list.
- State limits and fallback behavior plainly.
- Prefer “works locally” to “disrupts connectivity.”
- Prefer “resilient” to “unstoppable.”
- Prefer “open” to “permissionless” unless the latter is technically required.

### Examples

| Prefer | Avoid |
|--------|-------|
| “When a gateway is down, available local routes can keep messages moving.” | “Unstoppable decentralized communications.” |
| “Built for remote and disrupted places.” | “The ultimate off-grid tactical mesh.” |
| “Connect outward when infrastructure is available.” | “Replace the Internet.” |
| “Measured for this radio profile and terrain.” | “Zero collisions and unlimited range.” |
| “Your node keeps its identity and keys.” | “Trustless military-grade security.” |

## Imagery And Graphic Language

Use imagery of deployment rather than lifestyle aspiration:

- Stone, bark, weathered metal, and mineral surfaces
- Field notebooks, instruments, maps, enclosures, antennas, and hands at work
- Topographic contours and sparse scientific annotations
- Real radios in real terrain and imperfect weather
- Packet, power, and signal evidence presented as specimen labels

Graphic forms may grow from an edge, bridge a gap, or accumulate in small
colonies. Avoid glossy 3D networks, glowing global spheres, camouflage, generic
green leaves, and dense node-link diagrams used as decoration.

## Hardware And E-Ink

Hardware is a primary brand surface, not an adaptation of the website.

### E-Ink

- Design the boot mark in one bit before adding color elsewhere.
- Use the wordmark only when the full mark would be too small.
- Favor large type, clear status language, and persistent quiet screens.
- Orange must never be required to interpret a state shown on monochrome e-ink.

### Enclosures

- Basalt or mineral should dominate the enclosure.
- A matte silver-green enclosure may use sparse mineral or crustose-lichen
  patterning. Keep the pattern organic and irregular without resembling
  military camouflage.
- Signal orange may identify one control, seal, antenna detail, or service point.
- A replaceable high-visibility orange tape band may wrap the radio as a field
  identification and recovery feature. Keep it clear of antennas, GNSS reception
  areas, displays, controls, vents, microphones, speakers, ports, and required
  safety or certification labels.
- Labels should remain legible after wear and in low light.
- The node fingerprint or recovery identity may appear inside the battery cover
  or on a replaceable label, not as ornamental visual noise.
- Validate patterned coatings and tape materials for RF transparency, UV and
  water exposure, abrasion, temperature extremes, gloved handling, adhesive
  residue, and field replacement before production.

### PCB And Engraving

- Maintain a simplified one-color symbol with minimum feature sizes specified
  for silkscreen and laser processes.
- Do not use a detailed organic illustration where a production mark is needed.
- Keep certification, revision, and safety labels visually separate from the
  brand mark.

## Accessibility

Accessibility is part of the concept, not a later compliance pass.

- Test final digital foreground/background pairs against WCAG 2.2 Level AA:
  4.5:1 for normal text, 3:1 for large text, and 3:1 for meaningful non-text
  boundaries and indicators.
- Do not rely on hue alone; pair color with text, shape, position, or pattern.
- Keep focus, selection, alarm, trust, and radio state distinguishable without orange.
- Preserve user font scaling in applications.
- Use plain status labels before abbreviations.
- Test e-ink screens in glare, dim light, and partial-refresh failure states.
- Test the symbol and wordmark for low vision, color-vision differences, blur,
  photocopying, and poor printing.

## Naming

Keep product and service names literal. The natural metaphor belongs in the
master brand and visual system, not in a taxonomy that users must decode. The
following are naming candidates, not adopted products:

- LICHEN Node
- LICHEN Gateway
- LICHEN Relay, an unattended always-on node optimized to forward traffic
- LICHEN Console
- LICHEN Field Kit
- LICHEN Mail
- LICHEN Bridge

Use title case in prose and uppercase only for the master wordmark. “Gateway”
means a network boundary role; “Bridge” is reserved for an application or
protocol adapter. Avoid inventing a different nature-themed name for every
component.

## Brand Boundaries

LICHEN should not look or sound like:

- A generic green environmental nonprofit
- A tactical or weapons product
- A cryptocurrency or “Web3” network
- A cloud service pretending to be decentralized
- A consumer social network
- A protocol acronym in search of a human purpose

Do not use proprietary ecosystem marks in a way that implies compatibility or
endorsement. Meshtastic-compatible hardware, Yggdrasil participation, and other
relationships should be described accurately in supporting copy.

## Next Design Work

1. Produce three distinct one-color symbol sketches from the Signal on Stone brief.
2. Test each at favicon, e-ink, PCB silkscreen, enclosure, document, and banner sizes.
3. Build wordmark and square/horizontal lockups using Atkinson Hyperlegible.
4. Run accessibility and reproduction tests before selecting a mark.
5. Refine the palette using screen, print, and enclosure samples, keeping orange sparse.
6. Create a small asset package only after approval: SVG masters, one-color variants,
   spacing/minimum-size rules, font guidance, and sample applications.
7. Validate the primary tagline with field users and contributors before treating
   it as permanent campaign copy.
8. Before physical production, define vendor-specific minimum stroke, gap,
   knockout, engraving depth, embroidery, wear, illumination, and viewing-distance
   acceptance criteria and approve physical proofs.

The immediate decision is the concept, not a polished identity system:

> **Where infrastructure ends, LICHEN grows.**

> Quiet, resilient communication. A signal established on stone.
