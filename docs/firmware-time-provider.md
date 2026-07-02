<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Firmware Date/Time Provider Design

This document defines the no-hardware policy for firmware wall-clock time. It
feeds the firmware-wide date/time provider tracked by `project-LICHEN-2067` and
keeps GNSS, network, local-client, and manual time sources from inventing
separate freshness rules.

## Epoch Floor

LICHEN firmware has two lower bounds for plausible Unix wall-clock time:

| Floor | Source | Policy |
|-------|--------|--------|
| Firmware build epoch | Deterministic firmware metadata, preferably `SOURCE_DATE_EPOCH`, or an explicit configured release epoch. | Required for production firmware. It is the minimum plausible wall-clock value for time accepted after boot. |
| Board provision epoch | Optional per-device manufacturing/provisioning timestamp stored with board identity or settings. | If present and valid, it overrides the build epoch as the stricter floor because the device cannot legitimately observe time before provisioning. |

The effective epoch floor is:

```text
effective_epoch_floor = max(firmware_build_epoch, board_provision_epoch_if_valid)
```

Production builds MUST NOT silently use the build host's current wall clock as
the firmware build epoch. If deterministic build metadata is unavailable, the
production build MUST fail. Developer builds MAY carry a generated timestamp
only when the metadata records that it is non-reproducible and tests cover that
mode explicitly.

The Zephyr firmware entry points use `lichen/cmake/lichen_build_epoch.cmake`
before Kconfig is loaded. In production mode, the helper derives
`CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX` from `SOURCE_DATE_EPOCH` or from an
explicit `-DLICHEN_RELEASE_EPOCH_UNIX=<unix-seconds>` value; missing production
metadata is a configure-time error. Non-reproducible developer timestamps are
allowed only with `-DLICHEN_TIME_BUILD_EPOCH_MODE=developer-generated`, and the
generated Kconfig metadata records that source separately from release metadata
and from explicit developer fixed-epoch overrides.

Provision metadata is valid only when it is explicitly present, authenticated or
integrity-checked by the same mechanism that protects board identity/settings,
non-zero, at or after the firmware build epoch, and no later than a deterministic
maximum provision lead relative to the firmware build epoch. The lead bound is a
configuration constant or release-policy value, not a comparison with an
untrusted current clock at boot.

Missing, zero, malformed, unauthenticated, earlier-than-build, or beyond-lead
provision epochs MUST be ignored for the effective floor and reported as
diagnostics. A corrupt board provision value must not permanently prevent
wall-clock establishment. Recovery mechanisms include ignoring invalid provision
metadata, accepting a source at or above the build floor when no valid provision
floor exists, and allowing an authenticated provisioning or administrative path
to replace or clear the stored provision epoch.

Time samples with a Unix timestamp below `effective_epoch_floor` MUST NOT make
the provider report valid wall-clock time. The provider MAY retain the sample as
diagnostic metadata, but consumers must see `wall_clock_valid=false` until a
sample at or above the floor is accepted.

This floor is not a clock source. It is a sanity guard for cold-start GNSS,
network, local-client, and manual time. It prevents common failures such as a
GNSS module reporting its default epoch, a phone/app sending a zero timestamp,
or a board booting with an uninitialized RTC.

## Source Classes

The provider should use one internal representation for all source classes:

| Source class | Examples | Can establish wall clock? | Notes |
|--------------|----------|---------------------------|-------|
| Monotonic/internal | uptime, cycle counter | No | Provides age and ordering only. |
| Internal RTC | retained RTC, external RTC chip | Yes, if timestamp is at or above the floor | Accuracy should degrade with age unless corrected. |
| GNSS | onboard/external GNSS fix time | Yes, if GNSS reports a valid time and timestamp is at or above the floor | Position fix and time validity are independent. |
| Network | SNTP/NTP, mesh time, border-router time | Yes, if authenticated or policy-accepted and at or above the floor | Trust metadata should be exposed separately from freshness. |
| Local client | phone/app/UI over LCI, BLE, SLIP, IPC | Yes, if policy permits and at or above the floor | Must be source-attributed; not implicitly more trusted than network time. |
| Manual/static | configured Unix time or provisioning tool | Yes, if policy permits and at or above the floor | Use for lab/simulator workflows and devices without GNSS. |

Every accepted sample records:

- source class and source name,
- Unix seconds and optional fractional/accuracy metadata,
- monotonic observed time,
- freshness/age,
- trust or quality metadata,
- whether the sample passed the effective epoch floor.

## Implementation Boundary

The firmware-wide date/time provider is a new abstraction for
`project-LICHEN-2067`; existing location-centered fields do not satisfy it by
themselves. Current HAL and app-interface location fields such as
`fix_time_unix_valid`, `fix_time_unix`, `fix_source`, and time-provider
capability flags can feed or consume the provider, but they are not the provider
state.

The provider state needs distinct wall-clock fields: source class, source name,
wall-clock validity, accepted Unix time, monotonic observation time, age,
accuracy or quality metadata, trust/precedence metadata, and the last rejection
reason. Gateway status, CoAP resources, and app-compat layers should expose
that unified provider state instead of treating GNSS fix time or uptime as the
firmware clock.

## Acceptance Policy

1. Reject invalid encodings, missing timestamps, and timestamps below the
   effective epoch floor for wall-clock establishment.
2. Preserve monotonic uptime as a fallback for age calculations even when wall
   clock is invalid.
3. Never synthesize Unix time from uptime. Uptime can age an accepted sample,
   but it is not itself a Unix epoch.
4. Prefer higher-trust/fresher samples according to the provider precedence
   policy in `project-LICHEN-2067`; the epoch floor is applied before
   precedence.
5. Do not step accepted wall time backwards unless the new source has an equal
   or higher trust class and policy explicitly allows correction.
6. Expose rejected-below-floor status in diagnostics or tests so GNSS cold-start
   failures are observable without hardware.

## GNSS Interaction

GNSS can provide both position and time, but the firmware must evaluate them
separately:

- A GNSS position fix without valid GNSS time may still be useful for location
  if the location provider marks `fix_time_unix_valid=false`.
- A GNSS time sample below the epoch floor is invalid for wall-clock, even if
  the position fields look plausible.
- A GNSS time sample at or above the floor can establish wall-clock time even
  before other network sources are available, subject to source trust policy.

Physical GNSS validation remains hardware-blocked. The no-hardware requirement
is to model these states in the provider API and simulator/native tests.

## Meshtastic Position Interaction

Meshtastic-compatible app surfaces can submit `POSITION_APP` payloads over a
local client transport. For those payloads, Meshtastic `timestamp` field 7 is
the preferred fix timestamp and `time` field 4 is only a fallback. A chosen
timestamp below the firmware build epoch floor is stripped from the submitted
location metadata, while otherwise valid coordinates remain usable as a
local-client position. If Position-derived time is submitted to the shared time
provider, the normal effective floor applies: a valid board/provision epoch
stricter than the build epoch rejects below-floor time.

## Test Plan

The no-hardware test suite for `project-LICHEN-2067` MUST include `native_sim`
coverage, with qemu coverage added where board-independent Zephyr behavior is
relevant, for:

| Case | Expected result |
|------|-----------------|
| Build epoch only, sample below build epoch | `wall_clock_valid=false`; rejection reason indicates below floor. |
| Build epoch only, sample equal to build epoch | sample can establish wall-clock if source policy permits. |
| Production build without deterministic build epoch | build fails before firmware can ship. |
| Developer build with generated non-reproducible timestamp | mode is explicit in metadata and tests assert the generated value is not treated as a release build epoch. |
| Build epoch plus provision epoch, sample between them | rejected because provision epoch is stricter. |
| Provision epoch earlier than build epoch | build epoch remains the effective floor. |
| Provision epoch missing, zero, malformed, unauthenticated, beyond the lead bound, or too far future | provision epoch is ignored, diagnostics record why, and build epoch remains the effective floor. |
| Integrity-valid provision epoch beyond the deterministic lead bound | provision epoch is ignored, diagnostics identify future-bound rejection, and a sample at or above the build floor can still establish wall-clock. |
| Authenticated administrative replacement or clearing of poisoned provision epoch | effective floor recomputes from the replacement provision epoch or the build epoch. |
| GNSS time below floor with valid position | time invalid; location can keep position metadata with `fix_time_unix_valid=false`. |
| Local-client/manual time at or above floor | accepted when source policy permits and source metadata is preserved. |
| Uptime-only boot | no Unix time is synthesized from uptime. |
| New lower-trust stale time after accepted time | does not move wall clock backwards. |

Tests should also assert that CoAP/status/app-compat consumers expose source
class, source name, wall-clock validity, age, and accuracy/quality without
needing to know whether the accepted source was GNSS, network, local-client, or
manual/static.
