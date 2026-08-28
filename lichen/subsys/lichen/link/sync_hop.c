/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sync_hop.c
 * @brief GNSS-synchronized frequency hopping implementation
 */

#include <lichen/sync_hop.h>

#include <errno.h>
#include <stddef.h>

/* Provided by the link module; keep this file independent of Zephyr-only L2
 * headers. */
uint32_t lichen_hash_32(const uint8_t *data, size_t len);

/* 2024-01-01 00:00:00 UTC */
#define EPOCH_BASE_MS 1704067200000ULL

uint8_t lichen_sync_hop_channel(uint32_t sfn, uint32_t seed, uint8_t n_channels)
{
    uint8_t data[8];
    uint32_t hash;

    /* Pack seed (LE) || sfn (LE) */
    data[0] = (uint8_t)(seed);
    data[1] = (uint8_t)(seed >> 8);
    data[2] = (uint8_t)(seed >> 16);
    data[3] = (uint8_t)(seed >> 24);
    data[4] = (uint8_t)(sfn);
    data[5] = (uint8_t)(sfn >> 8);
    data[6] = (uint8_t)(sfn >> 16);
    data[7] = (uint8_t)(sfn >> 24);

    hash = lichen_hash_32(data, sizeof(data));

    /* n_channels includes reserved CH0.  A degenerate plan containing only
     * CH0 has no data channel and therefore fails closed to CH0. */
    if (n_channels <= 1U) {
        return 0U;
    }

    return (uint8_t)(1U + (hash % (uint32_t)(n_channels - 1U)));
}

uint32_t lichen_sfn_from_unix_ms(uint64_t unix_time_ms)
{
    uint64_t superframe_ms = CONFIG_LICHEN_SYNC_HOP_SUPERFRAME_MS;

    /* SECURITY: Prevent underflow if timestamp is before epoch base (spoofed/malformed GNSS) */
    if (unix_time_ms < EPOCH_BASE_MS) {
        return 0;
    }

    return (uint32_t)((unix_time_ms - EPOCH_BASE_MS) / superframe_ms);
}

int lichen_asn_sfn_derive(uint64_t unix_time_us, uint64_t epoch_base_us,
                          uint64_t interval_duration_us,
                          struct lichen_asn_sfn_result *result) {
  struct lichen_asn_sfn_result derived;

  if (result == NULL) {
    return -EINVAL;
  }

  /* SECURITY: Clamp to zero for invalid inputs per spec
   * 09-packets-timing.md 14.7 */
  if (interval_duration_us == 0 || unix_time_us < epoch_base_us) {
    derived = (struct lichen_asn_sfn_result){
        .asn = 0,
        .sfn = 0,
        .clamped = true,
    };
  } else {
    /* Subtract only after the ordering check, avoiding unsigned wrap. */
    derived.asn = (unix_time_us - epoch_base_us) / interval_duration_us;
    derived.sfn = (uint32_t)derived.asn;
    derived.clamped = false;
  }

  /* Commit all result fields only after the derivation is complete. */
  *result = derived;
  return 0;
}

int lichen_asn_sfn_derive_sample(const struct lichen_asn_time_sample *sample,
                                 uint64_t epoch_base_us,
                                 uint64_t interval_duration_us,
                                 struct lichen_asn_sfn_result *result) {
  struct lichen_asn_sfn_result derived;
  uint64_t seconds;
  uint64_t unix_time_us;
  int ret;

  if (sample == NULL || result == NULL || interval_duration_us == 0) {
    return -EINVAL;
  }
  if (!sample->wall_clock_valid || !sample->source_valid ||
      sample->scale != LICHEN_ASN_TIME_SCALE_UNIX_UTC || sample->stratum == 0 ||
      sample->stratum > 4) {
    return -EACCES;
  }
  if (sample->unix_seconds < 0 || sample->subsecond_us >= 1000000U) {
    return -ERANGE;
  }

  seconds = (uint64_t)sample->unix_seconds;
  if (seconds > (UINT64_MAX - sample->subsecond_us) / 1000000U) {
    return -EOVERFLOW;
  }
  unix_time_us = seconds * 1000000U + sample->subsecond_us;

  if (unix_time_us < sample->effective_epoch_floor_us) {
    return -ESTALE;
  }
  if (unix_time_us < epoch_base_us) {
    return -ERANGE;
  }

  ret = lichen_asn_sfn_derive(unix_time_us, epoch_base_us, interval_duration_us,
                              &derived);
  if (ret != 0 || derived.clamped) {
    return ret != 0 ? ret : -ERANGE;
  }

  *result = derived;
  return 0;
}
