/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sync_hop.c
 * @brief GNSS-synchronized frequency hopping implementation
 */

#include <lichen/sync_hop.h>
#include <lichen_util.h>

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

    if (n_channels < 3) {
        n_channels = 3;
    }

    return 1 + (hash % n_channels);
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

int lichen_asn_sfn_derive(uint64_t unix_time_us,
                          uint64_t epoch_base_us,
                          uint64_t interval_duration_us,
                          struct lichen_asn_sfn_result *result)
{
    if (result == NULL) {
        return -EINVAL;
    }

    /* SECURITY: Clamp to zero for invalid inputs per spec 09-packets-timing.md 14.7 */
    if (interval_duration_us == 0 || unix_time_us < epoch_base_us) {
        result->asn = 0;
        result->sfn = 0;
        result->clamped = true;
        return 0;
    }

    /* Compute ASN as unbounded u64 quotient */
    result->asn = (unix_time_us - epoch_base_us) / interval_duration_us;

    /* SFN is the low 32 bits of ASN */
    result->sfn = (uint32_t)(result->asn & 0xFFFFFFFFULL);
    result->clamped = false;

    return 0;
}
