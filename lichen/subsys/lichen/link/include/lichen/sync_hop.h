/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sync_hop.h
 * @brief GNSS-synchronized frequency hopping for LICHEN
 *
 * Implements CCP-12 synchronized hopping: all nodes derive the same
 * channel from the superframe number (SFN) using a deterministic hash.
 */

#ifndef LICHEN_SYNC_HOP_H
#define LICHEN_SYNC_HOP_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Calculate hop channel from SFN using LICHEN hash.
 * @param sfn Superframe number
 * @param seed Hopping seed
 * @param n_channels Number of channels (minimum 3)
 * @return Channel in range [1, n_channels]
 */
uint8_t lichen_sync_hop_channel(uint32_t sfn, uint32_t seed, uint8_t n_channels);

/**
 * @brief Derive SFN from unix timestamp.
 * @param unix_time_ms Unix time in milliseconds
 * @return Superframe number
 */
uint32_t lichen_sfn_from_unix_ms(uint64_t unix_time_ms);

/**
 * @brief ASN/SFN derivation result per spec 09-packets-timing.md 14.7.
 *
 * Duration-parametric time-counter derivation from Unix UTC microseconds.
 * With a slot/superframe duration, the unbounded quotient is an Absolute
 * Slot Number (ASN, u64); its low 32 bits are the TDMA SFN.
 */
struct lichen_asn_sfn_result {
    uint64_t asn;      /**< Absolute slot number (unbounded u64 quotient) */
    uint32_t sfn;      /**< Superframe number (asn mod 2^32) */
    bool clamped;      /**< True if result was clamped to zero */
};

/**
 * @brief Derive ASN and SFN from Unix UTC microseconds.
 *
 * Implements the spec 09-packets-timing.md 14.7 derivation:
 *   ASN = (unix_time_us - epoch_base_us) / interval_duration_us
 *   SFN = ASN mod 2^32
 *
 * Edge cases:
 *   - unix_time_us < epoch_base_us: clamps to 0, clamped=true
 *   - interval_duration_us == 0: clamps to 0, clamped=true
 *
 * @param unix_time_us Unix UTC timestamp in microseconds
 * @param epoch_base_us Epoch base time in microseconds
 * @param interval_duration_us Slot/superframe duration in microseconds
 * @param result Output structure for ASN/SFN/clamped (must not be NULL)
 * @return 0 on success, -EINVAL if result is NULL
 */
int lichen_asn_sfn_derive(uint64_t unix_time_us,
                          uint64_t epoch_base_us,
                          uint64_t interval_duration_us,
                          struct lichen_asn_sfn_result *result);

#endif /* LICHEN_SYNC_HOP_H */
