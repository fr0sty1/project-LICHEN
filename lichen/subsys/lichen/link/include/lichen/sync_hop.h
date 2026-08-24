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

#endif /* LICHEN_SYNC_HOP_H */
