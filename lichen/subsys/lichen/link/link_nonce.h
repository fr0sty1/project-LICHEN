/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file link_nonce.h
 * @brief Shared AES-CCM nonce construction for TX/RX paths
 *
 * Internal header - not part of public API.
 */

#ifndef LICHEN_LINK_NONCE_H_
#define LICHEN_LINK_NONCE_H_

#include <lichen/link_ctx.h>
#include "oscore/aes_ccm.h"
#include <string.h>

/**
 * @brief Build AES-CCM nonce for link-layer MIC.
 *
 * Nonce format (13 bytes):
 *   - eui64[8]: sender's EUI-64
 *   - epoch[1]: current epoch
 *   - seqnum[2]: sequence number (big-endian)
 *   - reserved[2]: 0x00 padding
 */
static inline void build_link_nonce(uint8_t nonce[AES_CCM_NONCE_LEN],
				    const uint8_t eui64[LICHEN_EUI64_LEN],
				    uint8_t epoch,
				    uint16_t seqnum)
{
	memcpy(&nonce[0], eui64, LICHEN_EUI64_LEN);
	nonce[8] = epoch;
	nonce[9] = (uint8_t)(seqnum >> 8);
	nonce[10] = (uint8_t)(seqnum & 0xFF);
	nonce[11] = 0x00;
	nonce[12] = 0x00;
}

#endif /* LICHEN_LINK_NONCE_H_ */
