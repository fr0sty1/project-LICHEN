/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_srh.c
 * @brief RFC 6554 Source Routing Header encode/decode
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>

/* Ensure LICHEN_RPL_MAX_HOPS fits in uint8_t (used for num_addresses field) */
_Static_assert(LICHEN_RPL_MAX_HOPS <= 255,
	       "LICHEN_RPL_MAX_HOPS exceeds uint8_t range");

int lichen_rpl_srh_write(const struct lichen_rpl_srh *srh,
			 uint8_t *buf, size_t len)
{
	if (srh == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (srh->num_addresses > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* segments_left must not exceed num_addresses */
	if (srh->segments_left > srh->num_addresses) {
		return LICHEN_RPL_ERR_INVALID;
	}
	size_t needed = 6 + (size_t)srh->num_addresses * 16;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = 3;  /* routing type */
	buf[1] = srh->segments_left;
	buf[2] = 0;  /* CmprI */
	buf[3] = 0;  /* CmprE */
	buf[4] = 0;  /* reserved */
	buf[5] = 0;

	for (int i = 0; i < srh->num_addresses; i++) {
		memcpy(&buf[6 + i * 16], srh->addresses[i], 16);
	}

	return (int)needed;
}

int lichen_rpl_srh_parse(struct lichen_rpl_srh *srh,
			 const uint8_t *data, size_t len)
{
	if (srh == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 6) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	if (data[0] != 3) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	/* SECURITY: Reject compressed SRHs (CmprI/CmprE > 0 per RFC 6554 Section 3).
	 * We only support uncompressed addresses (16 bytes each). Compressed SRHs
	 * would be parsed incorrectly, leading to misrouted packets. */
	if (data[2] != 0 || data[3] != 0) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	size_t addr_bytes = len - 6;
	if (addr_bytes % 16 != 0) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	size_t num_addrs = addr_bytes / 16;
	if (num_addrs > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_OVERRUN;
	}

	uint8_t segments_left = data[1];

	/* segments_left must not exceed num_addresses */
	if (segments_left > num_addrs) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	srh->segments_left = segments_left;
	srh->num_addresses = (uint8_t)num_addrs;

	for (size_t i = 0; i < num_addrs; i++) {
		memcpy(srh->addresses[i], &data[6 + i * 16], 16);
	}

	return LICHEN_RPL_OK;
}

int lichen_rpl_srh_check_nonstoring(const struct lichen_rpl_srh *srh,
				    const uint8_t *node_addr)
{
	if (srh == NULL || node_addr == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (srh->num_addresses == 0) {
		return LICHEN_RPL_ERR_BAD_RT;
	}
	if (memcmp(srh->addresses[0], node_addr, 16) == 0) {
		return LICHEN_RPL_ERR_BAD_RT;
	}
	return LICHEN_RPL_OK;
}
