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

	/* SECURITY: Reject compressed or padded SRHs.  This profile supports
	 * full 16-byte addresses only, so CmprI, CmprE, and Pad must be zero.
	 * RFC 6554 Section 3 requires receivers to ignore the low reserved nibble
	 * of data[3] and both reserved octets data[4..6]. */
	if (data[2] != 0 || (data[3] & 0xf0u) != 0) {
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

static bool srh_addr_is_multicast(const uint8_t addr[16])
{
	return addr[0] == 0xffu;
}

int lichen_rpl_srh_advance(struct lichen_rpl_srh *srh,
			   const uint8_t *source_addr,
			   uint8_t *destination,
			   uint8_t *hop_limit,
			   uint8_t *next_hop)
{
	uint8_t current_destination[16];
	uint8_t selected_next_hop[16];
	size_t next_index;

	if (srh == NULL || source_addr == NULL || destination == NULL ||
	    hop_limit == NULL || next_hop == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (srh->num_addresses > LICHEN_RPL_MAX_HOPS ||
	    srh->segments_left > srh->num_addresses || *hop_limit == 0) {
		return LICHEN_RPL_ERR_BAD_RT;
	}
	if (srh_addr_is_multicast(source_addr) ||
	    srh_addr_is_multicast(destination) ||
	    rpl_addr_eq(source_addr, destination)) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	/* Validate every address before mutation.  Already-visited entries hold
	 * prior IPv6 Destinations because RFC 6554 swaps each consumed segment. */
	for (size_t i = 0; i < srh->num_addresses; i++) {
		const uint8_t *addr = srh->addresses[i];

		if (srh_addr_is_multicast(addr) || rpl_addr_eq(addr, source_addr) ||
		    rpl_addr_eq(addr, destination)) {
			return LICHEN_RPL_ERR_BAD_RT;
		}
		for (size_t j = 0; j < i; j++) {
			if (rpl_addr_eq(addr, srh->addresses[j])) {
				return LICHEN_RPL_ERR_BAD_RT;
			}
		}
	}

	if (srh->segments_left == 0) {
		return LICHEN_RPL_SRH_COMPLETE;
	}
	/* LICHEN's profile requires enough Hop Limit for all remaining segments.
	 * This also prevents decrementing a forwarding packet to zero. */
	if (srh->segments_left >= *hop_limit) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	next_index = (size_t)srh->num_addresses - srh->segments_left;
	memcpy(current_destination, destination, sizeof(current_destination));
	memcpy(selected_next_hop, srh->addresses[next_index],
	       sizeof(selected_next_hop));

	/* Commit only after all validation and copies have succeeded. */
	memcpy(srh->addresses[next_index], current_destination,
	       sizeof(current_destination));
	memcpy(destination, selected_next_hop, sizeof(selected_next_hop));
	*hop_limit = (uint8_t)(*hop_limit - 1u);
	srh->segments_left--;
	memcpy(next_hop, selected_next_hop, sizeof(selected_next_hop));
	return LICHEN_RPL_SRH_FORWARD;
}
