/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_prefix.c
 * @brief IPv6 prefix manipulation helpers
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <lichen/rpl_routing.h>

bool lichen_rpl_prefix_canonicalize(uint8_t *prefix, uint8_t prefix_len)
{
	if (prefix_len > 128) {
		return false;
	}
	uint8_t whole_bytes = prefix_len / 8;
	uint8_t remaining_bits = prefix_len % 8;
	uint8_t used_bytes = whole_bytes + (remaining_bits != 0 ? 1 : 0);
	if (remaining_bits != 0) {
		prefix[whole_bytes] &= (uint8_t)(0xffU << (8 - remaining_bits));
	}
	memset(&prefix[used_bytes], 0, 16 - used_bytes);
	return true;
}

bool lichen_rpl_prefix_contains(const uint8_t *prefix, uint8_t prefix_len,
				const uint8_t *address)
{
	uint8_t whole_bytes = prefix_len / 8;
	if (memcmp(prefix, address, whole_bytes) != 0) {
		return false;
	}
	uint8_t remaining_bits = prefix_len % 8;
	if (remaining_bits == 0) {
		return true;
	}
	uint8_t mask = (uint8_t)(0xffU << (8 - remaining_bits));
	return ((prefix[whole_bytes] ^ address[whole_bytes]) & mask) == 0;
}
