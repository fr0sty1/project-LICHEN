/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file hash32.c
 * @brief LICHEN 32-bit FNV-1a hash
 *
 * Defined in the link module so it is built for every LICHEN_LINK image,
 * independent of CONFIG_LICHEN_IPV6 (whose l2/lichen_util.c was the only
 * other definition). Declared by <lichen/link.h> and l2/lichen_util.h.
 *
 * The prototype is repeated locally instead of including <lichen/link.h>:
 * that header's transitive includes (replay.h) require CONFIG_LICHEN_LINK
 * Kconfig symbols, which are absent in Zephyr apps that compile this file
 * directly without the module enabled (e.g. tests/util). Same pattern as
 * link_load_balance.c.
 */

#include <stddef.h>
#include <stdint.h>

uint32_t lichen_hash_32(const uint8_t *data, size_t len);

uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
	uint32_t hash = 0x811c9dc5u;
	for (size_t i = 0; i < len; i++) {
		hash ^= (uint32_t)data[i];
		hash = hash * 0x01000193u;
	}
	return hash;
}
