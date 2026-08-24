/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file stub/lichen/routing/gradient.h
 * @brief Minimal gradient stub for native LOADng tests.
 */

#ifndef LICHEN_ROUTING_GRADIENT_STUB_H_
#define LICHEN_ROUTING_GRADIENT_STUB_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal gradient entry for intermediate reply feature. */
struct lichen_gradient_entry {
	uint8_t destination_iid[8];
	uint8_t next_hop[16];
	uint8_t hop_count;
	uint16_t seq_num;
	uint32_t expires_ms;
	bool valid;
};

/* Gradient table (opaque). */
struct lichen_gradient_table {
	struct lichen_gradient_entry entries[1];
	size_t count;
};

/* Stub: always returns NULL (no gradient). */
static inline struct lichen_gradient_entry *lichen_gradient_lookup(
	struct lichen_gradient_table *table,
	const uint8_t destination_iid[8],
	uint32_t now_ms)
{
	(void)table;
	(void)destination_iid;
	(void)now_ms;
	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_GRADIENT_STUB_H_ */
