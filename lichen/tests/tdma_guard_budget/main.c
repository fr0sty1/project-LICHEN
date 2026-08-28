/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* tdma.c also contains slot selection; the guard-budget test does not depend
 * on a particular hash result, but the translation unit requires the symbol. */
uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
	(void)data;
	(void)len;
	return 0U;
}

int main(void)
{
	/* Canonical ccp7_holdover.json cases, in milliseconds. */
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 5U, 5U,
						   5U, 5U));
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 10U, 10U,
						   5U, 5U));
	assert(!lichen_tdma_guard_budget_sufficient(50U, 20U, 20U, 5U, 5U,
						    5U, 5U));

	/* The mandatory 50 ms SF10 guard covers the canonical target budget. */
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 10U, 10U,
						   5U, 5U));
	assert(!lichen_tdma_guard_budget_sufficient(49U, 10U, 10U, 10U, 10U,
						    5U, 5U));

	/* Equality and the all-zero mathematical budget are valid. */
	assert(lichen_tdma_guard_budget_sufficient(1U, 1U, 0U, 0U, 0U,
						   0U, 0U));
	assert(lichen_tdma_guard_budget_sufficient(0U, 0U, 0U, 0U, 0U,
						   0U, 0U));

	/* Overflow must never wrap the required budget into an approval. */
	assert(!lichen_tdma_guard_budget_sufficient(UINT64_MAX, UINT64_MAX, 1U,
						    0U, 0U, 0U, 0U));
	assert(!lichen_tdma_guard_budget_sufficient(UINT64_MAX, UINT64_MAX - 4U,
						    1U, 1U, 1U, 1U, 1U));

	return 0;
}
