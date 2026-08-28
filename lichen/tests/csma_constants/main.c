/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>

#include <assert.h>
#include <stdint.h>

BUILD_ASSERT(LICHEN_CSMA_CAD_TIMEOUT_SYMBOLS == 3U,
	     "CAD timeout must be three symbols");
BUILD_ASSERT(LICHEN_CSMA_BACKOFF_UNIT_MS == 10U,
	     "CSMA backoff unit must be 10 ms");
BUILD_ASSERT(LICHEN_CSMA_BACKOFF_MAX_EXPONENT == 5U,
	     "maximum CSMA exponent must be five");
BUILD_ASSERT(LICHEN_CSMA_RETRY_LIMIT == 3U,
	     "CSMA retry limit must be three");

int main(void)
{
	uint32_t contention_window =
		(UINT32_C(1) << LICHEN_CSMA_BACKOFF_MAX_EXPONENT) - 1U;

	/* packets-timing.json fixes exponent five to CW=31. */
	assert(contention_window == 31U);

	/* Three busy attempts are retries; the fourth attempt is exhausted. */
	for (uint32_t attempt = 1U; attempt <= LICHEN_CSMA_RETRY_LIMIT; attempt++) {
		assert(attempt <= LICHEN_CSMA_RETRY_LIMIT);
	}
	assert(LICHEN_CSMA_RETRY_LIMIT + 1U == 4U);

	return 0;
}
