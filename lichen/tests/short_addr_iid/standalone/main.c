/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "short_addr.h"
#include "vectors.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void check_vector(const struct short_addr_iid_vector *vector)
{
	uint8_t iid[LICHEN_SHORT_ADDR_IID_LEN];
	uint16_t decoded = 0;

	assert(lichen_short_addr_to_iid(vector->short_addr, iid) == 0);
	assert(memcmp(iid, vector->iid, sizeof(iid)) == 0);
	assert(lichen_short_addr_from_iid(iid, &decoded) == 0);
	assert(decoded == vector->short_addr);
	assert(lichen_short_addr_is_reserved(decoded) == vector->reserved);
}

int main(void)
{
	static const uint8_t malformed_iid[LICHEN_SHORT_ADDR_IID_LEN] = {
		0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x12, 0x34,
	};
	uint16_t unchanged = 0xa5a5;

	for (size_t i = 0; i < sizeof(canonical_short_addr_iid_vectors) /
				       sizeof(canonical_short_addr_iid_vectors[0]); i++) {
		check_vector(&canonical_short_addr_iid_vectors[i]);
	}
	for (size_t i = 0; i < sizeof(boundary_short_addr_iid_vectors) /
				       sizeof(boundary_short_addr_iid_vectors[0]); i++) {
		check_vector(&boundary_short_addr_iid_vectors[i]);
	}

	assert(lichen_short_addr_to_iid(0x1234, NULL) == -EINVAL);
	assert(lichen_short_addr_from_iid(NULL, &unchanged) == -EINVAL);
	assert(lichen_short_addr_from_iid(malformed_iid, NULL) == -EINVAL);
	assert(lichen_short_addr_from_iid(malformed_iid, &unchanged) == -EINVAL);
	assert(unchanged == 0xa5a5);
	return 0;
}
