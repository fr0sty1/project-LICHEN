/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>

#include "short_addr.h"
#include "vectors.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void assert_vector(const struct short_addr_iid_vector *vector)
{
	uint8_t iid[LICHEN_SHORT_ADDR_IID_LEN];
	uint16_t decoded = 0;

	zassert_equal(lichen_short_addr_to_iid(vector->short_addr, iid), 0,
		      "short address mapping failed");
	zassert_mem_equal(iid, vector->iid, sizeof(iid), "IID bytes differ");
	zassert_equal(lichen_short_addr_from_iid(iid, &decoded), 0,
		      "IID reverse mapping failed");
	zassert_equal(decoded, vector->short_addr, "short address differs");
	zassert_equal(lichen_short_addr_is_reserved(decoded), vector->reserved,
		      "reserved classification differs");
}

ZTEST(short_addr_iid, test_canonical_python_rust_vectors)
{
	for (size_t i = 0;
	     i < ARRAY_SIZE(canonical_short_addr_iid_vectors); i++) {
		assert_vector(&canonical_short_addr_iid_vectors[i]);
	}
}

ZTEST(short_addr_iid, test_boundaries_and_reserved_values)
{
	for (size_t i = 0;
	     i < ARRAY_SIZE(boundary_short_addr_iid_vectors); i++) {
		assert_vector(&boundary_short_addr_iid_vectors[i]);
	}
}

ZTEST(short_addr_iid, test_reverse_rejects_noncanonical_without_mutation)
{
	static const uint8_t malformed_iid[LICHEN_SHORT_ADDR_IID_LEN] = {
		0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x12, 0x34,
	};
	uint16_t short_addr = 0xa5a5;

	zassert_equal(lichen_short_addr_from_iid(malformed_iid, &short_addr),
		      -EINVAL, "non-canonical prefix accepted");
	zassert_equal(short_addr, 0xa5a5, "failure mutated output");
}

ZTEST(short_addr_iid, test_null_outputs_are_rejected)
{
	static const uint8_t iid[LICHEN_SHORT_ADDR_IID_LEN] = {
		0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x12, 0x34,
	};
	uint16_t short_addr = 0;

	zassert_equal(lichen_short_addr_to_iid(0x1234, NULL), -EINVAL,
		      "NULL IID accepted");
	zassert_equal(lichen_short_addr_from_iid(NULL, &short_addr), -EINVAL,
		      "NULL IID accepted");
	zassert_equal(lichen_short_addr_from_iid(iid, NULL), -EINVAL,
		      "NULL short output accepted");
}

ZTEST_SUITE(short_addr_iid, NULL, NULL, NULL, NULL, NULL);
