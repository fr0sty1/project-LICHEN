/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN utility tests
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "lichen_util.h"

ZTEST(lichen_util, test_sha256_accepts_null_empty_input)
{
	static const uint8_t empty_sha256[TC_SHA256_DIGEST_SIZE] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	};
	uint8_t output[TC_SHA256_DIGEST_SIZE];

	memset(output, 0xa5, sizeof(output));

	zassert_equal(lichen_sha256(NULL, 0, output), 0,
		      "sha256 accepts NULL input with zero length");
	zassert_mem_equal(output, empty_sha256, sizeof(output),
			  "sha256(NULL, 0) returns empty-message digest");
}

ZTEST(lichen_util, test_sha256_rejects_null_nonempty_input)
{
	uint8_t output[TC_SHA256_DIGEST_SIZE];

	zassert_equal(lichen_sha256(NULL, 1, output), -EINVAL,
		      "sha256 rejects NULL input with nonzero length");
}

ZTEST(lichen_util, test_sha256_rejects_null_output)
{
	static const uint8_t input[] = { 0x01 };

	zassert_equal(lichen_sha256(input, sizeof(input), NULL), -EINVAL,
		      "sha256 rejects NULL output");
}

ZTEST(lichen_util, test_lichen_hash_32)
{
	static const uint8_t test_data[] = { 't', 'e', 's', 't' };
	static const uint8_t zeros[32] = { 0 };

	zassert_equal(lichen_hash_32(NULL, 0), 0x811c9dc5u, "");
	zassert_equal(lichen_hash_32(test_data, 4), 0xafd071e5u, "");
	zassert_equal(lichen_hash_32(zeros, 32), 0x0b2ae445u, "");
}

ZTEST_SUITE(lichen_util, NULL, NULL, NULL, NULL, NULL);
