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

ZTEST(lichen_util, test_hash_32_sfn_wrap)
{
	static const uint8_t eui64[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	};
	static const uint8_t eui64_2[] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11
	};
	uint8_t buf[12];
	uint32_t sfn;
	uint32_t h;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, eui64, 8);

	sfn = 0xFFFFFFFFu;
	buf[8] = (uint8_t)(sfn);
	buf[9] = (uint8_t)(sfn >> 8);
	buf[10] = (uint8_t)(sfn >> 16);
	buf[11] = (uint8_t)(sfn >> 24);
	h = lichen_hash_32(buf, 12);
	zassert_equal(h, 0x211a6929u,
		      "hash_32(EUI64=0011223344556677, SFN=0xFFFFFFFF)");

	sfn = 0x00000000u;
	buf[8] = (uint8_t)(sfn);
	buf[9] = (uint8_t)(sfn >> 8);
	buf[10] = (uint8_t)(sfn >> 16);
	buf[11] = (uint8_t)(sfn >> 24);
	h = lichen_hash_32(buf, 12);
	zassert_equal(h, 0x87645a8du,
		      "hash_32(EUI64=0011223344556677, SFN=0x00000000)");

	memcpy(buf, eui64_2, 8);
	sfn = 0xFFFFFFFFu;
	buf[8] = (uint8_t)(sfn);
	buf[9] = (uint8_t)(sfn >> 8);
	buf[10] = (uint8_t)(sfn >> 16);
	buf[11] = (uint8_t)(sfn >> 24);
	h = lichen_hash_32(buf, 12);
	zassert_equal(h, 0x7217ad29u,
		      "hash_32(EUI64=aabbccddeeff0011, SFN=0xFFFFFFFF)");

	sfn = 0x00000000u;
	buf[8] = (uint8_t)(sfn);
	buf[9] = (uint8_t)(sfn >> 8);
	buf[10] = (uint8_t)(sfn >> 16);
	buf[11] = (uint8_t)(sfn >> 24);
	h = lichen_hash_32(buf, 12);
	zassert_equal(h, 0xd8619e8du,
		      "hash_32(EUI64=aabbccddeeff0011, SFN=0x00000000)");
}

ZTEST(lichen_util, test_hash_32_delta_wrap)
{
	uint32_t last_sfn = 0xFFFFFFFFu;
	uint32_t current_sfn = 0x00000002u;
	uint32_t delta = current_sfn - last_sfn;

	zassert_equal(delta, 3u,
		      "SFN delta 0x00000002 - 0xFFFFFFFF = 3 (unsigned wrap)");
}

ZTEST_SUITE(lichen_util, NULL, NULL, NULL, NULL, NULL);
