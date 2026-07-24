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

ZTEST(lichen_util, test_iid_to_human_address_matches_node_address_vectors)
{
	static const struct {
		uint8_t iid[8];
		const char *expected;
	} vectors[] = {
		{{0x64, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77}, "68T3-TNQW-65FBQ"},
		{{0x70, 0xcd, 0x6e, 0x84, 0x22, 0xc4, 0x07, 0xfb}, "71KB-EGGH-C81ZV"},
		{{0x75, 0x87, 0x7b, 0xb4, 0x1d, 0x39, 0x3b, 0x5f}, "7B1V-VPGE-KJETZ"},
		{{0x64, 0x8a, 0xa5, 0xc5, 0x79, 0xfb, 0x30, 0xf3}, "692N-5RNW-ZPC7K"},
		{{0x9d, 0x4f, 0xb6, 0x8f, 0x3e, 0x1d, 0xac, 0x82}, "9TKX-PHWZ-1VB42"},
		{{0xf8, 0x49, 0xd6, 0x73, 0x25, 0xfa, 0xcf, 0x04}, "FGJE-PECJ-ZNKR4"},
		{{0xe8, 0x02, 0x08, 0x6a, 0xd6, 0xa1, 0xe1, 0x6b}, "EG0G-8DBB-A3RBB"},
		{{0x49, 0xb0, 0x6f, 0x8e, 0x4e, 0x3a, 0x77, 0x15}, "4KC3-FHS7-3MXRN"},
		{{0x25, 0x78, 0xcc, 0xf8, 0x64, 0x5b, 0x2d, 0x1d}, "2AY6-CZ1J-5PB8X"},
		{{0x8c, 0x0c, 0xc1, 0x7a, 0x04, 0x94, 0x2c, 0xc4}, "8R36-1F82-98B64"},
	};
	char buf[16];

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		int ret = lichen_iid_to_human_address(vectors[i].iid, buf, sizeof(buf));
		zassert_equal(ret, 0, "vector %zu failed: %d", i, ret);
		zassert_equal(strcmp(buf, vectors[i].expected), 0,
			      "vector %zu: expected %s, got %s", i, vectors[i].expected, buf);
	}

	int ret = lichen_iid_to_human_address(NULL, buf, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL iid should return -EINVAL");

	ret = lichen_iid_to_human_address(vectors[0].iid, NULL, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL buf should return -EINVAL");

	ret = lichen_iid_to_human_address(vectors[0].iid, buf, 10);
	zassert_equal(ret, -EINVAL, "small buffer should return -EINVAL");
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
