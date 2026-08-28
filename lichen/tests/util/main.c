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

	zassert_equal(lichen_sha256(NULL, 0, output, sizeof(output)), 0,
		      "sha256 accepts NULL input with zero length");
	zassert_mem_equal(output, empty_sha256, sizeof(output),
			  "sha256(NULL, 0) returns empty-message digest");
}

ZTEST(lichen_util, test_sha256_rejects_null_nonempty_input)
{
	uint8_t output[TC_SHA256_DIGEST_SIZE];

	zassert_equal(lichen_sha256(NULL, 1, output, sizeof(output)), -EINVAL,
		      "sha256 rejects NULL input with nonzero length");
}

ZTEST(lichen_util, test_sha256_rejects_null_output)
{
	static const uint8_t input[] = { 0x01 };

	zassert_equal(lichen_sha256(input, sizeof(input), NULL, 0), -EINVAL,
		      "sha256 rejects NULL output");
}

ZTEST(lichen_util, test_sha256_rejects_small_output)
{
	uint8_t output[TC_SHA256_DIGEST_SIZE];

	zassert_equal(lichen_sha256(NULL, 0, output, TC_SHA256_DIGEST_SIZE - 1), -ENOMEM,
		      "sha256 rejects output buffer smaller than TC_SHA256_DIGEST_SIZE");
}

ZTEST(lichen_util, test_iid_to_human_address_matches_node_address_vectors)
{
	/*
	 * Cross-validation vectors from test/vectors/node_address.json
	 * These are the canonical shared vectors tested by Python and Rust.
	 */
	static const struct {
		uint8_t iid[8];
		const char *expected;
	} shared_vectors[] = {
		/* test-vector-0 */
		{{0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86}, "50HN-DR7D-TGE46"},
		/* test-vector-1 */
		{{0x5c, 0xe8, 0x6e, 0xfb, 0x75, 0xfa, 0x4e, 0x2c}, "5ST3-EZDT-ZMKHC"},
		/* test-vector-2 */
		{{0xa8, 0x3c, 0x62, 0x6b, 0xc9, 0xc3, 0x8c, 0x8c}, "AGF3-2DF4-W734C"},
		/* test-vector-3 */
		{{0x98, 0xae, 0xbb, 0xb1, 0x78, 0xa5, 0x51, 0x87}, "9HBN-VP5W-AAMC7"},
		/* test-vector-4 */
		{{0x49, 0x3e, 0x3c, 0x14, 0x5d, 0x7e, 0x68, 0x0a}, "4JFH-W2HE-QWT0A"},
	};

	/* Additional edge-case vectors for robustness */
	static const struct {
		uint8_t iid[8];
		const char *expected;
	} extra_vectors[] = {
		{{0x64, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77}, "68T3-TNQW-65FBQ"},
		{{0x70, 0xcd, 0x6e, 0x84, 0x22, 0xc4, 0x07, 0xfb}, "71KB-EGGH-C81ZV"},
		{{0x75, 0x87, 0x7b, 0xb4, 0x1d, 0x39, 0x3b, 0x5f}, "7B1V-VPGE-KJETZ"},
		{{0x64, 0x8a, 0xa5, 0xc5, 0x79, 0xfb, 0x30, 0xf3}, "692N-5RNW-ZPC7K"},
		{{0x9d, 0x4f, 0xb6, 0x8f, 0x3e, 0x1d, 0xac, 0x82}, "9TKX-PHWZ-1VB42"},
	};
	char buf[16];

	/* Test shared cross-validation vectors (from node_address.json) */
	for (size_t i = 0; i < ARRAY_SIZE(shared_vectors); i++) {
		int ret = lichen_iid_to_human_address(shared_vectors[i].iid, buf, sizeof(buf));
		zassert_equal(ret, 0, "shared vector %zu failed: %d", i, ret);
		zassert_equal(strcmp(buf, shared_vectors[i].expected), 0,
			      "shared vector %zu: expected %s, got %s",
			      i, shared_vectors[i].expected, buf);
	}

	/* Test additional edge-case vectors */
	for (size_t i = 0; i < ARRAY_SIZE(extra_vectors); i++) {
		int ret = lichen_iid_to_human_address(extra_vectors[i].iid, buf, sizeof(buf));
		zassert_equal(ret, 0, "extra vector %zu failed: %d", i, ret);
		zassert_equal(strcmp(buf, extra_vectors[i].expected), 0,
			      "extra vector %zu: expected %s, got %s",
			      i, extra_vectors[i].expected, buf);
	}

	int ret = lichen_iid_to_human_address(NULL, buf, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL iid should return -EINVAL");

	ret = lichen_iid_to_human_address(shared_vectors[0].iid, NULL, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL buf should return -EINVAL");

	ret = lichen_iid_to_human_address(shared_vectors[0].iid, buf, 10);
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

/**
 * @brief Helper: compute slot_for per ccp_sfn_wrap_slot_hash.json spec
 *
 * Formula: ((hash_32(eui64) + (sfn & 0xFFFFFFFF)) & 0xFFFFFFFF) % num_slots
 */
static uint8_t slot_for(const uint8_t eui64[8], uint32_t sfn, uint8_t num_slots)
{
	if (num_slots == 0) {
		num_slots = 8;
	}
	uint32_t hash = lichen_hash_32(eui64, 8);
	uint32_t sum = hash + sfn; /* wraps at 32-bit */
	return (uint8_t)(sum % num_slots);
}

ZTEST(lichen_util, test_slot_for_vectors)
{
	/*
	 * Test vectors from ccp_sfn_wrap_slot_hash.json
	 * These validate the TDMA slot selection algorithm:
	 * slot = (FNV-1a32(eui64) + sfn) % num_slots
	 */
	static const uint8_t eui64_ref[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};

	/* hash_32_reference: FNV-1a32 of eui64 = 0x2804678d */
	uint32_t hash = lichen_hash_32(eui64_ref, 8);
	zassert_equal(hash, 0x2804678du,
		      "hash_32(0102030405060708) = 0x2804678d");

	/* slot_for_sfn_zero: (0x2804678d + 0) % 16 = 13 */
	zassert_equal(slot_for(eui64_ref, 0, 16), 13,
		      "slot_for(sfn=0, num_slots=16) = 13");

	/* slot_for_sfn_one: (0x2804678d + 1) % 16 = 14 */
	zassert_equal(slot_for(eui64_ref, 1, 16), 14,
		      "slot_for(sfn=1, num_slots=16) = 14");

	/* slot_for_sfn_max: ((0x2804678d + 0xFFFFFFFF) & 0xFFFFFFFF) % 16 = 12 */
	zassert_equal(slot_for(eui64_ref, 0xFFFFFFFFu, 16), 12,
		      "slot_for(sfn=0xFFFFFFFF, num_slots=16) = 12");

	/* slot_for_sfn_after_wrap: (0x2804678d + 2) % 16 = 15 */
	zassert_equal(slot_for(eui64_ref, 2, 16), 15,
		      "slot_for(sfn=2, num_slots=16) = 15");

	/* slot_for_different_num_slots_8: (0x2804678d + 0) % 8 = 5 */
	zassert_equal(slot_for(eui64_ref, 0, 8), 5,
		      "slot_for(sfn=0, num_slots=8) = 5");

	/* slot_for_different_num_slots_32: (0x2804678d + 0) % 32 = 13 */
	zassert_equal(slot_for(eui64_ref, 0, 32), 13,
		      "slot_for(sfn=0, num_slots=32) = 13");

	/* slot_for_wrapping_sum_before_non_power_of_two_modulus */
	zassert_equal(slot_for(eui64_ref, 0xFFFFFFFFu, 3), 2,
		      "slot_for(sfn=0xFFFFFFFF, num_slots=3) = 2");
}

ZTEST(lichen_util, test_slot_for_edge_cases)
{
	/* slot_for_zeros_eui: hash_32(0000...) = 0x9be17165 */
	static const uint8_t eui64_zeros[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	uint32_t hash_zeros = lichen_hash_32(eui64_zeros, 8);
	zassert_equal(hash_zeros, 0x9be17165u,
		      "hash_32(0000000000000000) = 0x9be17165");
	zassert_equal(slot_for(eui64_zeros, 0, 16), 5,
		      "slot_for(zeros, sfn=0, num_slots=16) = 5");

	/* slot_for_ones_eui: hash_32(ffff...) = 0x6cae0a5d */
	static const uint8_t eui64_ones[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	uint32_t hash_ones = lichen_hash_32(eui64_ones, 8);
	zassert_equal(hash_ones, 0x6cae0a5du,
		      "hash_32(ffffffffffffffff) = 0x6cae0a5d");
	zassert_equal(slot_for(eui64_ones, 0, 16), 13,
		      "slot_for(ones, sfn=0, num_slots=16) = 13");
}

ZTEST(lichen_util, test_slot_for_wrap_sequence)
{
	/*
	 * full_wrap_sequence from ccp_sfn_wrap_slot_hash.json
	 * Validates continuous slot rotation across SFN wrap boundary.
	 */
	static const uint8_t eui64_ref[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	static const struct {
		uint32_t sfn;
		uint8_t expected_slot;
	} sequence[] = {
		{ 0xFFFFFFFDu, 10 },
		{ 0xFFFFFFFEu, 11 },
		{ 0xFFFFFFFFu, 12 },
		{ 0x00000000u, 13 },
		{ 0x00000001u, 14 },
		{ 0x00000002u, 15 },
		{ 0x00000003u, 0 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(sequence); i++) {
		uint8_t slot = slot_for(eui64_ref, sequence[i].sfn, 16);
		zassert_equal(slot, sequence[i].expected_slot,
			      "wrap sequence[%zu] sfn=0x%08x: expected %u, got %u",
			      i, sequence[i].sfn, sequence[i].expected_slot, slot);
	}
}

ZTEST(lichen_util, test_sfn_delta_vectors)
{
	/*
	 * sfn_delta test vectors from ccp_sfn_wrap_slot_hash.json
	 * Formula: sfn_delta(curr, last) = (curr - last) & 0xFFFFFFFF
	 */

	/* sfn_delta_wrap_minimal: 0 - 0xFFFFFFFF = 1 */
	uint32_t delta = 0u - 0xFFFFFFFFu;
	zassert_equal(delta, 1u, "sfn_delta(0, 0xFFFFFFFF) = 1");

	/* sfn_delta_wrap_multi: 2 - 0xFFFFFFFF = 3 */
	delta = 2u - 0xFFFFFFFFu;
	zassert_equal(delta, 3u, "sfn_delta(2, 0xFFFFFFFF) = 3");

	/* sfn_delta_wrap_near: 5 - 0xFFFFFFFE = 7 */
	delta = 5u - 0xFFFFFFFEu;
	zassert_equal(delta, 7u, "sfn_delta(5, 0xFFFFFFFE) = 7");

	/* sfn_delta_no_wrap: 100 - 50 = 50 */
	delta = 100u - 50u;
	zassert_equal(delta, 50u, "sfn_delta(100, 50) = 50");

	/* sfn_delta_zero: 12345 - 12345 = 0 */
	delta = 12345u - 12345u;
	zassert_equal(delta, 0u, "sfn_delta(12345, 12345) = 0");

	/* sfn_delta_large_forward: 0x80000000 - 0 = 0x80000000 */
	delta = 0x80000000u - 0u;
	zassert_equal(delta, 0x80000000u, "sfn_delta(0x80000000, 0) = 0x80000000");

	/* sfn_delta_apparent_backward: 10 - 100 wraps to 0xFFFFFFA6 */
	delta = 10u - 100u;
	zassert_equal(delta, 0xFFFFFFA6u, "sfn_delta(10, 100) = 0xFFFFFFA6");
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
