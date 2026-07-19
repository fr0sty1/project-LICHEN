/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <schc/bitstream.h>
#include <schc/schc.h>

#include "schc_fragmentation_vectors.h"

#define TEST_RULE_ID 0x2a
#define TEST_UNCOMPRESSED_RULE_ID 0xff

ZTEST(schc_generic, test_shared_fragmentation_vector_fixture)
{
	zassert_equal(ARRAY_SIZE(schc_fragment_scenarios),
		      SCHC_FRAGMENT_VECTOR_SOURCE_COUNT);
	zassert_equal(ARRAY_SIZE(schc_fragment_byte_vectors),
		      SCHC_FRAGMENT_BYTE_VECTOR_COUNT);
	zassert_equal(ARRAY_SIZE(schc_fragment_fragments),
		      SCHC_FRAGMENT_FRAGMENT_VECTOR_COUNT);
	zassert_true(SCHC_FRAGMENT_VECTOR_SOURCE_COUNT >= 12U);
	zassert_true(SCHC_FRAGMENT_BYTE_VECTOR_COUNT >= 20U);

	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_byte_vectors); i++) {
		zassert_not_null(schc_fragment_byte_vectors[i].scenario);
		zassert_not_null(schc_fragment_byte_vectors[i].field);
		zassert_not_null(schc_fragment_byte_vectors[i].data);
		zassert_true(schc_fragment_byte_vectors[i].len > 0U);
	}

	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_fragments); i++) {
		zassert_not_null(schc_fragment_fragments[i].scenario);
		zassert_not_null(schc_fragment_fragments[i].name);
		zassert_not_null(schc_fragment_fragments[i].kind);
		zassert_not_null(schc_fragment_fragments[i].wire);
		zassert_true(schc_fragment_fragments[i].wire_len > 0U);
	}

	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_scenarios); i++) {
		zassert_not_null(schc_fragment_scenarios[i].name);
		zassert_not_null(schc_fragment_scenarios[i].category);
		zassert_not_null(schc_fragment_scenarios[i].provenance);
	}
}

static int test_rule_compress(const struct schc_rule *rule,
			      const uint8_t *packet, size_t packet_len,
			      uint8_t *out, size_t out_len)
{
	if (packet_len == 0 || packet[0] != 0xa5) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	if (out_len < packet_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	out[0] = rule->rule_id;
	for (size_t i = 1; i < packet_len; i++) {
		out[i] = packet[i] ^ 0xff;
	}

	return (int)packet_len;
}

static int test_rule_decompress(const struct schc_rule *rule,
				const uint8_t *data, size_t data_len,
				uint8_t *out, size_t out_len)
{
	if (data_len == 0 || data[0] != rule->rule_id) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}

	if (out_len < data_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	out[0] = 0xa5;
	for (size_t i = 1; i < data_len; i++) {
		out[i] = data[i] ^ 0xff;
	}

	return (int)data_len;
}

static const struct schc_rule test_rules[] = {
	{
		.rule_id = TEST_RULE_ID,
		.compress = test_rule_compress,
		.decompress = test_rule_decompress,
	},
};

static const struct schc_profile test_profile = {
	.rules = test_rules,
	.rule_count = ARRAY_SIZE(test_rules),
	.uncompressed_rule_id = TEST_UNCOMPRESSED_RULE_ID,
	.use_uncompressed_fallback = true,
};

ZTEST(schc_generic, test_profile_rule_round_trip)
{
	const uint8_t packet[] = { 0xa5, 0x00, 0x55, 0xff };
	uint8_t compressed[sizeof(packet)];
	uint8_t decompressed[sizeof(packet)];

	int ret = schc_compress(&test_profile, packet, sizeof(packet),
				compressed, sizeof(compressed));
	zassert_equal(ret, sizeof(packet));
	zassert_equal(compressed[0], TEST_RULE_ID);
	zassert_equal(compressed[1], 0xff);
	zassert_equal(compressed[2], 0xaa);
	zassert_equal(compressed[3], 0x00);

	ret = schc_decompress(&test_profile, compressed, sizeof(compressed),
			      decompressed, sizeof(decompressed));
	zassert_equal(ret, sizeof(packet));
	zassert_mem_equal(decompressed, packet, sizeof(packet));
}

ZTEST(schc_generic, test_uncompressed_fallback)
{
	const uint8_t packet[] = { 0x01, 0x02, 0x03 };
	uint8_t compressed[sizeof(packet) + 1];
	uint8_t decompressed[sizeof(packet)];

	int ret = schc_compress(&test_profile, packet, sizeof(packet),
				compressed, sizeof(compressed));
	zassert_equal(ret, sizeof(compressed));
	zassert_equal(compressed[0], TEST_UNCOMPRESSED_RULE_ID);
	zassert_mem_equal(&compressed[1], packet, sizeof(packet));

	ret = schc_decompress(&test_profile, compressed, sizeof(compressed),
			      decompressed, sizeof(decompressed));
	zassert_equal(ret, sizeof(packet));
	zassert_mem_equal(decompressed, packet, sizeof(packet));
}

ZTEST(schc_generic, test_uncompressed_fallback_without_rules)
{
	const struct schc_profile passthrough_profile = {
		.rules = NULL,
		.rule_count = 0,
		.uncompressed_rule_id = TEST_UNCOMPRESSED_RULE_ID,
		.use_uncompressed_fallback = true,
	};
	const uint8_t packet[] = { 0x04, 0x05 };
	uint8_t compressed[sizeof(packet) + 1];

	int ret = schc_compress(&passthrough_profile, packet, sizeof(packet),
				compressed, sizeof(compressed));
	zassert_equal(ret, sizeof(compressed));
	zassert_equal(compressed[0], TEST_UNCOMPRESSED_RULE_ID);
	zassert_mem_equal(&compressed[1], packet, sizeof(packet));
}

ZTEST(schc_generic, test_fragmenter_emits_tiles_and_all_1)
{
	const uint8_t packet[] = {
		0x10, 0x11, 0x12, 0x13,
		0x20, 0x21, 0x22, 0x23,
		0x30, 0x31,
	};
	struct schc_fragmenter fragmenter;
	struct schc_fragmenter_config config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 6,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_NO_ACK,
	};
	uint8_t out[8];

	zassert_equal(schc_fragmenter_init(&fragmenter, &config,
					   packet, sizeof(packet)),
		      SCHC_OK);

	int ret = schc_fragmenter_next(&fragmenter, out, sizeof(out));
	zassert_equal(ret, 6);
	zassert_equal(out[0], TEST_RULE_ID);
	zassert_equal(out[1], 0x06);
	zassert_mem_equal(&out[2], &packet[0], 4);

	ret = schc_fragmenter_next(&fragmenter, out, sizeof(out));
	zassert_equal(ret, 6);
	zassert_equal(out[0], TEST_RULE_ID);
	zassert_equal(out[1], 0x05);
	zassert_mem_equal(&out[2], &packet[4], 4);

	ret = schc_fragmenter_next(&fragmenter, out, sizeof(out));
	zassert_equal(ret, 4);
	zassert_equal(out[0], TEST_RULE_ID);
	zassert_equal(out[1], 0x07);
	zassert_mem_equal(&out[2], &packet[8], 2);

	zassert_equal(schc_fragmenter_next(&fragmenter, out, sizeof(out)),
		      SCHC_ERR_DONE);
}

ZTEST(schc_generic, test_fragmenter_rolls_windows)
{
	const uint8_t packet[] = {
		0x00, 0x01, 0x02,
		0x03, 0x04, 0x05,
		0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e,
		0x0f, 0x10,
	};
	struct schc_fragmenter fragmenter;
	struct schc_fragmenter_config config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 2,
		.tile_size = 3,
		.mtu = 5,
		.direction = SCHC_FRAGMENT_DOWNLINK,
		.mode = SCHC_FRAGMENT_NO_ACK,
	};
	uint8_t out[5];
	const uint8_t expected_control[] = {
		0x02, 0x01, 0x00, 0x06, 0x05, 0x07,
	};

	zassert_equal(schc_fragmenter_init(&fragmenter, &config,
					   packet, sizeof(packet)),
		      SCHC_OK);

	for (size_t i = 0; i < ARRAY_SIZE(expected_control); i++) {
		int ret = schc_fragmenter_next(&fragmenter, out, sizeof(out));

		zassert_true(ret > 0);
		zassert_equal(out[0], TEST_RULE_ID);
		zassert_equal(out[1], expected_control[i]);
	}
	zassert_equal(schc_fragmenter_next(&fragmenter, out, sizeof(out)),
		      SCHC_ERR_DONE);
}

ZTEST(schc_generic, test_fragmenter_rejects_too_small_mtu_or_output)
{
	const uint8_t packet[] = { 0x01, 0x02, 0x03 };
	struct schc_fragmenter fragmenter;
	struct schc_fragmenter_config config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 2,
		.mtu = 3,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	uint8_t out[3];

	zassert_equal(schc_fragmenter_init(&fragmenter, &config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	zassert_equal(schc_fragmenter_next(&fragmenter, out, sizeof(out)),
		      SCHC_ERR_BUFFER_TOO_SMALL);

	config.mtu = 4;
	zassert_equal(schc_fragmenter_init(&fragmenter, &config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	zassert_equal(schc_fragmenter_next(&fragmenter, out, sizeof(out)),
		      SCHC_ERR_BUFFER_TOO_SMALL);
}

ZTEST(schc_generic, test_fragmenter_emits_dtag_and_ack_mode_mic)
{
	const uint8_t packet[] = { 0x10, 0x11, 0x12 };
	struct schc_fragmenter fragmenter;
	struct schc_fragmenter_config config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 0x01,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 10,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	uint8_t out[10];

	zassert_equal(schc_fragmenter_init(&fragmenter, &config,
					   packet, sizeof(packet)),
		      SCHC_OK);

	int ret = schc_fragmenter_next(&fragmenter, out, sizeof(out));

	zassert_equal(ret, 9);
	zassert_equal(out[0], TEST_RULE_ID);
	zassert_equal(out[1], 0x27);
	zassert_mem_equal(&out[2], packet, sizeof(packet));
	zassert_not_equal(sys_get_be32(&out[5]), 0);
	zassert_equal(schc_fragmenter_next(&fragmenter, out, sizeof(out)),
		      SCHC_ERR_DONE);
}

ZTEST(schc_generic, test_reassembler_round_trips_fragmenter_output)
{
	const uint8_t packet[] = {
		0xa0, 0xa1, 0xa2, 0xa3,
		0xb0, 0xb1, 0xb2, 0xb3,
		0xc0,
	};
	struct schc_fragmenter fragmenter;
	struct schc_reassembler reassembler;
	struct schc_fragmenter_config frag_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 6,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_NO_ACK,
	};
	struct schc_reassembler_config reasm_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
	};
	uint8_t fragment[6];
	uint8_t output[sizeof(packet)];
	bool complete = false;

	zassert_equal(schc_fragmenter_init(&fragmenter, &frag_config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_init(&reassembler, &reasm_config,
					    output, sizeof(output)),
		      SCHC_OK);

	int ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(ret, 6);
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      SCHC_OK);
	zassert_false(complete);

	ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(ret, 6);
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      SCHC_OK);
	zassert_false(complete);

	ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(ret, 3);
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      sizeof(packet));
	zassert_true(complete);
	zassert_mem_equal(output, packet, sizeof(packet));
}

ZTEST(schc_generic, test_ack_mode_reassembler_validates_mic)
{
	const uint8_t packet[] = {
		0xa0, 0xa1, 0xa2, 0xa3,
		0xb0,
	};
	struct schc_fragmenter fragmenter;
	struct schc_reassembler reassembler;
	struct schc_fragmenter_config frag_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 10,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_ACK_ALWAYS,
	};
	struct schc_reassembler_config reasm_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mode = SCHC_FRAGMENT_ACK_ALWAYS,
	};
	uint8_t fragment[10];
	uint8_t correct_all_1[10];
	uint8_t output[sizeof(packet)];
	bool complete = false;

	zassert_equal(schc_fragmenter_init(&fragmenter, &frag_config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_init(&reassembler, &reasm_config,
					    output, sizeof(output)),
		      SCHC_OK);

	int ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(ret, 6);
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      SCHC_OK);
	zassert_false(complete);

	ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(ret, 7);
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      sizeof(packet));
	zassert_true(complete);
	zassert_mem_equal(output, packet, sizeof(packet));

	zassert_equal(schc_reassembler_init(&reassembler, &reasm_config,
					    output, sizeof(output)),
		      SCHC_OK);
	zassert_equal(schc_fragmenter_init(&fragmenter, &frag_config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      SCHC_OK);
	ret = schc_fragmenter_next(&fragmenter, fragment, sizeof(fragment));
	zassert_true(ret > 0);
	memcpy(correct_all_1, fragment, ret);
	fragment[ret - 1] ^= 0x01;
	zassert_equal(schc_reassembler_input(&reassembler, fragment, ret,
					     &complete),
		      SCHC_ERR_MIC_MISMATCH);
	zassert_false(complete);
	zassert_equal(schc_reassembler_input(&reassembler, correct_all_1, ret,
					     &complete),
		      sizeof(packet));
	zassert_true(complete);
	zassert_mem_equal(output, packet, sizeof(packet));
}

ZTEST(schc_generic, test_reassembler_rejects_wrong_rule_and_out_of_order)
{
	struct schc_reassembler reassembler;
	struct schc_reassembler_config config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
	};
	uint8_t output[16];
	bool complete = false;
	const uint8_t wrong_rule[] = { 0x01, 0x06, 0xaa, 0xbb, 0xcc, 0xdd };
	const uint8_t out_of_order[] = { TEST_RULE_ID, 0x05, 0xaa, 0xbb, 0xcc, 0xdd };
	struct schc_ack ack;

	zassert_equal(schc_reassembler_init(&reassembler, &config,
					    output, sizeof(output)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_input(&reassembler, wrong_rule,
					     sizeof(wrong_rule), &complete),
		      SCHC_ERR_UNKNOWN_RULE_ID);
	zassert_equal(schc_reassembler_input(&reassembler, out_of_order,
					     sizeof(out_of_order), &complete),
		      SCHC_OK);
	zassert_false(complete);
	zassert_equal(schc_reassembler_ack(&reassembler, &ack), SCHC_OK);
	zassert_equal(ack.bitmap_bits, 7);
	zassert_equal(ack.bitmap, 0x02);
}

ZTEST(schc_generic, test_reassembler_missing_tile_ack_and_retransmit)
{
	const uint8_t packet[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08,
	};
	struct schc_fragmenter fragmenter;
	struct schc_reassembler reassembler;
	struct schc_fragmenter_config frag_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 10,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	struct schc_reassembler_config reasm_config = {
		.rule_id = TEST_RULE_ID,
		.dtag = 1,
		.dtag_bits = 1,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	uint8_t fragments[3][10];
	int fragment_len[3];
	uint8_t output[sizeof(packet)];
	bool complete = false;
	struct schc_ack ack;
	uint8_t ack_frame[8];
	struct schc_ack decoded;
	uint8_t retransmit[10];

	zassert_equal(schc_fragmenter_init(&fragmenter, &frag_config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	for (size_t i = 0; i < ARRAY_SIZE(fragments); i++) {
		fragment_len[i] = schc_fragmenter_next(&fragmenter, fragments[i],
						       sizeof(fragments[i]));
		zassert_true(fragment_len[i] > 0);
	}

	zassert_equal(schc_reassembler_init(&reassembler, &reasm_config,
					    output, sizeof(output)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_input(&reassembler, fragments[1],
					     fragment_len[1], &complete),
		      SCHC_OK);
	zassert_false(complete);
	zassert_equal(schc_reassembler_ack(&reassembler, &ack), SCHC_OK);
	zassert_equal(ack.bitmap, 0x02);

	int ack_len = schc_ack_encode(&ack, ack_frame, sizeof(ack_frame));
	zassert_equal(ack_len, 4);
	zassert_equal(schc_ack_decode(&decoded, 1, 2, ack.bitmap_bits,
				      ack_frame, ack_len),
		      ack_len);
	zassert_equal(decoded.rule_id, TEST_RULE_ID);
	zassert_equal(decoded.dtag, 1);
	zassert_equal(decoded.dtag_bits, 1);
	zassert_equal(decoded.window, 0);
	zassert_equal(decoded.window_bits, 2);
	zassert_equal(decoded.bitmap, 0x02);

	zassert_equal(schc_fragmenter_retransmit(&fragmenter, &decoded,
						 retransmit, sizeof(retransmit)),
		      fragment_len[0]);
	zassert_mem_equal(retransmit, fragments[0], fragment_len[0]);

	zassert_equal(schc_reassembler_input(&reassembler, retransmit,
					     fragment_len[0], &complete),
		      SCHC_OK);
	zassert_false(complete);
	zassert_equal(schc_reassembler_input(&reassembler, fragments[2],
					     fragment_len[2], &complete),
		      sizeof(packet));
	zassert_true(complete);
	zassert_mem_equal(output, packet, sizeof(packet));
}

ZTEST(schc_generic, test_all_1_does_not_complete_with_missing_prior_tile)
{
	const uint8_t packet[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08,
	};
	struct schc_fragmenter fragmenter;
	struct schc_reassembler reassembler;
	struct schc_fragmenter_config frag_config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mtu = 10,
		.direction = SCHC_FRAGMENT_UPLINK,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	struct schc_reassembler_config reasm_config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};
	uint8_t fragment[3][10];
	int fragment_len[3];
	uint8_t output[sizeof(packet)];
	bool complete = false;

	zassert_equal(schc_fragmenter_init(&fragmenter, &frag_config,
					   packet, sizeof(packet)),
		      SCHC_OK);
	for (size_t i = 0; i < ARRAY_SIZE(fragment); i++) {
		fragment_len[i] = schc_fragmenter_next(&fragmenter, fragment[i],
						       sizeof(fragment[i]));
		zassert_true(fragment_len[i] > 0);
	}

	zassert_equal(schc_reassembler_init(&reassembler, &reasm_config,
					    output, sizeof(output)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_input(&reassembler, fragment[1],
					     fragment_len[1], &complete),
		      SCHC_OK);
	zassert_equal(schc_reassembler_input(&reassembler, fragment[2],
					     fragment_len[2], &complete),
		      SCHC_ERR_NO_MATCHING_RULE);
	zassert_false(complete);
}

ZTEST(schc_generic, test_reassembler_rejects_truncated_and_oversize_tiles)
{
	struct schc_reassembler reassembler;
	struct schc_reassembler_config config = {
		.rule_id = TEST_RULE_ID,
		.window_bits = 2,
		.fcn_bits = 3,
		.tile_size = 4,
	};
	uint8_t output[4];
	bool complete = false;
	const uint8_t too_short[] = { TEST_RULE_ID };
	const uint8_t empty_tile[] = { TEST_RULE_ID, 0x06 };
	const uint8_t too_large[] = {
		TEST_RULE_ID, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04,
	};

	zassert_equal(schc_reassembler_init(&reassembler, &config,
					    output, sizeof(output)),
		      SCHC_OK);
	zassert_equal(schc_reassembler_input(&reassembler, too_short,
					     sizeof(too_short), &complete),
		      SCHC_ERR_TOO_SHORT);
	zassert_equal(schc_reassembler_input(&reassembler, empty_tile,
					     sizeof(empty_tile), &complete),
		      SCHC_ERR_TOO_SHORT);
	zassert_equal(schc_reassembler_input(&reassembler, too_large,
					     sizeof(too_large), &complete),
		      SCHC_ERR_TOO_SHORT);
}

ZTEST(schc_generic, test_bitstream_round_trip_unaligned_fields)
{
	uint8_t buf[4];
	struct schc_bit_writer writer;
	struct schc_bit_reader reader;
	uint64_t value;

	schc_bit_writer_init(&writer, buf, sizeof(buf));
	zassert_ok(schc_bit_writer_write(&writer, 0x5, 3));
	zassert_ok(schc_bit_writer_write(&writer, 0x12, 5));
	zassert_ok(schc_bit_writer_write(&writer, 0xabc, 12));
	zassert_equal(schc_bit_writer_byte_len(&writer), 3);
	zassert_equal(buf[0], 0xb2);
	zassert_equal(buf[1], 0xab);
	zassert_equal(buf[2], 0xc0);

	schc_bit_reader_init(&reader, buf, schc_bit_writer_byte_len(&writer));
	zassert_ok(schc_bit_reader_read(&reader, 3, &value));
	zassert_equal(value, 0x5);
	zassert_ok(schc_bit_reader_read(&reader, 5, &value));
	zassert_equal(value, 0x12);
	zassert_ok(schc_bit_reader_read(&reader, 12, &value));
	zassert_equal(value, 0xabc);
	zassert_equal(schc_bit_reader_residue_byte_end(&reader), 3);
}

ZTEST(schc_generic, test_bitstream_write128_and_read_bytes)
{
	const uint8_t input[16] = {
		0x12, 0x34, 0x56, 0x78,
		0x9a, 0xbc, 0xde, 0xf0,
		0x55, 0xaa, 0x00, 0xff,
		0x11, 0x22, 0x33, 0x44,
	};
	uint8_t buf[17];
	uint8_t output[16];
	struct schc_bit_writer writer;
	struct schc_bit_reader reader;
	uint64_t prefix;

	schc_bit_writer_init(&writer, buf, sizeof(buf));
	zassert_ok(schc_bit_writer_write(&writer, 0x3, 2));
	zassert_ok(schc_bit_writer_write128(&writer, input, 128));

	schc_bit_reader_init(&reader, buf, schc_bit_writer_byte_len(&writer));
	zassert_ok(schc_bit_reader_read(&reader, 2, &prefix));
	zassert_equal(prefix, 0x3);
	zassert_ok(schc_bit_reader_read_bytes(&reader, 128,
					       output, sizeof(output)));
	zassert_mem_equal(output, input, sizeof(input));
}

ZTEST_SUITE(schc_generic, NULL, NULL, NULL, NULL, NULL);
