/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <schc/bitstream.h>
#include <schc/schc.h>

#include <limits.h>
#include <string.h>

#include "schc_fragmentation_vectors.h"

#define TEST_RULE_ID 0x2a
#define TEST_UNCOMPRESSED_RULE_ID 0xff

static uint8_t large_reassembly[SCHC_FRAGMENT_MAX_PACKET_SIZE];

static const struct schc_fragment_byte_vector *field(const char *name,
						     const char *field_name)
{
	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_byte_vectors); i++) {
		if (strcmp(schc_fragment_byte_vectors[i].scenario, name) == 0 &&
		    strcmp(schc_fragment_byte_vectors[i].field, field_name) == 0) {
			return &schc_fragment_byte_vectors[i];
		}
	}
	return NULL;
}

static const struct schc_fragment_fragment_vector *fragment_field(
	const char *name, size_t ordinal)
{
	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_fragments); i++) {
		if (strcmp(schc_fragment_fragments[i].scenario, name) == 0 &&
		    schc_fragment_fragments[i].tile_ordinal == ordinal) {
			return &schc_fragment_fragments[i];
		}
	}
	return NULL;
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

static const struct schc_rule test_rules[] = {{
	.rule_id = TEST_RULE_ID,
	.compress = test_rule_compress,
	.decompress = test_rule_decompress,
}};

static const struct schc_profile test_profile = {
	.rules = test_rules,
	.rule_count = ARRAY_SIZE(test_rules),
	.uncompressed_rule_id = TEST_UNCOMPRESSED_RULE_ID,
	.use_uncompressed_fallback = true,
};

ZTEST(schc_generic, test_profile_dispatch_regressions)
{
	const uint8_t matched[] = { 0xa5, 0x00, 0x55, 0xff };
	const uint8_t fallback[] = { 0x01, 0x02, 0x03 };
	uint8_t compressed[sizeof(matched) + 1];
	uint8_t decompressed[sizeof(matched)];
	int ret = schc_compress(&test_profile, matched, sizeof(matched),
				compressed, sizeof(compressed));

	zassert_equal(ret, sizeof(matched));
	zassert_mem_equal(compressed, ((uint8_t[]){ TEST_RULE_ID, 0xff, 0xaa, 0x00 }),
			  sizeof(matched));
	ret = schc_decompress(&test_profile, compressed, sizeof(matched),
			      decompressed, sizeof(decompressed));
	zassert_equal(ret, sizeof(matched));
	zassert_mem_equal(decompressed, matched, sizeof(matched));
	ret = schc_compress(&test_profile, fallback, sizeof(fallback),
			    compressed, sizeof(compressed));
	zassert_equal(ret, sizeof(fallback) + 1);
	zassert_equal(compressed[0], TEST_UNCOMPRESSED_RULE_ID);
	zassert_mem_equal(&compressed[1], fallback, sizeof(fallback));
}

ZTEST(schc_generic, test_fallback_length_overflow_regressions)
{
	const struct schc_profile fallback_profile = {
		.rules = NULL,
		.rule_count = 0,
		.uncompressed_rule_id = TEST_UNCOMPRESSED_RULE_ID,
		.use_uncompressed_fallback = true,
	};
	const uint8_t packet = 0xa5;
	const uint8_t data = TEST_UNCOMPRESSED_RULE_ID;
	uint8_t out = 0;

	zassert_equal(schc_compress(&fallback_profile, &packet,
				     (size_t)INT_MAX - 1u, &out, 0),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(schc_compress(&fallback_profile, &packet,
				     (size_t)INT_MAX, &out, SIZE_MAX),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(schc_compress(&fallback_profile, &packet,
				     SIZE_MAX, &out, SIZE_MAX),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(schc_decompress(&fallback_profile, &data,
				       (size_t)INT_MAX + 1u, &out, 0),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(schc_decompress(&fallback_profile, &data,
				       (size_t)INT_MAX + 2u, &out, SIZE_MAX),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(schc_decompress(&fallback_profile, &data,
				       SIZE_MAX, &out, SIZE_MAX),
		      SCHC_ERR_BUFFER_TOO_SMALL);
}

static void assert_delivered(struct schc_reassembler *receiver,
			     const uint8_t *expected, size_t expected_len)
{
	/* Matches schc_fragment.json:single_fragment and multi_fragment vectors.
	 * Independent oracle from RFC 8724; all 3 impls (Python/Rust/C) interop on these. */
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

	zassert_ok(schc_reassembler_packet(receiver, &packet, &packet_len));
	zassert_equal(packet_len, expected_len);
	zassert_mem_equal(packet, expected, expected_len);
}

static void check_literal_fragments(
	const struct schc_fragment_scenario_vector *meta,
	const struct schc_fragment_byte_vector *packet)
{
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];

	zassert_ok(schc_fragmenter_init(&sender, meta->rule_id, packet->data,
					 packet->len, packet->len));
	zassert_equal(sender.fragment_count, meta->fragment_count);
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		const struct schc_fragment_fragment_vector *expected =
			fragment_field(meta->name, ordinal);
		struct schc_fragment decoded;
		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));

		zassert_not_null(expected);
		zassert_true(length > 0);
		zassert_equal(length, expected->wire_len);
		zassert_mem_equal(wire, expected->wire, expected->wire_len);
		int consumed = schc_fragment_decode(&decoded, expected->wire,
						    expected->wire_len, tile, sizeof(tile));
		zassert_equal(consumed, expected->wire_len);
		zassert_equal(decoded.window, expected->window);
		zassert_equal(decoded.fcn, expected->fcn);
		if (expected->kind == SCHC_VECTOR_FRAGMENT_ALL1) {
			zassert_equal(decoded.fcn, 63);
		} else if (expected->kind == SCHC_VECTOR_FRAGMENT_ALL0) {
			zassert_equal(decoded.fcn, 0);
		} else {
			zassert_true(decoded.fcn > 0 && decoded.fcn < 63);
		}
	}
}

static void exercise_recovery(const struct schc_fragment_scenario_vector *meta)
{
	const struct schc_fragment_byte_vector *packet = field(meta->name, "packet");
	const struct schc_fragment_byte_vector *ack_failure = field(meta->name, "ack_failure");
	const struct schc_fragment_byte_vector *retransmission = field(meta->name, "retransmission");
	const struct schc_fragment_byte_vector *ack_req = field(meta->name, "ack_req");
	const struct schc_fragment_byte_vector *ack_success = field(meta->name, "ack_success");
	struct schc_fragmenter sender;
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	const uint8_t *delivered;
	size_t delivered_len;

	zassert_not_null(meta->drop_fragment);
	zassert_not_null(packet);
	zassert_not_null(field(meta->name, "rcs"));
	zassert_not_null(ack_failure);
	zassert_not_null(retransmission);
	zassert_not_null(ack_req);
	zassert_not_null(ack_success);
	zassert_equal(packet->len, meta->packet_len);
	check_literal_fragments(meta, packet);
	zassert_ok(schc_fragmenter_init(&sender, meta->rule_id, packet->data,
					 packet->len, packet->len));
	zassert_ok(schc_reassembler_init(&receiver, large_reassembly,
					 sizeof(large_reassembly), packet->len));
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		const struct schc_fragment_fragment_vector *literal =
			fragment_field(meta->name, ordinal);
		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));

		zassert_not_null(literal);
		if (strcmp(literal->name, meta->drop_fragment) != 0) {
			zassert_ok(schc_reassembler_input(&receiver, wire,
							  (size_t)length, &result));
		}
	}
	int length = schc_reassembler_next(&receiver, wire, sizeof(wire), &result);
	zassert_equal(length, ack_failure->len);
	zassert_mem_equal(wire, ack_failure->data, ack_failure->len);
	zassert_ok(schc_fragmenter_input(&sender, wire, (size_t)length));
	length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	zassert_equal(length, retransmission->len);
	zassert_mem_equal(wire, retransmission->data, retransmission->len);
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	zassert_equal(length, ack_req->len);
	zassert_mem_equal(wire, ack_req->data, ack_req->len);
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_false(result.complete);
	zassert_true(result.rcs_checked && result.rcs_ok);
	zassert_equal(schc_reassembler_packet(&receiver, &delivered, &delivered_len),
		      SCHC_ERR_DONE);
	length = schc_reassembler_next(&receiver, wire, sizeof(wire), &result);
	zassert_equal(length, ack_success->len);
	zassert_mem_equal(wire, ack_success->data, ack_success->len);
	zassert_true(result.complete);
	zassert_equal(result.packet_len, packet->len);
	assert_delivered(&receiver, packet->data, packet->len);
	zassert_ok(schc_fragmenter_input(&sender, wire, (size_t)length));
	zassert_equal(sender.status, SCHC_SENDER_SUCCEEDED);

	const struct schc_fragment_byte_vector *corrupt = field(meta->name, "corrupt_all1");
	if (corrupt != NULL) {
		const struct schc_fragment_byte_vector *failure = field(meta->name,
								     "rcs_failure_ack");
		const struct schc_fragment_byte_vector *abort = field(meta->name,
								   "next_sender_message");
		zassert_not_null(failure);
		zassert_not_null(abort);
		zassert_ok(schc_fragmenter_init(&sender, meta->rule_id, packet->data,
						 packet->len, packet->len));
		zassert_ok(schc_reassembler_init(&receiver, large_reassembly,
						 sizeof(large_reassembly), packet->len));
		for (size_t i = 0; i < sender.fragment_count; i++) {
			length = schc_fragmenter_next(&sender, wire, sizeof(wire));
			if (i + 1 < sender.fragment_count) {
				zassert_ok(schc_reassembler_input(&receiver, wire,
								  (size_t)length, &result));
			}
		}
		zassert_ok(schc_reassembler_input(&receiver, corrupt->data,
						 corrupt->len, &result));
		zassert_true(result.rcs_checked);
		zassert_false(result.rcs_ok);
		length = schc_reassembler_next(&receiver, wire, sizeof(wire), &result);
		zassert_equal(length, failure->len);
		zassert_mem_equal(wire, failure->data, failure->len);
		zassert_ok(schc_fragmenter_input(&sender, wire, (size_t)length));
		length = schc_fragmenter_next(&sender, wire, sizeof(wire));
		zassert_equal(length, abort->len);
		zassert_mem_equal(wire, abort->data, abort->len);
	}
}

static void exercise_controls(const struct schc_fragment_scenario_vector *meta)
{
	const char *fields[] = {
		"rule_78_ack_success_w0", "rule_78_ack_success_w1",
		"rule_78_ack_req_w0", "rule_78_ack_req_w1",
		"rule_78_sender_abort", "rule_78_receiver_abort",
		"rule_79_ack_success_w0", "rule_79_ack_success_w1",
		"rule_79_ack_req_w0", "rule_79_ack_req_w1",
		"rule_79_sender_abort", "rule_79_receiver_abort",
	};
	uint8_t wire[10];

	for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
		const struct schc_fragment_byte_vector *expected = field(meta->name, fields[i]);
		uint8_t rule = i < 6 ? 0x78 : 0x79;
		uint8_t item = (uint8_t)(i % 6);
		int length;

		zassert_not_null(expected);
		if (item < 2) {
			struct schc_ack ack = {
				.rule_id = rule,
				.window = item,
				.complete = true,
			};
			length = schc_ack_encode(&ack, wire, sizeof(wire));
			struct schc_ack decoded;
			int consumed = schc_ack_decode(&decoded, 0, false, wire,
						       (size_t)length);
			zassert_equal(consumed, length);
			zassert_equal(decoded.complete, true);
		} else {
			enum schc_fragment_control control = item < 4 ?
				SCHC_CONTROL_ACK_REQUEST : item == 4 ?
				SCHC_CONTROL_SENDER_ABORT : SCHC_CONTROL_RECEIVER_ABORT;
			length = schc_control_encode(control, rule, (uint8_t)(item & 1u),
						     wire, sizeof(wire));
		}
		zassert_equal(length, expected->len);
		zassert_mem_equal(wire, expected->data, expected->len);
	}
}

static void exercise_retry(const struct schc_fragment_scenario_vector *meta)
{
	const struct schc_fragment_byte_vector *trigger = field(meta->name, "trigger");
	const struct schc_fragment_byte_vector *expected = field(meta->name,
								 "expected_message");
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	zassert_not_null(trigger);
	zassert_not_null(expected);
	zassert_equal(meta->expect_status, SCHC_VECTOR_STATUS_ABORTED);
	zassert_equal(meta->attempts_before, SCHC_FRAGMENT_MAX_ATTEMPTS);
	if (meta->retry_role == SCHC_VECTOR_RETRY_SENDER) {
		struct schc_fragmenter sender;
		memset(large_reassembly, 0xa5, 11782);
		zassert_ok(schc_fragmenter_init(&sender, meta->rule_id, large_reassembly,
						 11782, 11782));
		for (size_t i = 0; i < sender.fragment_count; i++) {
			zassert_true(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
		}
		for (uint8_t attempt = 1; attempt < meta->attempts_before; attempt++) {
			zassert_ok(schc_fragmenter_timeout(&sender));
			int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
			zassert_equal(length, trigger->len);
			zassert_mem_equal(wire, trigger->data, trigger->len);
		}
		zassert_ok(schc_fragmenter_timeout(&sender));
		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
		zassert_equal(length, expected->len);
		zassert_mem_equal(wire, expected->data, expected->len);
		zassert_equal(sender.status, SCHC_SENDER_ABORTED);
	} else {
		struct schc_reassembler receiver;
		struct schc_reassembly_result result;
		uint8_t storage = 0;
		zassert_equal(meta->retry_role, SCHC_VECTOR_RETRY_RECEIVER);
		zassert_ok(schc_reassembler_init(&receiver, &storage, 1, 1));
		for (uint8_t attempt = 0; attempt < meta->attempts_before; attempt++) {
			zassert_ok(schc_reassembler_input(&receiver, trigger->data,
							  trigger->len, &result));
			zassert_true(schc_reassembler_next(&receiver, wire, sizeof(wire),
						     &result) > 0);
		}
		zassert_ok(schc_reassembler_input(&receiver, trigger->data,
						  trigger->len, &result));
		zassert_true(result.aborted);
		int length = schc_reassembler_next(&receiver, wire, sizeof(wire), &result);
		zassert_equal(length, expected->len);
		zassert_mem_equal(wire, expected->data, expected->len);
	}
}

static void exercise_capacity(const struct schc_fragment_scenario_vector *meta)
{
	const struct schc_fragment_byte_vector *packet = field(meta->name, "packet");
	const struct schc_fragment_byte_vector *rcs = field(meta->name, "rcs");
	struct schc_fragmenter sender;

	zassert_not_null(packet);
	zassert_equal(packet->len, meta->packet_len);
	int ret = schc_fragmenter_init(&sender, 0x78, packet->data, packet->len,
				       SCHC_FRAGMENT_MAX_PACKET_SIZE);
	if (meta->expect_status == SCHC_VECTOR_STATUS_PACKET_TOO_LARGE) {
		zassert_true(ret < 0);
		zassert_equal(meta->fragment_count, 0);
		zassert_is_null(rcs);
		return;
	}
	zassert_equal(meta->expect_status, SCHC_VECTOR_STATUS_OK);
	zassert_not_null(rcs);
	zassert_ok(ret);
	zassert_equal(sender.fragment_count, meta->fragment_count);
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	struct schc_fragment final;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	zassert_ok(schc_reassembler_init(&receiver, large_reassembly,
					 sizeof(large_reassembly), packet->len));
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
		zassert_true(length > 0);
		if (ordinal + 1 == sender.fragment_count) {
			int consumed = schc_fragment_decode(&final, wire, (size_t)length,
							    receiver.decode_tile,
							    sizeof(receiver.decode_tile));
			zassert_equal(consumed, length);
			zassert_mem_equal(final.rcs, rcs->data, rcs->len);
			const struct schc_fragment_fragment_vector *literal =
				fragment_field(meta->name, ordinal);
			if (literal != NULL) {
				zassert_equal(length, literal->wire_len);
				zassert_mem_equal(wire, literal->wire, literal->wire_len);
			}
		}
		zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length,
						  &result));
	}
	zassert_false(result.complete);
	zassert_true(result.rcs_checked && result.rcs_ok);
	zassert_true(schc_reassembler_next(&receiver, wire, sizeof(wire), &result) > 0);
	zassert_true(result.complete);
	zassert_equal(result.packet_len, packet->len);
	assert_delivered(&receiver, packet->data, packet->len);
}

static int vector_error(enum schc_fragment_vector_error error)
{
	switch (error) {
	case SCHC_VECTOR_ERROR_FRAGMENT_LENGTH:
		return SCHC_ERR_FRAGMENT_LENGTH;
	case SCHC_VECTOR_ERROR_FRAGMENT_PADDING:
		return SCHC_ERR_FRAGMENT_PADDING;
	case SCHC_VECTOR_ERROR_FRAGMENT_FCN:
		return SCHC_ERR_FRAGMENT_FCN;
	case SCHC_VECTOR_ERROR_ACK_MALFORMED:
		return SCHC_ERR_ACK_MALFORMED;
	case SCHC_VECTOR_ERROR_ACK_UNASSIGNED:
		return SCHC_ERR_ACK_UNASSIGNED;
	case SCHC_VECTOR_ERROR_NONE:
		break;
	}
	return SCHC_ERR_INVALID_ARGUMENT;
}

static void exercise_malformed(const struct schc_fragment_scenario_vector *meta)
{
	const struct schc_fragment_byte_vector *wire = field(meta->name, "wire");
	int expected = vector_error(meta->expect_error);

	zassert_not_null(wire);
	zassert_not_equal(meta->expect_error, SCHC_VECTOR_ERROR_NONE);
	if (meta->parser == SCHC_VECTOR_PARSER_ACK) {
		uint64_t assigned = 0;
		bool contextual = meta->expect_error == SCHC_VECTOR_ERROR_ACK_UNASSIGNED;
		if (contextual) {
			const struct schc_fragment_byte_vector *fcns = field(meta->name,
									 "assigned_fcns");
			zassert_not_null(fcns);
			for (size_t i = 0; i < fcns->len; i++) {
				assigned |= UINT64_C(1) << (fcns->data[i] == 63 ? 0 :
								 fcns->data[i]);
			}
		}
		struct schc_ack ack;
		zassert_equal(schc_ack_decode(&ack, assigned, contextual,
						      wire->data, wire->len), expected);
		return;
	}
	zassert_equal(meta->parser, SCHC_VECTOR_PARSER_FRAGMENT);
	struct schc_fragment fragment;
	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];
	zassert_equal(schc_fragment_decode(&fragment, wire->data, wire->len,
					   tile, sizeof(tile)), expected);
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	uint8_t response[3];
	zassert_ok(schc_reassembler_init(&receiver, large_reassembly,
					 sizeof(large_reassembly),
					 SCHC_FRAGMENT_DEFAULT_RECEIVER_LIMIT));
	zassert_ok(schc_reassembler_input(&receiver, wire->data, wire->len, &result));
	zassert_true(result.aborted);
	zassert_equal(schc_reassembler_next(&receiver, response, sizeof(response),
					    &result), 3);
}

ZTEST(schc_generic, test_all_shared_fragmentation_vectors_once)
{
	bool executed[SCHC_FRAGMENT_VECTOR_SOURCE_COUNT] = { false };
	uint32_t categories = 0;

	for (size_t i = 0; i < ARRAY_SIZE(schc_fragment_scenarios); i++) {
		const struct schc_fragment_scenario_vector *meta =
			&schc_fragment_scenarios[i];
		zassert_false(executed[i]);
		zassert_not_null(meta->name);
		zassert_not_null(meta->provenance);
		executed[i] = true;
		categories |= UINT32_C(1) << meta->category;
		switch (meta->category) {
		case SCHC_VECTOR_RECOVERY:
		case SCHC_VECTOR_WINDOW_TRANSITION:
			exercise_recovery(meta);
			break;
		case SCHC_VECTOR_CONTROLS:
			exercise_controls(meta);
			break;
		case SCHC_VECTOR_RETRY_EXHAUSTION:
			exercise_retry(meta);
			break;
		case SCHC_VECTOR_CAPACITY:
			exercise_capacity(meta);
			break;
		case SCHC_VECTOR_MALFORMED:
			exercise_malformed(meta);
			break;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(executed); i++) {
		zassert_true(executed[i]);
	}
	zassert_equal(categories, (UINT32_C(1) << 6) - 1u);
}

ZTEST(schc_generic, test_sender_ignores_stale_ack_until_waiting)
{
	const struct schc_fragment_byte_vector *packet = field("recover_missing_regular_tile",
								 "packet");
	const struct schc_fragment_fragment_vector *second =
		fragment_field("recover_missing_regular_tile", 1);
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t ack[10];
	struct schc_ack c0 = { .rule_id = 0x78, .window = 0, .bitmap = 0 };

	zassert_ok(schc_fragmenter_init(&sender, 0x78, packet->data, packet->len,
					 packet->len));
	zassert_true(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
	zassert_ok(schc_fragmenter_input(&sender, ((uint8_t[]){ 0x78, 0x40 }), 2));
	int ack_len = schc_ack_encode(&c0, ack, sizeof(ack));
	zassert_true(ack_len > 0);
	zassert_ok(schc_fragmenter_input(&sender, ack, (size_t)ack_len));
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	zassert_equal(length, second->wire_len);
	zassert_mem_equal(wire, second->wire, second->wire_len);
	zassert_not_null(sender.packet);
	zassert_ok(schc_fragmenter_input(&sender, ((uint8_t[]){ 0x78, 0xff, 0xff }), 3));
	zassert_equal(sender.status, SCHC_SENDER_ABORTED);
}

ZTEST(schc_generic, test_receiver_rule_isolation)
{
	const struct schc_fragment_fragment_vector *first =
		fragment_field("recover_missing_regular_tile", 0);
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	uint64_t bitmap;
	uint8_t opposite[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	zassert_ok(schc_reassembler_init(&receiver, large_reassembly,
					 sizeof(large_reassembly), 375));
	zassert_ok(schc_reassembler_input(&receiver, first->wire, first->wire_len, &result));
	bitmap = receiver.bitmap[0];
	zassert_ok(schc_reassembler_input(&receiver,
					  ((uint8_t[]){ 0x79, 0x00 }), 2, &result));
	zassert_equal(receiver.bitmap[0], bitmap);
	zassert_true(receiver.active);
	memcpy(opposite, first->wire, first->wire_len);
	opposite[0] = 0x79;
	zassert_ok(schc_reassembler_input(&receiver, opposite, first->wire_len,
					  &result));
	zassert_equal(receiver.bitmap[0], bitmap);
	zassert_ok(schc_reassembler_input(&receiver,
					  ((uint8_t[]){ 0x79, 0xff, 0xff }), 3, &result));
	zassert_true(receiver.active);
	zassert_equal(receiver.pending, 0);
	zassert_ok(schc_reassembler_input(&receiver,
					  ((uint8_t[]){ 0x78, 0xfe }), 2, &result));
	zassert_false(receiver.active);
}

ZTEST(schc_generic, test_control_errors_leave_output_unchanged)
{
	uint8_t out[3] = { 0xa5, 0xa5, 0xa5 };
	const uint8_t sentinel[3] = { 0xa5, 0xa5, 0xa5 };

	zassert_equal(schc_control_encode((enum schc_fragment_control)99, 0x78, 0,
					 out, sizeof(out)), SCHC_ERR_INVALID_ARGUMENT);
	zassert_mem_equal(out, sentinel, sizeof(out));
	zassert_equal(schc_control_encode(SCHC_CONTROL_RECEIVER_ABORT, 0x77, 0,
					 out, 0), SCHC_ERR_INVALID_ARGUMENT);
	zassert_mem_equal(out, sentinel, sizeof(out));
	zassert_equal(schc_control_encode(SCHC_CONTROL_RECEIVER_ABORT, 0x78, 0,
					 out, 2), SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_mem_equal(out, sentinel, sizeof(out));
}

ZTEST(schc_generic, test_pending_all1_delivery_and_expiry)
{
	const uint8_t packet[] = { 0xa5 };
	uint8_t storage[sizeof(packet)];
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t conflicting[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t response[10];
	struct schc_fragmenter sender;
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	const uint8_t *delivered;
	size_t delivered_len;

	zassert_ok(schc_fragmenter_init(&sender, 0x79, packet, sizeof(packet),
					 sizeof(packet)));
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	memcpy(conflicting, wire, (size_t)length);
	conflicting[length - 1] ^= 2u;
	zassert_ok(schc_reassembler_init(&receiver, storage, sizeof(storage), sizeof(storage)));
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_false(result.complete);
	zassert_equal(schc_reassembler_packet(&receiver, &delivered, &delivered_len),
		      SCHC_ERR_DONE);
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_equal(schc_reassembler_input(&receiver, ((uint8_t[]){ 0x79 }), 1,
					     &result), SCHC_ERR_INVALID_ARGUMENT);
	zassert_equal(schc_reassembler_next(&receiver, response, 1, &result),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_false(result.complete);
	zassert_equal(schc_reassembler_packet(&receiver, &delivered, &delivered_len),
		      SCHC_ERR_DONE);
	zassert_equal(schc_reassembler_expire(&receiver), SCHC_ERR_DONE);
	zassert_equal(schc_reassembler_next(&receiver, response, sizeof(response),
					    &result), 2);
	zassert_true(result.complete);
	assert_delivered(&receiver, packet, sizeof(packet));

	zassert_ok(schc_reassembler_init(&receiver, storage, sizeof(storage), sizeof(storage)));
	zassert_ok(schc_reassembler_input(&receiver,
					  ((uint8_t[]){ 0x79, 0x00 }), 2, &result));
	zassert_equal(schc_reassembler_next(&receiver, response, 1, &result),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_ok(schc_reassembler_expire(&receiver));
	zassert_equal(schc_reassembler_next(&receiver, response, sizeof(response),
					    &result), 3);
	zassert_true(result.aborted);

	zassert_ok(schc_reassembler_init(&receiver, storage, sizeof(storage), sizeof(storage)));
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_ok(schc_reassembler_input(&receiver, conflicting, (size_t)length, &result));
	zassert_true(result.aborted);
	zassert_equal(schc_reassembler_next(&receiver, response, sizeof(response),
					    &result), 3);

	zassert_ok(schc_reassembler_init(&receiver, storage, sizeof(storage), sizeof(storage)));
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_equal(schc_reassembler_next(&receiver, response, 1, &result),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_false(result.complete);
	zassert_equal(schc_reassembler_packet(&receiver, &delivered, &delivered_len),
		      SCHC_ERR_DONE);
	zassert_equal(schc_reassembler_next(&receiver, response, sizeof(response),
					    &result), 2);
	zassert_true(result.complete);
	zassert_equal(result.packet_len, sizeof(packet));
	assert_delivered(&receiver, packet, sizeof(packet));
	zassert_equal(schc_reassembler_input(&receiver, ((uint8_t[]){ 0x79 }), 1,
					     &result), SCHC_ERR_TOO_SHORT);
	assert_delivered(&receiver, packet, sizeof(packet));
	zassert_equal(schc_reassembler_input(&receiver,
					     ((uint8_t[]){ 0x79, 0x7c, 0x00 }), 3,
					     &result), SCHC_ERR_FRAGMENT_LENGTH);
	assert_delivered(&receiver, packet, sizeof(packet));
	zassert_ok(schc_reassembler_input(&receiver,
					  ((uint8_t[]){ 0x78, 0x00 }), 2, &result));
	assert_delivered(&receiver, packet, sizeof(packet));
	zassert_ok(schc_reassembler_input(&receiver, wire, (size_t)length, &result));
	zassert_equal(schc_reassembler_packet(&receiver, &delivered, &delivered_len),
		      SCHC_ERR_DONE);
}

ZTEST(schc_generic, test_regular_rcs_validation_preserves_output)
{
	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE] = { 0 };
	uint8_t out[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t expected[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	struct schc_fragment fragment = {
		.tile = tile,
		.tile_len = sizeof(tile),
		.rule_id = 0x78,
		.window = 0,
		.fcn = 62,
		.rcs = { 1, 0, 0, 0 },
	};

	memset(out, 0xa5, sizeof(out));
	memset(expected, 0xa5, sizeof(expected));
	zassert_equal(schc_fragment_encode(&fragment, out, sizeof(out)),
		      SCHC_ERR_INVALID_ARGUMENT);
	zassert_mem_equal(out, expected, sizeof(out));
}

ZTEST(schc_generic, test_sender_short_write_and_terminal_noops)
{
	const struct schc_fragment_byte_vector *packet = field("recover_missing_regular_tile",
								 "packet");
	const struct schc_fragment_byte_vector *ack_req = field("recover_missing_regular_tile",
								  "ack_req");
	const struct schc_fragment_byte_vector *ack_failure =
		field("recover_missing_regular_tile", "ack_failure");
	const struct schc_fragment_byte_vector *retransmission =
		field("recover_missing_regular_tile", "retransmission");
	const struct schc_fragment_byte_vector *rcs_failure =
		field("recover_missing_regular_tile", "rcs_failure_ack");
	const struct schc_fragment_byte_vector *sender_abort =
		field("recover_missing_regular_tile", "next_sender_message");
	const struct schc_fragment_fragment_vector *first =
		fragment_field("recover_missing_regular_tile", 0);
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	zassert_ok(schc_fragmenter_init(&sender, 0x78, packet->data, packet->len,
					 packet->len));
	zassert_equal(schc_fragmenter_next(&sender, wire, 1),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	zassert_equal(length, first->wire_len);
	zassert_mem_equal(wire, first->wire, first->wire_len);
	for (size_t i = 1; i < sender.fragment_count; i++) {
		zassert_true(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
	}
	zassert_ok(schc_fragmenter_timeout(&sender));
	zassert_equal(schc_fragmenter_next(&sender, wire, 1),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	zassert_equal(length, ack_req->len);
	zassert_mem_equal(wire, ack_req->data, ack_req->len);
	zassert_ok(schc_fragmenter_input(&sender,
					  ((uint8_t[]){ 0x78, 0xff, 0xff }), 3));
	zassert_equal(sender.status, SCHC_SENDER_ABORTED);
	zassert_equal(schc_fragmenter_next(&sender, wire, sizeof(wire)), SCHC_ERR_DONE);
	zassert_ok(schc_fragmenter_input(&sender, ((uint8_t[]){ 0x78, 0x40 }), 2));
	zassert_equal(sender.status, SCHC_SENDER_ABORTED);

	struct schc_fragmenter retrans_sender;
	zassert_ok(schc_fragmenter_init(&retrans_sender, 0x78, packet->data, packet->len,
					 packet->len));
	for (size_t i = 0; i < retrans_sender.fragment_count; i++) {
		zassert_true(schc_fragmenter_next(&retrans_sender, wire, sizeof(wire)) > 0);
	}
	zassert_ok(schc_fragmenter_input(&retrans_sender, ack_failure->data,
					  ack_failure->len));
	uint8_t position = retrans_sender.retransmit_position;
	zassert_equal(schc_fragmenter_next(&retrans_sender, wire, 1),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	zassert_equal(retrans_sender.retransmit_position, position);
	length = schc_fragmenter_next(&retrans_sender, wire, sizeof(wire));
	zassert_equal(length, retransmission->len);
	zassert_mem_equal(wire, retransmission->data, retransmission->len);
	zassert_equal(schc_fragmenter_next(&retrans_sender, wire, 1),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	length = schc_fragmenter_next(&retrans_sender, wire, sizeof(wire));
	zassert_equal(length, ack_req->len);
	zassert_mem_equal(wire, ack_req->data, ack_req->len);

	struct schc_fragmenter abort_sender;
	zassert_ok(schc_fragmenter_init(&abort_sender, 0x78, packet->data, packet->len,
					 packet->len));
	for (size_t i = 0; i < abort_sender.fragment_count; i++) {
		zassert_true(schc_fragmenter_next(&abort_sender, wire, sizeof(wire)) > 0);
	}
	zassert_ok(schc_fragmenter_input(&abort_sender, rcs_failure->data,
					  rcs_failure->len));
	zassert_equal(abort_sender.status, SCHC_SENDER_ABORTED);
	zassert_equal(schc_fragmenter_next(&abort_sender, wire, 1),
		      SCHC_ERR_BUFFER_TOO_SMALL);
	length = schc_fragmenter_next(&abort_sender, wire, sizeof(wire));
	zassert_equal(length, sender_abort->len);
	zassert_mem_equal(wire, sender_abort->data, sender_abort->len);
	zassert_equal(schc_fragmenter_next(&abort_sender, wire, sizeof(wire)),
		      SCHC_ERR_DONE);

	struct schc_fragmenter ignored_sender;
	zassert_ok(schc_fragmenter_init(&ignored_sender, 0x78, packet->data, packet->len,
					 packet->len));
	for (size_t i = 0; i < ignored_sender.fragment_count; i++) {
		zassert_true(schc_fragmenter_next(&ignored_sender, wire, sizeof(wire)) > 0);
	}
	uint8_t attempts = ignored_sender.attempts;
	uint8_t phase = ignored_sender.phase;
	zassert_ok(schc_fragmenter_input(&ignored_sender,
					  ((uint8_t[]){ 0x78, 0xc0 }), 2));
	zassert_equal(ignored_sender.attempts, attempts);
	zassert_equal(ignored_sender.phase, phase);
	struct schc_ack unused = { .rule_id = 0x78, .window = 1, .bitmap = 0 };
	int unused_len = schc_ack_encode(&unused, wire, sizeof(wire));
	zassert_true(unused_len > 0);
	zassert_ok(schc_fragmenter_input(&ignored_sender, wire, (size_t)unused_len));
	zassert_equal(ignored_sender.attempts, attempts);
	zassert_equal(ignored_sender.phase, phase);
	zassert_equal(ignored_sender.status, SCHC_SENDER_ACTIVE);
	zassert_equal(schc_fragmenter_next(&ignored_sender, wire, sizeof(wire)),
		      SCHC_ERR_DONE);
	zassert_ok(schc_fragmenter_input(&ignored_sender,
					  ((uint8_t[]){ 0x79, 0x40 }), 2));
	zassert_equal(ignored_sender.attempts, attempts);
	zassert_equal(ignored_sender.phase, phase);

	const uint8_t one = 0xa5;
	zassert_ok(schc_fragmenter_init(&sender, 0x78, &one, 1, 1));
	zassert_true(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
	zassert_ok(schc_fragmenter_input(&sender, ((uint8_t[]){ 0x78, 0x40 }), 2));
	zassert_equal(sender.status, SCHC_SENDER_SUCCEEDED);
	zassert_equal(schc_fragmenter_next(&sender, wire, sizeof(wire)), SCHC_ERR_DONE);
	zassert_equal(schc_fragmenter_timeout(&sender), SCHC_ERR_INVALID_ARGUMENT);
	zassert_ok(schc_fragmenter_input(&sender,
					  ((uint8_t[]){ 0x78, 0xff, 0xff }), 3));
	zassert_equal(sender.status, SCHC_SENDER_SUCCEEDED);
}

ZTEST(schc_generic, test_bitstream_regressions)
{
	const uint8_t input[16] = {
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x55, 0xaa, 0x00, 0xff, 0x11, 0x22, 0x33, 0x44,
	};
	const uint8_t expected_128[17] = {
		0xc4, 0x8d, 0x15, 0x9e, 0x26, 0xaf, 0x37, 0xbc,
		0x15, 0x6a, 0x80, 0x3f, 0xc4, 0x48, 0x8c, 0xd1, 0x00,
	};
	uint8_t buf[17];
	uint8_t output[16];
	struct schc_bit_writer writer;
	struct schc_bit_reader reader;
	uint64_t value;

	schc_bit_writer_init(&writer, buf, sizeof(buf));
	zassert_ok(schc_bit_writer_write(&writer, 0x5, 3));
	zassert_ok(schc_bit_writer_write(&writer, 0x12, 5));
	zassert_ok(schc_bit_writer_write(&writer, 0xabc, 12));
	zassert_mem_equal(buf, ((uint8_t[]){ 0xb2, 0xab, 0xc0 }), 3);
	schc_bit_reader_init(&reader, buf, 3);
	zassert_ok(schc_bit_reader_read(&reader, 3, &value));
	zassert_equal(value, 0x5);
	zassert_ok(schc_bit_reader_read(&reader, 5, &value));
	zassert_equal(value, 0x12);
	zassert_ok(schc_bit_reader_read(&reader, 12, &value));
	zassert_equal(value, 0xabc);
	schc_bit_writer_init(&writer, buf, sizeof(buf));
	zassert_ok(schc_bit_writer_write(&writer, 0x3, 2));
	zassert_ok(schc_bit_writer_write128(&writer, input, 128));
	zassert_equal(schc_bit_writer_byte_len(&writer), sizeof(expected_128));
	zassert_mem_equal(buf, expected_128, sizeof(expected_128));
	schc_bit_reader_init(&reader, expected_128, sizeof(expected_128));
	zassert_ok(schc_bit_reader_read(&reader, 2, &value));
	zassert_ok(schc_bit_reader_read_bytes(&reader, 128, output, sizeof(output)));
	zassert_mem_equal(output, input, sizeof(input));
}

ZTEST_SUITE(schc_generic, NULL, NULL, NULL, NULL, NULL);
