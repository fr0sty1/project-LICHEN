/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <schc/schc.h>

#include <stdio.h>
#include <string.h>

#include "schc_fragmentation_vectors.h"

#define SENTINEL 0xa5u

#define CHECK(condition) do { \
	if (!(condition)) { \
		printf("FAIL line %d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static const struct schc_fragment_byte_vector *field(const char *scenario,
						       const char *field_name)
{
	for (size_t i = 0; i < SCHC_FRAGMENT_BYTE_VECTOR_COUNT; i++) {
		if (strcmp(schc_fragment_byte_vectors[i].scenario, scenario) == 0 &&
		    strcmp(schc_fragment_byte_vectors[i].field, field_name) == 0) {
			return &schc_fragment_byte_vectors[i];
		}
	}
	return NULL;
}

static const struct schc_fragment_fragment_vector *fragment_field(
	const char *scenario, size_t ordinal)
{
	for (size_t i = 0; i < SCHC_FRAGMENT_FRAGMENT_VECTOR_COUNT; i++) {
		if (strcmp(schc_fragment_fragments[i].scenario, scenario) == 0 &&
		    schc_fragment_fragments[i].tile_ordinal == ordinal) {
			return &schc_fragment_fragments[i];
		}
	}
	return NULL;
}

static bool unchanged(const uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (buffer[i] != SENTINEL) {
			return false;
		}
	}
	return true;
}

static int test_control_vectors(void)
{
	static const char *const names[] = {
		"rule_78_ack_success_w0", "rule_78_ack_success_w1",
		"rule_78_ack_req_w0", "rule_78_ack_req_w1",
		"rule_78_sender_abort", "rule_78_receiver_abort",
		"rule_79_ack_success_w0", "rule_79_ack_success_w1",
		"rule_79_ack_req_w0", "rule_79_ack_req_w1",
		"rule_79_sender_abort", "rule_79_receiver_abort",
	};
	uint8_t wire[10];

	for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		const struct schc_fragment_byte_vector *expected =
			field("control_messages", names[index]);
		uint8_t rule_id = index < 6u ? SCHC_FRAGMENT_RULE_A_TO_B :
			SCHC_FRAGMENT_RULE_B_TO_A;
		uint8_t item = (uint8_t)(index % 6u);
		int length;

		CHECK(expected != NULL);
		if (item < 2u) {
			struct schc_ack ack = {
				.rule_id = rule_id,
				.window = item,
				.complete = true,
			};
			length = schc_ack_encode(&ack, wire, sizeof(wire));
			struct schc_ack decoded;
			CHECK(schc_ack_decode(&decoded, 0, false, wire,
					      (size_t)length) == length);
			CHECK(decoded.complete && decoded.window == item);
		} else {
			enum schc_fragment_control control = item < 4u ?
				SCHC_CONTROL_ACK_REQUEST : item == 4u ?
				SCHC_CONTROL_SENDER_ABORT : SCHC_CONTROL_RECEIVER_ABORT;
			length = schc_control_encode(control, rule_id,
						     (uint8_t)(item & 1u), wire,
						     sizeof(wire));
		}
		CHECK(length == (int)expected->len);
		CHECK(memcmp(wire, expected->data, expected->len) == 0);
	}
	return 0;
}

static int expected_ack_error(enum schc_fragment_vector_error error)
{
	switch (error) {
	case SCHC_VECTOR_ERROR_ACK_MALFORMED:
		return SCHC_ERR_ACK_MALFORMED;
	case SCHC_VECTOR_ERROR_ACK_UNASSIGNED:
		return SCHC_ERR_ACK_UNASSIGNED;
	default:
		return SCHC_ERR_INVALID_ARGUMENT;
	}
}

static int test_malformed_ack_vectors(void)
{
	for (size_t index = 0; index < SCHC_FRAGMENT_VECTOR_SOURCE_COUNT; index++) {
		const struct schc_fragment_scenario_vector *meta =
			&schc_fragment_scenarios[index];
		if (meta->parser != SCHC_VECTOR_PARSER_ACK) {
			continue;
		}
		const struct schc_fragment_byte_vector *wire = field(meta->name, "wire");
		const struct schc_fragment_byte_vector *fcns =
			field(meta->name, "assigned_fcns");
		uint64_t assigned = 0;
		if (fcns != NULL) {
			for (size_t i = 0; i < fcns->len; i++) {
				assigned |= UINT64_C(1) <<
					(fcns->data[i] == SCHC_ALL_1 ? 0u : fcns->data[i]);
			}
		}
		struct schc_ack decoded;
		struct schc_ack before;
		memset(&decoded, SENTINEL, sizeof(decoded));
		before = decoded;
		CHECK(wire != NULL);
		CHECK(schc_ack_decode(&decoded, assigned, fcns != NULL, wire->data,
				      wire->len) == expected_ack_error(meta->expect_error));
		CHECK(memcmp(&decoded, &before, sizeof(decoded)) == 0);
	}
	return 0;
}

static int test_ack_codec_atomicity(void)
{
	struct schc_ack ack = {
		.bitmap = (UINT64_C(1) << 62) | (UINT64_C(1) << 61) | 1u,
		.rule_id = SCHC_FRAGMENT_RULE_A_TO_B,
		.window = 0,
	};
	uint8_t wire[10];
	uint8_t expected[10];

	memset(wire, SENTINEL, sizeof(wire));
	memset(expected, SENTINEL, sizeof(expected));
	CHECK(schc_ack_encode(&ack, wire, 1) == SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(memcmp(wire, expected, sizeof(wire)) == 0);
	int length = schc_ack_encode(&ack, wire, sizeof(wire));
	CHECK(length == 9);
	struct schc_ack decoded;
	CHECK(schc_ack_decode(&decoded, ack.bitmap, true, wire, (size_t)length) == length);
	CHECK(decoded.bitmap == ack.bitmap && !decoded.complete);

	memset(wire, SENTINEL, sizeof(wire));
	CHECK(schc_control_encode(SCHC_CONTROL_RECEIVER_ABORT,
				  SCHC_FRAGMENT_RULE_A_TO_B, 0, wire, 2) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(unchanged(wire, sizeof(wire)));
	return 0;
}

static int emit_initial(struct schc_fragmenter *sender, uint8_t *wire,
			size_t wire_len)
{
	for (size_t ordinal = 0; ordinal < sender->fragment_count; ordinal++) {
		CHECK(schc_fragmenter_next(sender, wire, wire_len) > 0);
	}
	return 0;
}

static int test_missing_tile_retransmission(void)
{
	const char *name = "recover_missing_regular_tile";
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_byte_vector *failure = field(name, "ack_failure");
	const struct schc_fragment_byte_vector *retransmission =
		field(name, "retransmission");
	const struct schc_fragment_byte_vector *request = field(name, "ack_req");
	const struct schc_fragment_byte_vector *success = field(name, "ack_success");
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	CHECK(packet != NULL && failure != NULL && retransmission != NULL &&
	      request != NULL && success != NULL);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   packet->data, packet->len, packet->len) == SCHC_OK);
	CHECK(emit_initial(&sender, wire, sizeof(wire)) == 0);
	CHECK(schc_fragmenter_input(&sender, failure->data, failure->len) == SCHC_OK);

	struct schc_fragmenter before = sender;
	memset(wire, SENTINEL, sizeof(wire));
	CHECK(schc_fragmenter_next(&sender, wire, 1) == SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(unchanged(wire, sizeof(wire)));
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	CHECK(length == (int)retransmission->len);
	CHECK(memcmp(wire, retransmission->data, retransmission->len) == 0);
	length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	CHECK(length == (int)request->len);
	CHECK(memcmp(wire, request->data, request->len) == 0);
	CHECK(schc_fragmenter_input(&sender, success->data, success->len) == SCHC_OK);
	CHECK(sender.status == SCHC_SENDER_SUCCEEDED && sender.packet == NULL);
	before = sender;
	CHECK(schc_fragmenter_input(&sender, success->data, success->len) == SCHC_OK);
	CHECK(schc_fragmenter_input(&sender,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_A_TO_B, 0xff, 0xff }),
				     3) == SCHC_OK);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	return 0;
}

static int test_late_malformed_and_cancel(void)
{
	const char *name = "recover_missing_regular_tile";
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_byte_vector *failure = field(name, "ack_failure");
	const struct schc_fragment_fragment_vector *second = fragment_field(name, 1);
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	CHECK(packet != NULL && failure != NULL && second != NULL);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   packet->data, packet->len, packet->len) == SCHC_OK);
	CHECK(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
	struct schc_fragmenter before = sender;
	CHECK(schc_fragmenter_input(&sender, failure->data, failure->len) == SCHC_OK);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	CHECK(length == (int)second->wire_len);
	CHECK(memcmp(wire, second->wire, second->wire_len) == 0);
	CHECK(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);

	before = sender;
	CHECK(schc_fragmenter_input(&sender,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_A_TO_B }), 1) ==
	      SCHC_ERR_TOO_SHORT);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_input(&sender,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_B_TO_A, 0x40 }), 2) ==
	      SCHC_OK);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_input(&sender,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_A_TO_B, 0xff, 0xff }),
				     3) == SCHC_OK);
	CHECK(sender.status == SCHC_SENDER_ABORTED && sender.packet == NULL);
	return 0;
}

static int test_retry_exhaustion(void)
{
	const struct schc_fragment_byte_vector *request =
		field("sender_retry_exhaustion", "trigger");
	const struct schc_fragment_byte_vector *abort =
		field("sender_retry_exhaustion", "expected_message");
	const struct schc_fragment_byte_vector *receiver_trigger =
		field("receiver_retry_exhaustion", "trigger");
	const struct schc_fragment_byte_vector *receiver_abort =
		field("receiver_retry_exhaustion", "expected_message");
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t one = SENTINEL;
	struct schc_ack missing_all1 = {
		.rule_id = SCHC_FRAGMENT_RULE_A_TO_B,
		.window = 0,
		.bitmap = 0,
	};
	uint8_t ack[10];

	CHECK(request != NULL && abort != NULL && receiver_trigger != NULL &&
	      receiver_abort != NULL);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   &one, 1, 1) == SCHC_OK);
	CHECK(emit_initial(&sender, wire, sizeof(wire)) == 0);
	int ack_len = schc_ack_encode(&missing_all1, ack, sizeof(ack));
	CHECK(ack_len > 0);
	for (uint8_t attempt = 0; attempt < 2; attempt++) {
		CHECK(schc_fragmenter_input(&sender, ack, (size_t)ack_len) == SCHC_OK);
		CHECK(schc_fragmenter_next(&sender, wire, sizeof(wire)) > 0);
	}
	CHECK(sender.attempts == SCHC_FRAGMENT_MAX_ATTEMPTS - 1u);
	CHECK(schc_fragmenter_timeout(&sender) == SCHC_OK);
	int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	CHECK(length == (int)request->len);
	CHECK(memcmp(wire, request->data, request->len) == 0);
	CHECK(sender.attempts == SCHC_FRAGMENT_MAX_ATTEMPTS);
	CHECK(schc_fragmenter_timeout(&sender) == SCHC_OK);
	struct schc_fragmenter terminal_sender = sender;
	memset(wire, SENTINEL, sizeof(wire));
	CHECK(schc_fragmenter_next(&sender, wire, 1) == SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(memcmp(&sender, &terminal_sender, sizeof(sender)) == 0);
	CHECK(unchanged(wire, sizeof(wire)));
	length = schc_fragmenter_next(&sender, wire, sizeof(wire));
	CHECK(length == (int)abort->len);
	CHECK(memcmp(wire, abort->data, abort->len) == 0);
	CHECK(sender.status == SCHC_SENDER_ABORTED);
	terminal_sender = sender;
	CHECK(schc_fragmenter_input(&sender,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_A_TO_B, 0x40 }),
				     2) == SCHC_OK);
	CHECK(memcmp(&sender, &terminal_sender, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_timeout(&sender) == SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&sender, &terminal_sender, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_next(&sender, wire, sizeof(wire)) == SCHC_ERR_DONE);

	uint8_t storage = 0;
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	CHECK(schc_reassembler_init(&receiver, &storage, 1, 1) == SCHC_OK);
	struct schc_reassembler pristine_receiver = receiver;
	CHECK(schc_reassembler_input(&receiver,
				     ((uint8_t[]){ SCHC_FRAGMENT_RULE_A_TO_B }), 1,
				     &result) == SCHC_ERR_TOO_SHORT);
	CHECK(memcmp(&receiver, &pristine_receiver, sizeof(receiver)) == 0);
	for (uint8_t attempt = 0; attempt < SCHC_FRAGMENT_MAX_ATTEMPTS; attempt++) {
		CHECK(schc_reassembler_input(&receiver, receiver_trigger->data,
					     receiver_trigger->len, &result) == SCHC_OK);
		CHECK(!result.aborted);
		CHECK(schc_reassembler_next(&receiver, wire, sizeof(wire), &result) > 0);
	}
	CHECK(receiver.attempts == SCHC_FRAGMENT_MAX_ATTEMPTS);
	CHECK(schc_reassembler_input(&receiver, receiver_trigger->data,
				     receiver_trigger->len, &result) == SCHC_OK);
	CHECK(result.aborted);
	struct schc_reassembler pending_abort = receiver;
	memset(wire, SENTINEL, sizeof(wire));
	CHECK(schc_reassembler_next(&receiver, wire, 2, &result) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(memcmp(&receiver, &pending_abort, sizeof(receiver)) == 0);
	CHECK(unchanged(wire, sizeof(wire)));
	length = schc_reassembler_next(&receiver, wire, sizeof(wire), &result);
	CHECK(length == (int)receiver_abort->len);
	CHECK(memcmp(wire, receiver_abort->data, receiver_abort->len) == 0);
	CHECK(result.aborted && receiver.terminal && !receiver.active);
	struct schc_reassembler tombstone = receiver;
	CHECK(schc_reassembler_input(&receiver, receiver_trigger->data,
				     receiver_trigger->len, &result) == SCHC_OK);
	CHECK(!result.aborted && !result.complete);
	CHECK(memcmp(&receiver, &tombstone, sizeof(receiver)) == 0);
	CHECK(schc_reassembler_expire(&receiver) == SCHC_ERR_DONE);
	CHECK(memcmp(&receiver, &tombstone, sizeof(receiver)) == 0);
	schc_reassembler_release(&receiver);
	CHECK(!receiver.terminal);
	CHECK(schc_reassembler_input(&receiver, receiver_trigger->data,
				     receiver_trigger->len, &result) == SCHC_OK);
	CHECK(receiver.active);
	return 0;
}

int main(void)
{
	CHECK(test_control_vectors() == 0);
	CHECK(test_malformed_ack_vectors() == 0);
	CHECK(test_ack_codec_atomicity() == 0);
	CHECK(test_missing_tile_retransmission() == 0);
	CHECK(test_late_malformed_and_cancel() == 0);
	CHECK(test_retry_exhaustion() == 0);
	printf("PASS: canonical SCHC ACK generation and processing\n");
	return 0;
}
