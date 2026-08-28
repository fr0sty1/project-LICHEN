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

static uint8_t reassembled[SCHC_FRAGMENT_MAX_PACKET_SIZE];
static uint8_t generated[SCHC_FRAGMENT_MAX_TILES][SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
static size_t generated_len[SCHC_FRAGMENT_MAX_TILES];

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

static const struct schc_fragment_scenario_vector *scenario(const char *name)
{
	for (size_t i = 0; i < SCHC_FRAGMENT_VECTOR_SOURCE_COUNT; i++) {
		if (strcmp(schc_fragment_scenarios[i].name, name) == 0) {
			return &schc_fragment_scenarios[i];
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

static int assert_packet(struct schc_reassembler *receiver,
			 const uint8_t *expected, size_t expected_len)
{
	const uint8_t *packet;
	size_t packet_len;

	CHECK(schc_reassembler_packet(receiver, &packet, &packet_len) == SCHC_OK);
	CHECK(packet_len == expected_len);
	CHECK(memcmp(packet, expected, expected_len) == 0);
	return 0;
}

static int drain_exact(struct schc_reassembler *receiver,
		       const struct schc_fragment_byte_vector *expected,
		       bool complete, bool aborted)
{
	struct schc_reassembly_result result = { 0 };
	struct schc_reassembler before = *receiver;
	uint8_t wire[16];

	memset(wire, SENTINEL, sizeof(wire));
	CHECK(schc_reassembler_next(receiver, wire, 1, &result) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	CHECK(memcmp(receiver, &before, sizeof(*receiver)) == 0);
	CHECK(unchanged(wire, sizeof(wire)));
	int length = schc_reassembler_next(receiver, wire, sizeof(wire), &result);
	CHECK(expected != NULL && length == (int)expected->len);
	CHECK(memcmp(wire, expected->data, expected->len) == 0);
	CHECK(result.complete == complete);
	CHECK(result.aborted == aborted);
	return 0;
}

static int test_loss_recovery(void)
{
	const char *name = "recover_missing_regular_tile";
	const struct schc_fragment_scenario_vector *meta = scenario(name);
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	struct schc_reassembler receiver;
	struct schc_reassembly_result result = { 0 };

	CHECK(meta != NULL && packet != NULL && meta->drop_fragment != NULL);
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    packet->len) == SCHC_OK);
	for (size_t ordinal = 0; ordinal < meta->fragment_count; ordinal++) {
		const struct schc_fragment_fragment_vector *fragment =
			fragment_field(name, ordinal);
		CHECK(fragment != NULL);
		if (strcmp(fragment->name, meta->drop_fragment) != 0) {
			CHECK(schc_reassembler_input(&receiver, fragment->wire,
						 fragment->wire_len, &result) == SCHC_OK);
		}
	}
	CHECK(!result.complete);
	CHECK(!result.rcs_checked || !result.rcs_ok);
	CHECK(drain_exact(&receiver, field(name, "ack_failure"), false, false) == 0);
	const struct schc_fragment_byte_vector *retransmission =
		field(name, "retransmission");
	CHECK(schc_reassembler_input(&receiver, retransmission->data,
				     retransmission->len, &result) == SCHC_OK);
	const struct schc_fragment_byte_vector *ack_request = field(name, "ack_req");
	CHECK(schc_reassembler_input(&receiver, ack_request->data,
				     ack_request->len, &result) == SCHC_OK);
	CHECK(result.rcs_checked && result.rcs_ok);
	CHECK(drain_exact(&receiver, field(name, "ack_success"), true, false) == 0);
	CHECK(assert_packet(&receiver, packet->data, packet->len) == 0);
	return 0;
}

static int test_out_of_order_and_duplicates(void)
{
	const char *name = "recover_missing_regular_tile";
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_fragment_vector *first = fragment_field(name, 0);
	const struct schc_fragment_fragment_vector *second = fragment_field(name, 1);
	const struct schc_fragment_fragment_vector *final = fragment_field(name, 2);
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;

	CHECK(packet != NULL && first != NULL && second != NULL && final != NULL);
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    packet->len) == SCHC_OK);
	CHECK(schc_reassembler_input(&receiver, second->wire, second->wire_len,
				     &result) == SCHC_OK);
	CHECK(schc_reassembler_input(&receiver, first->wire, first->wire_len,
				     &result) == SCHC_OK);
	uint64_t bitmap = receiver.bitmap[0];
	CHECK(schc_reassembler_input(&receiver, first->wire, first->wire_len,
				     &result) == SCHC_OK);
	CHECK(receiver.bitmap[0] == bitmap && !result.aborted);
	CHECK(schc_reassembler_input(&receiver, final->wire, final->wire_len,
				     &result) == SCHC_OK);
	CHECK(result.rcs_checked && result.rcs_ok);
	CHECK(drain_exact(&receiver, field(name, "ack_success"), true, false) == 0);
	CHECK(assert_packet(&receiver, packet->data, packet->len) == 0);

	/* A conflicting retransmission for an occupied tile fails closed. */
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    packet->len) == SCHC_OK);
	CHECK(schc_reassembler_input(&receiver, first->wire, first->wire_len,
				     &result) == SCHC_OK);
	uint8_t conflicting[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	memcpy(conflicting, first->wire, first->wire_len);
	conflicting[10] ^= 0x02u;
	CHECK(schc_reassembler_input(&receiver, conflicting, first->wire_len,
				     &result) == SCHC_OK);
	CHECK(result.aborted);
	CHECK(drain_exact(&receiver, field("control_messages", "rule_78_receiver_abort"),
			 false, true) == 0);
	return 0;
}

static int test_rcs_failure(void)
{
	const char *name = "recover_missing_regular_tile";
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_byte_vector *corrupt = field(name, "corrupt_all1");
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;

	CHECK(packet != NULL && corrupt != NULL);
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    packet->len) == SCHC_OK);
	for (size_t ordinal = 0; ordinal < 2; ordinal++) {
		const struct schc_fragment_fragment_vector *fragment =
			fragment_field(name, ordinal);
		CHECK(schc_reassembler_input(&receiver, fragment->wire,
						 fragment->wire_len, &result) == SCHC_OK);
	}
	CHECK(schc_reassembler_input(&receiver, corrupt->data, corrupt->len,
				     &result) == SCHC_OK);
	CHECK(result.rcs_checked && !result.rcs_ok && !result.complete);
	CHECK(drain_exact(&receiver, field(name, "rcs_failure_ack"), false, false) == 0);
	return 0;
}

static int test_capacity_out_of_order(const char *name)
{
	const struct schc_fragment_scenario_vector *meta = scenario(name);
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	struct schc_fragmenter sender;
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	uint8_t response[16];

	CHECK(meta != NULL && packet != NULL);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   packet->data, packet->len,
				   SCHC_FRAGMENT_MAX_PACKET_SIZE) == SCHC_OK);
	CHECK(sender.fragment_count == meta->fragment_count);
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		int length = schc_fragmenter_next(&sender, generated[ordinal],
					   sizeof(generated[ordinal]));
		CHECK(length > 0);
		generated_len[ordinal] = (size_t)length;
	}
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    packet->len) == SCHC_OK);
	/* All regular tiles arrive in reverse order, across both windows. */
	for (size_t ordinal = sender.fragment_count - 1u; ordinal-- > 0u;) {
		CHECK(schc_reassembler_input(&receiver, generated[ordinal],
						 generated_len[ordinal], &result) == SCHC_OK);
		CHECK(!result.aborted);
	}
	size_t final = sender.fragment_count - 1u;
	CHECK(schc_reassembler_input(&receiver, generated[final], generated_len[final],
				     &result) == SCHC_OK);
	CHECK(result.rcs_checked && result.rcs_ok);
	int response_len = schc_reassembler_next(&receiver, response, sizeof(response),
						 &result);
	CHECK(response_len == 2 && result.complete && result.packet_len == packet->len);
	CHECK(assert_packet(&receiver, packet->data, packet->len) == 0);
	return 0;
}

static int test_memory_and_timeout(void)
{
	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE] = { 0 };
	struct schc_fragment fragment = {
		.tile = tile,
		.tile_len = sizeof(tile),
		.rule_id = SCHC_FRAGMENT_RULE_A_TO_B,
		.window = 0,
		.fcn = 54,
	};
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	struct schc_reassembler receiver;
	struct schc_reassembler before;
	struct schc_reassembly_result result;

	memset(&receiver, SENTINEL, sizeof(receiver));
	before = receiver;
	CHECK(schc_reassembler_init(&receiver, reassembled, 1280, 1281) ==
	      SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&receiver, &before, sizeof(receiver)) == 0);
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    SCHC_FRAGMENT_MAX_PACKET_SIZE + 1u) ==
	      SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&receiver, &before, sizeof(receiver)) == 0);

	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    1281) == SCHC_OK);
	int length = schc_fragment_encode(&fragment, wire, sizeof(wire));
	CHECK(length > 0);
	CHECK(schc_reassembler_input(&receiver, wire, (size_t)length, &result) ==
	      SCHC_OK);
	CHECK(result.aborted);
	CHECK(drain_exact(&receiver, field("control_messages", "rule_78_receiver_abort"),
			 false, true) == 0);

	const struct schc_fragment_fragment_vector *first =
		fragment_field("recover_missing_regular_tile", 0);
	CHECK(schc_reassembler_init(&receiver, reassembled, sizeof(reassembled),
				    1281) == SCHC_OK);
	CHECK(schc_reassembler_input(&receiver, first->wire, first->wire_len,
				     &result) == SCHC_OK);
	CHECK(schc_reassembler_expire(&receiver) == SCHC_OK);
	CHECK(drain_exact(&receiver, field("control_messages", "rule_78_receiver_abort"),
			 false, true) == 0);
	CHECK(schc_reassembler_expire(&receiver) == SCHC_ERR_DONE);
	return 0;
}

int main(void)
{
	CHECK(test_loss_recovery() == 0);
	CHECK(test_out_of_order_and_duplicates() == 0);
	CHECK(test_rcs_failure() == 0);
	CHECK(test_capacity_out_of_order("mandatory_receiver_boundary") == 0);
	CHECK(test_capacity_out_of_order("profile_capacity") == 0);
	CHECK(test_memory_and_timeout() == 0);
	printf("PASS: canonical SCHC reassembly state machine\n");
	return 0;
}
