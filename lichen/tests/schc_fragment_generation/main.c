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

static int verify_fragment(const struct schc_fragmenter *sender, size_t ordinal,
			   const uint8_t *wire, size_t wire_len,
			   const struct schc_fragment_fragment_vector *literal)
{
	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];
	struct schc_fragment decoded;
	int consumed = schc_fragment_decode(&decoded, wire, wire_len,
					    tile, sizeof(tile));

	CHECK(consumed == (int)wire_len);
	CHECK(decoded.rule_id == sender->rule_id);
	CHECK(decoded.window == ordinal / SCHC_FRAGMENT_WINDOW_SIZE);
	bool final = ordinal + 1u == sender->fragment_count;
	uint8_t expected_fcn = final ? SCHC_ALL_1 :
		(uint8_t)(62u - ordinal % SCHC_FRAGMENT_WINDOW_SIZE);
	CHECK(decoded.fcn == expected_fcn);
	size_t offset = ordinal * SCHC_FRAGMENT_TILE_SIZE;
	size_t remaining = sender->packet_len - offset;
	size_t expected_tile_len = remaining < SCHC_FRAGMENT_TILE_SIZE ?
		remaining : SCHC_FRAGMENT_TILE_SIZE;
	CHECK(decoded.tile_len == expected_tile_len);
	CHECK(memcmp(decoded.tile, &sender->packet[offset], expected_tile_len) == 0);
	if (literal != NULL) {
		CHECK(wire_len == literal->wire_len);
		CHECK(memcmp(wire, literal->wire, wire_len) == 0);
		CHECK(decoded.window == literal->window);
		CHECK(decoded.fcn == literal->fcn);
	}
	return 0;
}

static int verify_generation_scenario(const char *name)
{
	const struct schc_fragment_scenario_vector *meta = scenario(name);
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_byte_vector *rcs = field(name, "rcs");
	struct schc_fragmenter sender;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	CHECK(meta != NULL && packet != NULL && rcs != NULL);
	CHECK(packet->len == meta->packet_len);
	CHECK(schc_fragmenter_init(&sender, meta->rule_id, packet->data,
				   packet->len, packet->len) == SCHC_OK);
	CHECK(sender.fragment_count == meta->fragment_count);
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		const struct schc_fragment_fragment_vector *literal =
			fragment_field(name, ordinal);
		struct schc_fragmenter before = sender;

		memset(wire, SENTINEL, sizeof(wire));
		CHECK(schc_fragmenter_next(&sender, wire, 1) ==
		      SCHC_ERR_BUFFER_TOO_SMALL);
		CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
		CHECK(unchanged(wire, sizeof(wire)));

		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
		CHECK(length > 0);
		CHECK(verify_fragment(&before, ordinal, wire, (size_t)length,
				      literal) == 0);
		if (ordinal + 1u == sender.fragment_count) {
			uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];
			struct schc_fragment decoded;
			CHECK(schc_fragment_decode(&decoded, wire, (size_t)length,
						   tile, sizeof(tile)) == length);
			CHECK(rcs->len == sizeof(decoded.rcs));
			CHECK(memcmp(decoded.rcs, rcs->data, rcs->len) == 0);
		}
	}
	CHECK(sender.status == SCHC_SENDER_ACTIVE);
	CHECK(sender.attempts == 1u);
	CHECK(schc_fragmenter_next(&sender, wire, sizeof(wire)) == SCHC_ERR_DONE);
	return 0;
}

static int verify_capacity(const char *name, bool expect_success)
{
	const struct schc_fragment_scenario_vector *meta = scenario(name);
	const struct schc_fragment_byte_vector *packet = field(name, "packet");
	const struct schc_fragment_byte_vector *rcs = field(name, "rcs");
	struct schc_fragmenter sender;
	struct schc_fragmenter before;
	uint8_t wire[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];

	CHECK(meta != NULL && packet != NULL);
	memset(&sender, SENTINEL, sizeof(sender));
	before = sender;
	int result = schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
					  packet->data, packet->len,
					  SCHC_FRAGMENT_MAX_PACKET_SIZE);
	if (!expect_success) {
		CHECK(result == SCHC_ERR_BUFFER_TOO_SMALL);
		CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
		CHECK(meta->fragment_count == 0u && rcs == NULL);
		return 0;
	}
	CHECK(result == SCHC_OK);
	CHECK(sender.fragment_count == meta->fragment_count);
	for (size_t ordinal = 0; ordinal < sender.fragment_count; ordinal++) {
		int length = schc_fragmenter_next(&sender, wire, sizeof(wire));
		CHECK(length > 0);
		CHECK(verify_fragment(&sender, ordinal, wire, (size_t)length,
				      fragment_field(name, ordinal)) == 0);
		if (ordinal + 1u == sender.fragment_count) {
			uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];
			struct schc_fragment decoded;
			CHECK(rcs != NULL && rcs->len == sizeof(decoded.rcs));
			CHECK(schc_fragment_decode(&decoded, wire, (size_t)length,
						   tile, sizeof(tile)) == length);
			CHECK(memcmp(decoded.rcs, rcs->data, rcs->len) == 0);
		}
	}
	return 0;
}

static int verify_init_rejections_are_atomic(void)
{
	uint8_t packet = 0;
	struct schc_fragmenter sender;
	struct schc_fragmenter before;

	memset(&sender, SENTINEL, sizeof(sender));
	before = sender;
	CHECK(schc_fragmenter_init(&sender, 0x77, &packet, 1, 1) ==
	      SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   &packet, 0, 1) == SCHC_ERR_TOO_SHORT);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   &packet, 1, 0) == SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	CHECK(schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B,
				   &packet, 1,
				   SCHC_FRAGMENT_MAX_PACKET_SIZE + 1u) ==
	      SCHC_ERR_INVALID_ARGUMENT);
	CHECK(memcmp(&sender, &before, sizeof(sender)) == 0);
	return 0;
}

int main(void)
{
	_Static_assert(SCHC_FRAGMENT_TILE_SIZE == 179u, "canonical tile size drift");
	_Static_assert(SCHC_FRAGMENT_MAX_TILES == 126u, "tile count drift");
	_Static_assert(SCHC_FRAGMENT_MAX_PACKET_SIZE == 22554u,
		       "profile capacity drift");
	CHECK(verify_generation_scenario("recover_missing_regular_tile") == 0);
	CHECK(verify_generation_scenario("all0_window_transition") == 0);
	CHECK(verify_capacity("mandatory_receiver_boundary", true) == 0);
	CHECK(verify_capacity("profile_capacity", true) == 0);
	CHECK(verify_capacity("over_profile_capacity", false) == 0);
	CHECK(verify_init_rejections_are_atomic() == 0);
	printf("PASS: canonical SCHC fragment generation vectors\n");
	return 0;
}
