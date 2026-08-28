/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/compact_cot_chat.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct chat_vector {
	const char *name;
	uint8_t destination_type;
	uint8_t team;
	uint8_t address[16];
	const uint8_t *message;
	uint8_t message_length;
	uint8_t wire[32];
	uint8_t wire_length;
};

static const uint8_t hello[] = "Hello";
static const uint8_t move_out[] = "Move out";
static const uint8_t hold_position[] = "Hold position";
static const uint8_t ack[] = "Ack";
static const uint8_t check_in[] = "Check in";
static const uint8_t utf8_message[] = {0xc3, 0xa9, 0xe4, 0xb8, 0xad,
				      0xf0, 0x9f, 0x99, 0x82};
static const uint8_t empty_message[] = {0};

/* Exact non-maximum chat cases from test/vectors/compact_cot.json. */
static const struct chat_vector vectors[] = {
	{
		.name = "broadcast_hello",
		.destination_type = LICHEN_COMPACT_COT_CHAT_BROADCAST,
		.message = hello,
		.message_length = 5,
		.wire = {0x01, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
		.wire_length = 8,
	},
	{
		.name = "team_blue_move",
		.destination_type = LICHEN_COMPACT_COT_CHAT_TEAM,
		.team = 1,
		.message = move_out,
		.message_length = 8,
		.wire = {0x01, 0x01, 0x01, 0x08, 0x4d, 0x6f, 0x76, 0x65,
			 0x20, 0x6f, 0x75, 0x74},
		.wire_length = 12,
	},
	{
		.name = "team_red_hold",
		.destination_type = LICHEN_COMPACT_COT_CHAT_TEAM,
		.team = 2,
		.message = hold_position,
		.message_length = 13,
		.wire = {0x01, 0x01, 0x02, 0x0d, 0x48, 0x6f, 0x6c, 0x64, 0x20,
			 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e},
		.wire_length = 17,
	},
	{
		.name = "direct_ack",
		.destination_type = LICHEN_COMPACT_COT_CHAT_DIRECT,
		.address = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
		.message = ack,
		.message_length = 3,
		.wire = {0x01, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			 0x03, 0x41, 0x63, 0x6b},
		.wire_length = 22,
	},
	{
		.name = "broadcast_empty",
		.destination_type = LICHEN_COMPACT_COT_CHAT_BROADCAST,
		.message = empty_message,
		.message_length = 0,
		.wire = {0x01, 0x00, 0x00},
		.wire_length = 3,
	},
	{
		.name = "team_yellow",
		.destination_type = LICHEN_COMPACT_COT_CHAT_TEAM,
		.team = 10,
		.message = check_in,
		.message_length = 8,
		.wire = {0x01, 0x01, 0x0a, 0x08, 0x43, 0x68, 0x65, 0x63,
			 0x6b, 0x20, 0x69, 0x6e},
		.wire_length = 12,
	},
	{
		.name = "broadcast_utf8",
		.destination_type = LICHEN_COMPACT_COT_CHAT_BROADCAST,
		.message = utf8_message,
		.message_length = sizeof(utf8_message),
		.wire = {0x01, 0x00, 0x09, 0xc3, 0xa9, 0xe4, 0xb8, 0xad,
			 0xf0, 0x9f, 0x99, 0x82},
		.wire_length = 12,
	},
	{
		.name = "direct_high_address",
		.destination_type = LICHEN_COMPACT_COT_CHAT_DIRECT,
		.address = {0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		.message = empty_message,
		.message_length = 0,
		.wire = {0x01, 0x02, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			 0x00},
		.wire_length = 19,
	},
};

static void vector_to_chat(const struct chat_vector *vector,
			   struct lichen_compact_cot_chat *chat)
{
	memset(chat, 0, sizeof(*chat));
	chat->destination_type = vector->destination_type;
	if (vector->destination_type == LICHEN_COMPACT_COT_CHAT_TEAM) {
		chat->destination.team = vector->team;
	} else if (vector->destination_type == LICHEN_COMPACT_COT_CHAT_DIRECT) {
		memcpy(chat->destination.address, vector->address,
		       sizeof(chat->destination.address));
	}
	chat->message_length = vector->message_length;
	memcpy(chat->message, vector->message, vector->message_length);
}

static bool chat_equal(const struct lichen_compact_cot_chat *left,
		       const struct lichen_compact_cot_chat *right)
{
	if (left->destination_type != right->destination_type ||
	    left->message_length != right->message_length ||
	    memcmp(left->message, right->message, left->message_length) != 0) {
		return false;
	}
	if (left->destination_type == LICHEN_COMPACT_COT_CHAT_TEAM) {
		return left->destination.team == right->destination.team;
	}
	if (left->destination_type == LICHEN_COMPACT_COT_CHAT_DIRECT) {
		return memcmp(left->destination.address, right->destination.address,
			      sizeof(left->destination.address)) == 0;
	}
	return true;
}

static bool bytes_are(const uint8_t *bytes, size_t size, uint8_t value)
{
	for (size_t i = 0; i < size; i++) {
		if (bytes[i] != value) {
			return false;
		}
	}
	return true;
}

static int test_canonical_vectors(void)
{
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		struct lichen_compact_cot_chat expected;
		struct lichen_compact_cot_chat decoded;
		uint8_t encoded[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
		int length;

		vector_to_chat(&vectors[i], &expected);
		memset(encoded, 0xa5, sizeof(encoded));
		length = lichen_compact_cot_chat_encode(&expected, encoded,
						       sizeof(encoded));
		if (length != vectors[i].wire_length ||
		    memcmp(encoded, vectors[i].wire, vectors[i].wire_length) != 0 ||
		    !bytes_are(&encoded[vectors[i].wire_length],
			       sizeof(encoded) - vectors[i].wire_length, 0xa5)) {
			fprintf(stderr, "%s: encode failed\n", vectors[i].name);
			return 1;
		}

		memset(&decoded, 0xa5, sizeof(decoded));
		if (lichen_compact_cot_chat_decode(vectors[i].wire,
						  vectors[i].wire_length,
						  &decoded) != 0 ||
		    !chat_equal(&decoded, &expected)) {
			fprintf(stderr, "%s: decode failed\n", vectors[i].name);
			return 1;
		}
	}

	return 0;
}

static int test_maximum_message(void)
{
	struct lichen_compact_cot_chat chat = {0};
	struct lichen_compact_cot_chat decoded;
	uint8_t wire[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
	int length;

	chat.destination_type = LICHEN_COMPACT_COT_CHAT_BROADCAST;
	chat.message_length = UINT8_MAX;
	memset(chat.message, 'a', sizeof(chat.message));
	length = lichen_compact_cot_chat_encode(&chat, wire, sizeof(wire));
	if (length != 258 || wire[0] != 0x01 || wire[1] != 0x00 ||
	    wire[2] != 0xff || !bytes_are(&wire[3], 255, 'a') ||
	    lichen_compact_cot_chat_decode(wire, (size_t)length, &decoded) != 0 ||
	    !chat_equal(&chat, &decoded)) {
		fprintf(stderr, "maximum message vector failed\n");
		return 1;
	}

	return 0;
}

static int expect_decode_error(const uint8_t *wire, size_t wire_size,
			       int expected)
{
	struct lichen_compact_cot_chat output;
	struct lichen_compact_cot_chat sentinel;

	memset(&output, 0xa5, sizeof(output));
	sentinel = output;
	if (lichen_compact_cot_chat_decode(wire, wire_size, &output) != expected ||
	    memcmp(&output, &sentinel, sizeof(output)) != 0) {
		return 1;
	}
	return 0;
}

static int test_canonical_rejections(void)
{
	static const struct {
		uint8_t wire[20];
		uint8_t length;
		int error;
	} invalid[] = {
		{{0x01, 0x03, 0x00}, 3, -EINVAL},
		{{0x01, 0x01, 0x00, 0x00}, 4, -EINVAL},
		{{0x01, 0x01, 0x0b, 0x00}, 4, -EINVAL},
		{{0x01, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, 17, -EMSGSIZE},
		{{0x01, 0x00, 0x02, 0x41}, 4, -EMSGSIZE},
		{{0x01, 0x00, 0x00, 0x00}, 4, -EMSGSIZE},
		{{0x01, 0x00, 0x01, 0xff}, 4, -EINVAL},
	};

	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		if (expect_decode_error(invalid[i].wire, invalid[i].length,
					invalid[i].error) != 0) {
			fprintf(stderr, "canonical rejection %zu failed\n", i);
			return 1;
		}
	}

	return 0;
}

static int test_utf8_and_reserved_rejections(void)
{
	static const struct {
		uint8_t bytes[4];
		uint8_t length;
	} invalid_utf8[] = {
		{{0x80}, 1},
		{{0xc0, 0x80}, 2},
		{{0xe0, 0x9f, 0xbf}, 3},
		{{0xed, 0xa0, 0x80}, 3},
		{{0xf0, 0x8f, 0xbf, 0xbf}, 4},
		{{0xf4, 0x90, 0x80, 0x80}, 4},
		{{0xf0, 0x9f, 0x99}, 3},
	};
	struct lichen_compact_cot_chat chat = {0};
	uint8_t output[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
	uint8_t wire[7];

	chat.destination_type = LICHEN_COMPACT_COT_CHAT_BROADCAST;
	for (size_t i = 0; i < sizeof(invalid_utf8) / sizeof(invalid_utf8[0]); i++) {
		chat.message_length = invalid_utf8[i].length;
		memcpy(chat.message, invalid_utf8[i].bytes, invalid_utf8[i].length);
		memset(output, 0xa5, sizeof(output));
		if (lichen_compact_cot_chat_encode(&chat, output, sizeof(output)) !=
			    -EINVAL ||
		    !bytes_are(output, sizeof(output), 0xa5)) {
			fprintf(stderr, "invalid UTF-8 encode %zu failed\n", i);
			return 1;
		}

		wire[0] = 0x01;
		wire[1] = 0x00;
		wire[2] = invalid_utf8[i].length;
		memcpy(&wire[3], invalid_utf8[i].bytes, invalid_utf8[i].length);
		if (expect_decode_error(wire, (size_t)invalid_utf8[i].length + 3U,
					-EINVAL) != 0) {
			fprintf(stderr, "invalid UTF-8 decode %zu failed\n", i);
			return 1;
		}
	}

	chat.message_length = 0;
	for (uint16_t type = 3; type <= UINT8_MAX; type++) {
		chat.destination_type = (uint8_t)type;
		memset(output, 0xa5, sizeof(output));
		if (lichen_compact_cot_chat_encode(&chat, output, sizeof(output)) !=
			    -EINVAL ||
		    !bytes_are(output, sizeof(output), 0xa5)) {
			fprintf(stderr, "reserved destination %u accepted\n", type);
			return 1;
		}
	}

	for (uint8_t team = 0; team <= 11; team = (uint8_t)(team + 11U)) {
		chat.destination_type = LICHEN_COMPACT_COT_CHAT_TEAM;
		chat.destination.team = team;
		if (lichen_compact_cot_chat_encode(&chat, output, sizeof(output)) !=
		    -EINVAL) {
			fprintf(stderr, "reserved team %u accepted\n", team);
			return 1;
		}
	}

	return 0;
}

static int test_lengths_null_and_overlap(void)
{
	union overlap {
		struct lichen_compact_cot_chat chat;
		uint8_t wire[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
	} overlap;
	struct lichen_compact_cot_chat direct;
	uint8_t output[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
	int required;

	_Static_assert(sizeof(overlap.wire) >= LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE,
		       "overlap storage must hold maximum chat datagram");

	vector_to_chat(&vectors[3], &direct);
	required = lichen_compact_cot_chat_encode(&direct, output, sizeof(output));
	if (required != vectors[3].wire_length) {
		return 1;
	}
	for (size_t size = 0; size < (size_t)required; size++) {
		memset(output, 0xa5, sizeof(output));
		if (lichen_compact_cot_chat_encode(&direct, output, size) != -EMSGSIZE ||
		    !bytes_are(output, sizeof(output), 0xa5)) {
			fprintf(stderr, "short output %zu was not atomic\n", size);
			return 1;
		}
	}

	for (size_t size = 0; size < vectors[3].wire_length; size++) {
		if (expect_decode_error(vectors[3].wire, size, -EMSGSIZE) != 0) {
			fprintf(stderr, "truncated input %zu was not atomic\n", size);
			return 1;
		}
	}
	if (expect_decode_error(NULL, 3, -EINVAL) != 0 ||
	    lichen_compact_cot_chat_decode(vectors[0].wire, vectors[0].wire_length,
					   NULL) != -EINVAL ||
	    lichen_compact_cot_chat_encode(NULL, output, sizeof(output)) != -EINVAL ||
	    lichen_compact_cot_chat_encode(&direct, NULL, sizeof(output)) != -EINVAL) {
		fprintf(stderr, "NULL behavior failed\n");
		return 1;
	}

	overlap.chat = direct;
	required = lichen_compact_cot_chat_encode(&overlap.chat, overlap.wire,
						   sizeof(overlap.wire));
	if (required != vectors[3].wire_length ||
	    memcmp(overlap.wire, vectors[3].wire, vectors[3].wire_length) != 0) {
		fprintf(stderr, "overlapping encode failed\n");
		return 1;
	}
	memcpy(overlap.wire, vectors[6].wire, vectors[6].wire_length);
	if (lichen_compact_cot_chat_decode(overlap.wire, vectors[6].wire_length,
					   &overlap.chat) != 0) {
		fprintf(stderr, "overlapping decode failed\n");
		return 1;
	}

	return 0;
}

int main(void)
{
	if (test_canonical_vectors() != 0 || test_maximum_message() != 0 ||
	    test_canonical_rejections() != 0 ||
	    test_utf8_and_reserved_rejections() != 0 ||
	    test_lengths_null_and_overlap() != 0) {
		return 1;
	}

	return 0;
}
