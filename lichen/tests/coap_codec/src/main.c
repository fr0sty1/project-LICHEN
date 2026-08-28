/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifdef __ZEPHYR__
#include <zephyr/ztest.h>
#else
#include <assert.h>
#endif

#include <lichen/coap_codec.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "coap_vectors.h"

#ifdef __ZEPHYR__
#define CHECK(condition) zassert_true((condition), "check failed: " #condition)
#else
#define CHECK(condition) assert(condition)
#endif

static void check_parse_unchanged(const uint8_t *wire, size_t wire_len,
				  int expected)
{
	struct lichen_coap_packet packet;
	struct lichen_coap_packet before;

	memset(&packet, 0xa5, sizeof(packet));
	memcpy(&before, &packet, sizeof(before));
	CHECK(lichen_coap_parse(wire, wire_len, &packet) == expected);
	CHECK(memcmp(&packet, &before, sizeof(packet)) == 0);
}

static void canonical_vectors_impl(void)
{
	uint8_t encoded[384];

	for (size_t i = 0U; i < sizeof(coap_vectors) / sizeof(coap_vectors[0]); i++) {
		const struct coap_vector *vector = &coap_vectors[i];
		struct lichen_coap_packet packet;
		size_t encoded_len = sizeof(encoded);

		(void)vector->name;
		CHECK(lichen_coap_parse(vector->wire, vector->wire_len, &packet) == 0);
		CHECK((uint8_t)packet.type == vector->type);
		CHECK(packet.code == vector->code);
		CHECK(packet.message_id == vector->mid);
		CHECK(packet.token_len == vector->token_len);
		CHECK(packet.payload_len == vector->payload_len);
		CHECK(packet.token_len == 0U ||
		      memcmp(packet.token, vector->token, packet.token_len) == 0);
		CHECK(packet.payload_len == 0U ||
		      memcmp(packet.payload, vector->payload, packet.payload_len) == 0);

		CHECK(lichen_coap_serialize(&packet, encoded, &encoded_len) == 0);
		CHECK(encoded_len == vector->wire_len);
		CHECK(memcmp(encoded, vector->wire, encoded_len) == 0);
	}
}

static void extended_options_impl(void)
{
	static const uint8_t delta_13[] = { 0x40, 0x01, 0x00, 0x01, 0xd0, 0x00 };
	static const uint8_t delta_269[] = { 0x40, 0x01, 0x00, 0x01, 0xe0, 0x00, 0x00 };
	static const uint8_t option_zero[] = { 0x40, 0x01, 0x00, 0x01, 0x00 };
	uint8_t length_13[4U + 2U + 13U] = { 0x40, 0x01, 0x00, 0x01, 0x0d, 0x00 };
	uint8_t length_269[4U + 3U + 269U] = { 0x40, 0x01, 0x00, 0x01, 0x0e, 0x00, 0x00 };
	struct lichen_coap_packet packet;
	uint8_t encoded[sizeof(length_269)];
	size_t encoded_len;

	memset(&length_13[6], 0x13, 13U);
	memset(&length_269[7], 0x69, 269U);

	CHECK(lichen_coap_parse(delta_13, sizeof(delta_13), &packet) == 0);
	CHECK(packet.option_count == 1U && packet.options[0].number == 13U);
	CHECK(lichen_coap_parse(delta_269, sizeof(delta_269), &packet) == 0);
	CHECK(packet.option_count == 1U && packet.options[0].number == 269U);
	CHECK(lichen_coap_parse(option_zero, sizeof(option_zero), &packet) == 0);
	CHECK(packet.option_count == 1U && packet.options[0].number == 0U &&
	      packet.options[0].length == 0U);
	CHECK(lichen_coap_parse(length_13, sizeof(length_13), &packet) == 0);
	CHECK(packet.options[0].length == 13U);
	encoded_len = sizeof(encoded);
	CHECK(lichen_coap_serialize(&packet, encoded, &encoded_len) == 0);
	CHECK(encoded_len == sizeof(length_13));
	CHECK(memcmp(encoded, length_13, encoded_len) == 0);
	CHECK(lichen_coap_parse(length_269, sizeof(length_269), &packet) == 0);
	CHECK(packet.options[0].length == 269U);
	encoded_len = sizeof(encoded);
	CHECK(lichen_coap_serialize(&packet, encoded, &encoded_len) == 0);
	CHECK(encoded_len == sizeof(length_269));
	CHECK(memcmp(encoded, length_269, encoded_len) == 0);
}

static void malformed_and_atomic_parse_impl(void)
{
	static const uint8_t too_short[] = { 0x40, 0x01, 0x00 };
	static const uint8_t wrong_version[] = { 0x00, 0x01, 0x00, 0x01 };
	static const uint8_t tkl_too_long[] = { 0x49, 0x01, 0x00, 0x01 };
	static const uint8_t token_truncated[] = { 0x42, 0x01, 0x00, 0x01, 0xaa };
	static const uint8_t delta_reserved[] = { 0x40, 0x01, 0x00, 0x01, 0xf0 };
	static const uint8_t length_reserved[] = { 0x40, 0x01, 0x00, 0x01, 0x0f };
	static const uint8_t delta_truncated[] = { 0x40, 0x01, 0x00, 0x01, 0xd0 };
	static const uint8_t length_truncated[] = { 0x40, 0x01, 0x00, 0x01, 0x0e, 0x00 };
	static const uint8_t value_truncated[] = {
		0x40, 0x01, 0x00, 0x01, 0x0a, 1, 2, 3, 4, 5
	};
	static const uint8_t number_overflow[] = {
		0x40, 0x01, 0x00, 0x01, 0xe0, 0xff, 0xff
	};
	static const uint8_t empty_payload[] = { 0x40, 0x01, 0x00, 0x01, 0xff };
	static const uint8_t nonempty_empty_code[] = { 0x41, 0x00, 0x00, 0x01, 0xaa };
	uint8_t too_many[4U + LICHEN_COAP_OPTIONS_MAX + 1U] = {
		0x40, 0x01, 0x00, 0x01
	};

	check_parse_unchanged(too_short, sizeof(too_short), -EBADMSG);
	check_parse_unchanged(wrong_version, sizeof(wrong_version), -EBADMSG);
	check_parse_unchanged(tkl_too_long, sizeof(tkl_too_long), -EBADMSG);
	check_parse_unchanged(token_truncated, sizeof(token_truncated), -EBADMSG);
	check_parse_unchanged(delta_reserved, sizeof(delta_reserved), -EBADMSG);
	check_parse_unchanged(length_reserved, sizeof(length_reserved), -EBADMSG);
	check_parse_unchanged(delta_truncated, sizeof(delta_truncated), -EBADMSG);
	check_parse_unchanged(length_truncated, sizeof(length_truncated), -EBADMSG);
	check_parse_unchanged(value_truncated, sizeof(value_truncated), -EBADMSG);
	check_parse_unchanged(number_overflow, sizeof(number_overflow), -EOVERFLOW);
	check_parse_unchanged(empty_payload, sizeof(empty_payload), -EBADMSG);
	check_parse_unchanged(nonempty_empty_code, sizeof(nonempty_empty_code),
			      -EBADMSG);
	check_parse_unchanged(too_many, sizeof(too_many), -E2BIG);
}

static void serializer_rejection_is_atomic_impl(void)
{
	static const uint8_t token[LICHEN_COAP_TOKEN_MAX + 1U] = { 0 };
	static const uint8_t value = 0xaa;
	struct lichen_coap_packet packet = {
		.type = LICHEN_COAP_TYPE_CON,
		.code = 1U,
		.message_id = 0x1234U,
		.option_count = 2U,
		.options = {
			{ .number = 12U, .value = &value, .length = 1U },
			{ .number = 11U, .value = &value, .length = 1U },
		},
	};
	uint8_t out[32];
	uint8_t before[sizeof(out)];
	size_t out_len;

	memset(out, 0x5a, sizeof(out));
	memcpy(before, out, sizeof(out));
	out_len = sizeof(out);
	CHECK(lichen_coap_serialize(&packet, out, &out_len) == -EINVAL);
	CHECK(out_len == sizeof(out));
	CHECK(memcmp(out, before, sizeof(out)) == 0);

	packet.option_count = 0U;
	packet.token = token;
	packet.token_len = sizeof(token);
	CHECK(lichen_coap_serialize(&packet, out, &out_len) == -EINVAL);
	CHECK(memcmp(out, before, sizeof(out)) == 0);

	packet.token_len = 0U;
	out_len = 3U;
	CHECK(lichen_coap_serialize(&packet, out, &out_len) == -ENOMEM);
	CHECK(out_len == 3U);
	CHECK(memcmp(out, before, sizeof(out)) == 0);
}

#ifdef __ZEPHYR__
ZTEST(coap_codec, test_canonical_vectors) { canonical_vectors_impl(); }
ZTEST(coap_codec, test_extended_options) { extended_options_impl(); }
ZTEST(coap_codec, test_malformed_and_atomic_parse) { malformed_and_atomic_parse_impl(); }
ZTEST(coap_codec, test_serializer_rejection_is_atomic) { serializer_rejection_is_atomic_impl(); }
ZTEST_SUITE(coap_codec, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	canonical_vectors_impl();
	extended_options_impl();
	malformed_and_atomic_parse_impl();
	serializer_rejection_is_atomic_impl();
	return 0;
}
#endif
