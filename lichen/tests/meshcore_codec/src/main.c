/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <lichen/meshcore/codec.h>

#include "meshcore_codec_vectors.h"

static void expect_bytes(const uint8_t *actual, size_t actual_len,
			 const uint8_t *expected, size_t expected_len)
{
	zassert_equal(actual_len, expected_len, "unexpected encoded length");
	zassert_mem_equal(actual, expected, expected_len, "unexpected encoded bytes");
}

ZTEST(meshcore_codec, test_generated_vectors_are_current)
{
	zassert_equal(MESHCORE_CODEC_VECTOR_SOURCE_COUNT, 36U);
	zassert_equal(MESHCORE_CODEC_VECTOR_COUNT,
		      ARRAY_SIZE(meshcore_codec_vectors));
	zassert_equal(MESHCORE_CODEC_VECTOR_COUNT, 36U);
	zassert_equal(MESHCORE_CODEC_ERROR_VECTOR_COUNT,
		      ARRAY_SIZE(meshcore_codec_error_vectors));
	zassert_equal(MESHCORE_CODEC_ERROR_VECTOR_COUNT, 15U);
}

ZTEST(meshcore_codec, test_canonical_inner_frame_vectors)
{
	for (size_t i = 0U; i < ARRAY_SIZE(meshcore_codec_vectors); i++) {
		const struct meshcore_codec_vector *v = &meshcore_codec_vectors[i];
		struct lichen_meshcore_frame_view view;
		int ret;

		if (v->kind == MESHCORE_CODEC_VECTOR_SERIAL) {
			continue;
		}

		ret = lichen_meshcore_decode_frame(v->encoded, v->encoded_len, &view);
		zassert_equal(ret, 0, "%s decode failed: %d", v->name, ret);
		zassert_equal(view.type, v->encoded[0], "%s wrong frame type", v->name);
		zassert_equal(view.payload_len, v->encoded_len - 1U,
			      "%s wrong payload length", v->name);
		if (view.payload_len > 0U) {
			zassert_mem_equal(view.payload, &v->encoded[1],
					  view.payload_len, "%s wrong payload", v->name);
		} else {
			zassert_is_null(view.payload, "%s payload should be NULL", v->name);
		}

		if (v->kind == MESHCORE_CODEC_VECTOR_COMMAND) {
			bool expected_known = v->encoded[0] >= 0x01U && v->encoded[0] <= 0x41U;

			zassert_equal(lichen_meshcore_command_known(view.type),
				      expected_known, "%s wrong command-known result", v->name);
		}
	}
}

ZTEST(meshcore_codec, test_canonical_serial_framing_vectors)
{
	for (size_t i = 0U; i < ARRAY_SIZE(meshcore_codec_vectors); i++) {
		const struct meshcore_codec_vector *v = &meshcore_codec_vectors[i];
		uint8_t out[LICHEN_MESHCORE_FRAME_MAX + 3U];
		int ret;

		if (v->kind != MESHCORE_CODEC_VECTOR_SERIAL) {
			continue;
		}

		ret = lichen_meshcore_encode_serial_frame(v->serial_marker,
							 v->serial_payload,
							 v->serial_payload_len,
							 out, sizeof(out));
		zassert_true(ret > 0, "%s serial encode failed: %d", v->name, ret);
		expect_bytes(out, (size_t)ret, v->encoded, v->encoded_len);
	}
}

ZTEST(meshcore_codec, test_canonical_error_response_encoder_vectors)
{
	for (size_t i = 0U; i < ARRAY_SIZE(meshcore_codec_error_vectors); i++) {
		const struct meshcore_codec_error_vector *v =
			&meshcore_codec_error_vectors[i];
		uint8_t out[2];
		int ret;

		ret = lichen_meshcore_encode_error(v->error_code, out, sizeof(out));
		zassert_true(ret > 0, "%s error encode failed: %d", v->name, ret);
		expect_bytes(out, (size_t)ret, v->encoded, v->encoded_len);
	}
}

ZTEST(meshcore_codec, test_ok_response_encoder)
{
	uint8_t out[1];
	const uint8_t expected[] = { LICHEN_MESHCORE_RESP_OK };
	int ret;

	ret = lichen_meshcore_encode_ok(out, sizeof(out));
	zassert_equal(ret, sizeof(expected), "OK response encode failed: %d", ret);
	expect_bytes(out, (size_t)ret, expected, sizeof(expected));
}

ZTEST(meshcore_codec, test_decode_rejects_malformed_and_oversized_frames)
{
	struct lichen_meshcore_frame_view view;
	uint8_t oversized[LICHEN_MESHCORE_FRAME_MAX + 1U];
	const uint8_t frame[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };

	memset(oversized, 0xa5, sizeof(oversized));

	zassert_equal(lichen_meshcore_decode_frame(NULL, sizeof(frame), &view),
		      -EINVAL);
	zassert_equal(lichen_meshcore_decode_frame(frame, sizeof(frame), NULL),
		      -EINVAL);
	zassert_equal(lichen_meshcore_decode_frame(frame, 0U, &view), -EINVAL);
	zassert_equal(lichen_meshcore_decode_frame(oversized, sizeof(oversized),
						   &view), -EINVAL);
}

ZTEST(meshcore_codec, test_serial_encoder_rejects_malformed_and_oversized_frames)
{
	uint8_t out[LICHEN_MESHCORE_FRAME_MAX + 3U];
	uint8_t payload[CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD + 1U];
	const uint8_t one_byte_payload[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };

	memset(payload, 0x5a, sizeof(payload));

	zassert_equal(lichen_meshcore_encode_serial_frame(
			      0x99U, one_byte_payload, sizeof(one_byte_payload),
			      out, sizeof(out)),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      one_byte_payload, 0U, out, sizeof(out)),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      one_byte_payload, sizeof(one_byte_payload), NULL,
			      sizeof(one_byte_payload) + 3U),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      NULL, sizeof(one_byte_payload), out, sizeof(out)),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      one_byte_payload, sizeof(one_byte_payload), out, 3U),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      payload, sizeof(payload), out, sizeof(out)),
		      -EINVAL);
}

ZTEST(meshcore_codec, test_command_known_boundaries)
{
	zassert_false(lichen_meshcore_command_known(0x00U));
	zassert_true(lichen_meshcore_command_known(0x01U));
	zassert_true(lichen_meshcore_command_known(0x3cU));
	zassert_true(lichen_meshcore_command_known(0x3eU));
	zassert_true(lichen_meshcore_command_known(0x41U));
	zassert_false(lichen_meshcore_command_known(0x42U));
	zassert_false(lichen_meshcore_command_known(0xffU));
}

ZTEST(meshcore_codec, test_response_encoder_bounds)
{
	uint8_t out[2];

	zassert_equal(lichen_meshcore_encode_error(LICHEN_MESHCORE_ERR_NOT_FOUND,
						   NULL, sizeof(out)), -ENOMEM);
	zassert_equal(lichen_meshcore_encode_error(LICHEN_MESHCORE_ERR_NOT_FOUND,
						   out, 1U), -ENOMEM);
	zassert_equal(lichen_meshcore_encode_ok(NULL, 1U), -ENOMEM);
	zassert_equal(lichen_meshcore_encode_ok(out, 0U), -ENOMEM);
}

ZTEST_SUITE(meshcore_codec, NULL, NULL, NULL, NULL, NULL);
