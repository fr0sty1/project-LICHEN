/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <lichen/meshtastic/codec.h>

#include "meshtastic_vectors.h"

static void expect_bytes(const uint8_t *actual, size_t actual_len,
			 const uint8_t *expected, size_t expected_len)
{
	zassert_equal(actual_len, expected_len, "unexpected encoded length");
	zassert_mem_equal(actual, expected, expected_len, "unexpected encoded bytes");
}

static int read_varint(const uint8_t *buf, size_t len, size_t *pos,
		       uint32_t *value)
{
	uint32_t out = 0U;
	uint8_t shift = 0U;

	while (*pos < len && shift < 32U) {
		uint8_t byte = buf[(*pos)++];

		out |= (uint32_t)(byte & 0x7fU) << shift;
		if ((byte & 0x80U) == 0U) {
			*value = out;
			return 0;
		}
		shift += 7U;
	}

	return -EINVAL;
}

static int read_varint64(const uint8_t *buf, size_t len, size_t *pos,
			 uint64_t *value)
{
	uint64_t out = 0U;
	uint8_t shift = 0U;

	while (*pos < len && shift < 64U) {
		uint8_t byte = buf[(*pos)++];

		out |= (uint64_t)(byte & 0x7fU) << shift;
		if ((byte & 0x80U) == 0U) {
			*value = out;
			return 0;
		}
		shift += 7U;
	}

	return -EINVAL;
}

static bool payload_has_string(const uint8_t *buf, size_t len, uint32_t field,
			       const char *value)
{
	size_t pos = 0U;
	size_t value_len = strlen(value);

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			if ((key >> 3) == field && n == value_len &&
			    memcmp(&buf[pos], value, value_len) == 0) {
				return true;
			}
			pos += n;
		} else if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_get_varint_field(const uint8_t *buf, size_t len,
				     uint32_t field, uint32_t *value)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = n;
				return true;
			}
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			pos += n;
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_get_varint64_field(const uint8_t *buf, size_t len,
				       uint32_t field, uint64_t *value)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint64_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 0U) {
			if (read_varint64(buf, len, &pos, &n) < 0) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = n;
				return true;
			}
		} else if ((key & 0x07U) == 2U) {
			uint32_t n32;

			if (read_varint(buf, len, &pos, &n32) < 0 ||
			    n32 > len - pos) {
				return false;
			}
			pos += n32;
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_get_len_field(const uint8_t *buf, size_t len, uint32_t field,
				  const uint8_t **value, size_t *value_len)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = &buf[pos];
				*value_len = n;
				return true;
			}
			pos += n;
		} else if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_get_fixed32_field(const uint8_t *buf, size_t len,
				      uint32_t field, uint32_t *value)
{
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			if ((key >> 3) == field) {
				*value = (uint32_t)buf[pos] |
					 ((uint32_t)buf[pos + 1U] << 8) |
					 ((uint32_t)buf[pos + 2U] << 16) |
					 ((uint32_t)buf[pos + 3U] << 24);
				return true;
			}
			pos += 4U;
		} else if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			pos += n;
		} else {
			return false;
		}
	}
	return false;
}

static bool payload_count_fields(const uint8_t *buf, size_t len, uint8_t *counts,
				 size_t counts_len)
{
	size_t pos = 0U;

	memset(counts, 0, counts_len);
	while (pos < len) {
		uint32_t key;
		uint32_t field;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		field = key >> 3;
		if (field == 0U || field >= counts_len || counts[field] == UINT8_MAX) {
			return false;
		}
		counts[field]++;
		if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			pos += n;
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return true;
}

static bool payload_has_only_metadata_fields(const uint8_t *buf, size_t len)
{
	bool seen[13] = { false };
	size_t pos = 0U;

	while (pos < len) {
		uint32_t key;
		uint32_t field;
		uint32_t n;

		if (read_varint(buf, len, &pos, &key) < 0) {
			return false;
		}
		field = key >> 3;
		if (field < 1U || field > 12U) {
			return false;
		}
		if (seen[field]) {
			return false;
		}
		seen[field] = true;
		if ((key & 0x07U) == 0U) {
			if (read_varint(buf, len, &pos, &n) < 0) {
				return false;
			}
		} else if ((key & 0x07U) == 2U) {
			if (read_varint(buf, len, &pos, &n) < 0 || n > len - pos) {
				return false;
			}
			pos += n;
		} else if ((key & 0x07U) == 5U) {
			if (len - pos < 4U) {
				return false;
			}
			pos += 4U;
		} else {
			return false;
		}
	}
	return true;
}

static void assert_metadata_varint(const uint8_t *buf, size_t len,
				   uint32_t field, uint32_t expected)
{
	uint32_t value = 0U;

	zassert_true(payload_get_varint_field(buf, len, field, &value),
		     "missing DeviceMetadata field %u", field);
	zassert_equal(value, expected, "DeviceMetadata field %u", field);
}

static void assert_metadata_payload(const uint8_t *buf, size_t len,
				    const char *firmware_version,
				    uint32_t has_bluetooth,
				    uint32_t excluded_modules)
{
	zassert_true(payload_has_only_metadata_fields(buf, len));
	zassert_true(payload_has_string(buf, len, 1U, firmware_version));
	assert_metadata_varint(buf, len, 2U, 1U);
	assert_metadata_varint(buf, len, 3U, 0U);
	assert_metadata_varint(buf, len, 4U, 0U);
	assert_metadata_varint(buf, len, 5U, has_bluetooth);
	assert_metadata_varint(buf, len, 6U, 0U);
	assert_metadata_varint(buf, len, 7U, 0U);
	assert_metadata_varint(buf, len, 8U, 0U);
	assert_metadata_varint(buf, len, 9U, 255U);
	assert_metadata_varint(buf, len, 10U, 0U);
	assert_metadata_varint(buf, len, 11U, 0U);
	assert_metadata_varint(buf, len, 12U, excluded_modules);
}

ZTEST(meshtastic_codec, test_generated_vectors_are_current)
{
	zassert_equal(MESHTASTIC_VECTOR_SOURCE_COUNT, 16U);
	zassert_equal(MESHTASTIC_VECTOR_CODEC_COUNT, ARRAY_SIZE(meshtastic_vectors));
	zassert_equal(MESHTASTIC_VECTOR_CODEC_COUNT, 14U);
}

ZTEST(meshtastic_codec, test_canonical_codec_vectors)
{
	for (size_t i = 0U; i < ARRAY_SIZE(meshtastic_vectors); i++) {
		const struct meshtastic_vector *v = &meshtastic_vectors[i];
		struct lichen_meshtastic_to_radio to_radio;
		struct lichen_meshtastic_queue_status status;
		uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
		int ret;

		switch (v->kind) {
		case MESHTASTIC_VECTOR_TO_HEARTBEAT:
			ret = lichen_meshtastic_decode_to_radio(v->encoded, v->encoded_len,
								&to_radio);
			zassert_equal(ret, 0, "%s decode failed: %d", v->name, ret);
			zassert_equal(to_radio.type, LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT,
				      "%s wrong type", v->name);
			break;
		case MESHTASTIC_VECTOR_TO_WANT_CONFIG_ID:
			ret = lichen_meshtastic_decode_to_radio(v->encoded, v->encoded_len,
								&to_radio);
			zassert_equal(ret, 0, "%s decode failed: %d", v->name, ret);
			zassert_equal(to_radio.type,
				      LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID,
				      "%s wrong type", v->name);
			zassert_equal(to_radio.value.want_config_id, v->value,
				      "%s wrong nonce", v->name);
			ret = lichen_meshtastic_encode_from_radio_config_complete(v->value,
										  buf,
										  sizeof(buf));
			zassert_true(ret > 0, "%s config_complete failed: %d", v->name, ret);
			expect_bytes(buf, (size_t)ret, v->payload, v->payload_len);
			break;
		case MESHTASTIC_VECTOR_TO_PACKET:
			ret = lichen_meshtastic_decode_to_radio(v->encoded, v->encoded_len,
								&to_radio);
			zassert_equal(ret, 0, "%s decode failed: %d", v->name, ret);
			zassert_equal(to_radio.type, LICHEN_MESHTASTIC_TO_RADIO_PACKET,
				      "%s wrong type", v->name);
			zassert_not_null(to_radio.value.packet.data, "%s packet missing",
					 v->name);
			zassert_true(to_radio.value.packet.len > 0U, "%s packet empty",
				     v->name);
			break;
		case MESHTASTIC_VECTOR_TO_REJECT:
			ret = lichen_meshtastic_decode_to_radio(v->encoded, v->encoded_len,
								&to_radio);
			if (v->expected_error == -90) {
				zassert_equal(ret, -EMSGSIZE, "%s wrong error: %d",
					      v->name, ret);
			} else {
				zassert_equal(ret, v->expected_error,
					      "%s wrong error: %d", v->name, ret);
			}
			break;
		case MESHTASTIC_VECTOR_FROM_QUEUE_STATUS:
			status = (struct lichen_meshtastic_queue_status){
				.res = v->res,
				.free = v->free,
				.maxlen = v->maxlen,
				.mesh_packet_id = v->mesh_packet_id,
				.has_res = true,
				.has_mesh_packet_id = true,
			};
			ret = lichen_meshtastic_encode_from_radio_queue_status(&status, buf,
									       sizeof(buf));
			zassert_true(ret > 0, "%s queueStatus failed: %d", v->name, ret);
			expect_bytes(buf, (size_t)ret, v->encoded, v->encoded_len);
			break;
		case MESHTASTIC_VECTOR_FROM_MODULE_CONFIG:
			ret = lichen_meshtastic_encode_from_radio_message(
				LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG,
				v->payload, v->payload_len, buf, sizeof(buf));
			zassert_true(ret > 0, "%s moduleConfig failed: %d", v->name, ret);
			expect_bytes(buf, (size_t)ret, v->encoded, v->encoded_len);
			break;
		case MESHTASTIC_VECTOR_FROM_REGION_PRESETS:
			ret = lichen_meshtastic_encode_from_radio_message(
				LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS,
				v->payload, v->payload_len, buf, sizeof(buf));
			zassert_true(ret > 0, "%s region_presets failed: %d", v->name, ret);
			expect_bytes(buf, (size_t)ret, v->encoded, v->encoded_len);
			break;
		case MESHTASTIC_VECTOR_FROM_PACKET:
			ret = lichen_meshtastic_encode_from_radio_packet(v->value, v->payload,
									 v->payload_len, buf,
									 sizeof(buf));
			zassert_true(ret > 0, "%s packet encode failed: %d", v->name, ret);
			expect_bytes(buf, (size_t)ret, v->encoded, v->encoded_len);
			break;
		}
	}
}

ZTEST(meshtastic_codec, test_decode_want_config_id)
{
	const uint8_t frame[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct lichen_meshtastic_to_radio msg;

	zassert_equal(lichen_meshtastic_decode_to_radio(frame, sizeof(frame), &msg),
		      0, "want_config_id should decode");
	zassert_equal(msg.type, LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID);
	zassert_equal(msg.value.want_config_id, 69420U);
}

ZTEST(meshtastic_codec, test_decode_heartbeat)
{
	const uint8_t frame[] = { 0x3a, 0x00 };
	struct lichen_meshtastic_to_radio msg;

	zassert_equal(lichen_meshtastic_decode_to_radio(frame, sizeof(frame), &msg),
		      0, "heartbeat should decode");
	zassert_equal(msg.type, LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT);
}

ZTEST(meshtastic_codec, test_decode_packet_view)
{
	const uint8_t frame[] = { 0x0a, 0x03, 0x01, 0x02, 0x03 };
	struct lichen_meshtastic_to_radio msg;

	zassert_equal(lichen_meshtastic_decode_to_radio(frame, sizeof(frame), &msg),
		      0, "packet should decode");
	zassert_equal(msg.type, LICHEN_MESHTASTIC_TO_RADIO_PACKET);
	zassert_equal(msg.value.packet.len, 3U);
	zassert_mem_equal(msg.value.packet.data, &frame[2], 3U);
}

ZTEST(meshtastic_codec, test_decode_rejects_invalid_inputs)
{
	uint8_t oversized[LICHEN_MESHTASTIC_TO_RADIO_MAX + 1U] = { 0 };
	const uint8_t malformed_varint[] = { 0x18, 0x80 };
	const uint8_t overflowing_varint[] = {
		0x18, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x02
	};
	const uint8_t multiple_oneof[] = { 0x18, 0xac, 0x9e, 0x04, 0x3a, 0x00 };
	const uint8_t unknown_only[] = { 0x28, 0x01 };
	const uint8_t oversized_field_key[] = {
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01
	};
	const uint8_t unknown_fixed64_only[] = {
		0x29, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	};
	struct lichen_meshtastic_to_radio msg;

	zassert_equal(lichen_meshtastic_decode_to_radio(NULL, 0U, &msg), -EINVAL);
	zassert_equal(lichen_meshtastic_decode_to_radio(oversized, sizeof(oversized), &msg),
		      -EMSGSIZE);
	zassert_equal(lichen_meshtastic_decode_to_radio(malformed_varint,
							sizeof(malformed_varint), &msg),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_decode_to_radio(overflowing_varint,
							sizeof(overflowing_varint), &msg),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_decode_to_radio(multiple_oneof,
							sizeof(multiple_oneof), &msg),
		      0);
	zassert_equal(msg.type, LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT);
	zassert_equal(lichen_meshtastic_decode_to_radio(unknown_only,
							sizeof(unknown_only), &msg),
		      -ENODATA);
	zassert_equal(lichen_meshtastic_decode_to_radio(oversized_field_key,
							sizeof(oversized_field_key), &msg),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_decode_to_radio(unknown_fixed64_only,
							sizeof(unknown_fixed64_only), &msg),
		      -ENODATA);
}

ZTEST(meshtastic_codec, test_encode_config_complete)
{
	const uint8_t expected[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint8_t buf[16];
	int ret;

	ret = lichen_meshtastic_encode_from_radio_config_complete(69420U, buf, sizeof(buf));
	zassert_true(ret > 0, "encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, expected, sizeof(expected));

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_from_radio_config_complete(69420U, buf, 1U),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
}

ZTEST(meshtastic_codec, test_encode_queue_status)
{
	const uint8_t expected[] = {
		0x5a, 0x0c, 0x08, 0x00, 0x10, 0x04, 0x18,
		0x08, 0x20, 0xf8, 0xac, 0xd1, 0x91, 0x01
	};
	struct lichen_meshtastic_queue_status status = {
		.res = 0U,
		.free = 4U,
		.maxlen = 8U,
		.mesh_packet_id = 0x12345678U,
		.has_res = true,
		.has_mesh_packet_id = true,
	};
	uint8_t buf[32];
	int ret;

	ret = lichen_meshtastic_encode_from_radio_queue_status(&status, buf, sizeof(buf));
	zassert_true(ret > 0, "encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, expected, sizeof(expected));

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_from_radio_queue_status(&status, buf, 1U),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
}

ZTEST(meshtastic_codec, test_encode_packet)
{
	const uint8_t packet[] = { 0x01, 0x02 };
	const uint8_t expected[] = { 0x08, 0x04, 0x12, 0x02, 0x01, 0x02 };
	uint8_t buf[16];
	int ret;

	ret = lichen_meshtastic_encode_from_radio_packet(4U, packet, sizeof(packet),
							 buf, sizeof(buf));
	zassert_true(ret > 0, "encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, expected, sizeof(expected));

	zassert_equal(lichen_meshtastic_encode_from_radio_packet(4U, NULL, 1U,
								 buf, sizeof(buf)),
		      -EINVAL);
	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_from_radio_packet(4U, packet,
								 sizeof(packet), buf, 1U),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
}

ZTEST(meshtastic_codec, test_encode_text_packet_matches_incoming_vector)
{
	const uint8_t expected_packet[] = {
		0x0d, 0x44, 0x33, 0x22, 0x11, 0x15, 0x04, 0x03,
		0x02, 0x01, 0x22, 0x06, 0x08, 0x01, 0x12, 0x02,
		0x68, 0x69, 0x35, 0x88, 0x77, 0x66, 0x55
	};
	const uint8_t expected_from_radio[] = {
		0x08, 0x01, 0x12, 0x17, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x06,
		0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x35, 0x88,
		0x77, 0x66, 0x55
	};
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_text_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	uint8_t packet_buf[64];
	uint8_t from_radio_buf[64];
	int ret;

	ret = lichen_meshtastic_encode_text_packet(&packet, packet_buf,
						   sizeof(packet_buf));
	zassert_true(ret > 0, "text packet encode failed: %d", ret);
	expect_bytes(packet_buf, (size_t)ret, expected_packet,
		     sizeof(expected_packet));

	ret = lichen_meshtastic_encode_from_radio_packet(1U, packet_buf,
							 sizeof(expected_packet),
							 from_radio_buf,
							 sizeof(from_radio_buf));
	zassert_true(ret > 0, "FromRadio packet encode failed: %d", ret);
	expect_bytes(from_radio_buf, (size_t)ret, expected_from_radio,
		     sizeof(expected_from_radio));
}

ZTEST(meshtastic_codec, test_encode_text_packet_optional_fields)
{
	const uint8_t expected_packet[] = {
		0x0d, 0x44, 0x33, 0x22, 0x11, 0x15, 0x04, 0x03,
		0x02, 0x01, 0x18, 0x07, 0x22, 0x06, 0x08, 0x01,
		0x12, 0x02, 0x68, 0x69, 0x35, 0x88, 0x77, 0x66,
		0x55, 0x50, 0x01
	};
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_text_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.channel = 7U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_channel = true,
		.want_ack = true,
	};
	uint8_t buf[64];
	int ret;

	ret = lichen_meshtastic_encode_text_packet(&packet, buf, sizeof(buf));
	zassert_true(ret > 0, "text packet encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, expected_packet,
		     sizeof(expected_packet));
}

ZTEST(meshtastic_codec, test_encode_text_packet_rejects_bad_sizes)
{
	uint8_t payload[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U];
	struct lichen_meshtastic_text_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX,
	};
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	memset(payload, 'x', sizeof(payload));
	memset(buf, 0x5a, sizeof(buf));
	ret = lichen_meshtastic_encode_text_packet(&packet, buf, sizeof(buf));
	zassert_equal(ret, 223, "max payload should fit");

	packet.payload_len = LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U;
	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_text_packet(&packet, buf,
							   sizeof(buf)),
		      -EMSGSIZE);
	zassert_equal(buf[0], 0x5a, "oversize encode should not write output");

	packet.payload_len = 0U;
	zassert_equal(lichen_meshtastic_encode_text_packet(&packet, buf,
							   sizeof(buf)),
		      -EMSGSIZE);
}

ZTEST(meshtastic_codec, test_encode_text_packet_rejects_short_buffer)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct lichen_meshtastic_text_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	uint8_t buf[22];

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_text_packet(&packet, buf,
							   sizeof(buf)),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
}

ZTEST(meshtastic_codec, test_encode_routing_packet_matches_vectors)
{
	const uint8_t expected_ack_packet[] = {
		0x0d, 0x44, 0x33, 0x22, 0x11, 0x15, 0x04, 0x03,
		0x02, 0x01, 0x22, 0x07, 0x08, 0x05, 0x35, 0x78,
		0x56, 0x34, 0x12, 0x35, 0x89, 0x77, 0x66, 0x55
	};
	const uint8_t expected_ack_from_radio[] = {
		0x08, 0x02, 0x12, 0x18, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x07,
		0x08, 0x05, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x89, 0x77, 0x66, 0x55
	};
	const uint8_t expected_nak_packet[] = {
		0x0d, 0x44, 0x33, 0x22, 0x11, 0x15, 0x04, 0x03,
		0x02, 0x01, 0x22, 0x0b, 0x08, 0x05, 0x12, 0x02,
		0x18, 0x01, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x8a, 0x77, 0x66, 0x55
	};
	const uint8_t expected_nak_from_radio[] = {
		0x08, 0x03, 0x12, 0x1c, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x0b,
		0x08, 0x05, 0x12, 0x02, 0x18, 0x01, 0x35, 0x78,
		0x56, 0x34, 0x12, 0x35, 0x8a, 0x77, 0x66, 0x55
	};
	struct lichen_meshtastic_routing_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
	};
	uint8_t packet_buf[64];
	uint8_t from_radio_buf[64];
	int ret;

	ret = lichen_meshtastic_encode_routing_packet(&packet, packet_buf,
						      sizeof(packet_buf));
	zassert_true(ret > 0, "routing ACK encode failed: %d", ret);
	expect_bytes(packet_buf, (size_t)ret, expected_ack_packet,
		     sizeof(expected_ack_packet));
	ret = lichen_meshtastic_encode_from_radio_packet(2U, packet_buf,
							 sizeof(expected_ack_packet),
							 from_radio_buf,
							 sizeof(from_radio_buf));
	zassert_true(ret > 0, "FromRadio ACK encode failed: %d", ret);
	expect_bytes(from_radio_buf, (size_t)ret, expected_ack_from_radio,
		     sizeof(expected_ack_from_radio));

	packet.id = 0x5566778aU;
	packet.error_reason = 1U;
	packet.has_error_reason = true;
	ret = lichen_meshtastic_encode_routing_packet(&packet, packet_buf,
						      sizeof(packet_buf));
	zassert_true(ret > 0, "routing NAK encode failed: %d", ret);
	expect_bytes(packet_buf, (size_t)ret, expected_nak_packet,
		     sizeof(expected_nak_packet));
	ret = lichen_meshtastic_encode_from_radio_packet(3U, packet_buf,
							 sizeof(expected_nak_packet),
							 from_radio_buf,
							 sizeof(from_radio_buf));
	zassert_true(ret > 0, "FromRadio NAK encode failed: %d", ret);
	expect_bytes(from_radio_buf, (size_t)ret, expected_nak_from_radio,
		     sizeof(expected_nak_from_radio));
}

ZTEST(meshtastic_codec, test_encode_routing_packet_rejects_short_buffer)
{
	struct lichen_meshtastic_routing_packet packet = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
	};
	uint8_t buf[23];

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_routing_packet(&packet, buf,
							      sizeof(buf)),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
	zassert_equal(lichen_meshtastic_encode_routing_packet(NULL, buf,
							      sizeof(buf)),
		      -EINVAL);
}

ZTEST(meshtastic_codec, test_encode_packet_rejects_from_radio_oversize)
{
	uint8_t packet[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX + 16U];

	memset(packet, 0xa5, sizeof(packet));
	memset(buf, 0x5a, sizeof(buf));

	zassert_equal(lichen_meshtastic_encode_from_radio_packet(4U, packet,
								 sizeof(packet), buf,
								 sizeof(buf)),
		      -EMSGSIZE);
	zassert_equal(buf[0], 0x5a, "oversize encode should not write output");
}

ZTEST(meshtastic_codec, test_encode_sync_response_messages)
{
	const uint8_t payload[] = { 0x08, 0x2a };
	uint8_t buf[32];
	int ret;

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "my_info encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x1a, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "node_info encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x22, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "config encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x2a, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "moduleConfig encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x4a, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "channel encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x52, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_METADATA, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "metadata encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x6a, 0x02, 0x08, 0x2a }, 4U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_CLIENT_NOTIFICATION, payload,
		sizeof(payload), buf, sizeof(buf));
	zassert_true(ret > 0, "clientNotification encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x82, 0x01, 0x02, 0x08, 0x2a },
		     5U);

	ret = lichen_meshtastic_encode_from_radio_message(
		LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS, payload, sizeof(payload),
		buf, sizeof(buf));
	zassert_true(ret > 0, "region_presets encode failed: %d", ret);
	expect_bytes(buf, (size_t)ret, (const uint8_t[]){ 0x9a, 0x01, 0x02, 0x08, 0x2a },
		     5U);

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_from_radio_message(
			      LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO, payload,
			      sizeof(payload), buf, 1U),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
	zassert_equal(lichen_meshtastic_encode_from_radio_message(
			      (enum lichen_meshtastic_from_radio_message)99, payload,
			      sizeof(payload), buf, sizeof(buf)),
		      -EINVAL);
}

ZTEST(meshtastic_codec, test_encode_sync_payload_builders)
{
	const uint8_t device_id[] = {
		0x02, 0x00, 0x00, 0xff, 0xaa, 0xbb, 0xcc, 0xdd
	};
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.min_app_version = 30200U,
		.nodedb_count = 1U,
		.uptime_seconds = 123U,
		.tx_power_dbm = 14,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.firmware_version = "LICHEN test 0.0.0",
		.pio_env = "zephyr-native_sim",
		.device_id = device_id,
		.device_id_len = sizeof(device_id),
		.has_bluetooth = true,
		.has_lora = true,
		.has_tx_power_dbm = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t from_radio[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	ret = lichen_meshtastic_encode_my_info_payload(&info, payload,
						       sizeof(payload));
	zassert_true(ret > 0, "my_info payload failed: %d", ret);
	zassert_true(lichen_meshtastic_encode_from_radio_message(
			     LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO, payload,
			     (size_t)ret, from_radio, sizeof(from_radio)) > 0);

	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));
	zassert_true(ret > 0, "metadata payload failed: %d", ret);

	ret = lichen_meshtastic_encode_config_payload(&info, payload,
						      sizeof(payload));
	zassert_true(ret > 0, "config payload failed: %d", ret);

	ret = lichen_meshtastic_encode_module_config_payload(&info, payload,
							     sizeof(payload));
	zassert_true(ret > 0, "module payload failed: %d", ret);

	ret = lichen_meshtastic_encode_channel_payload(&info, payload,
						       sizeof(payload));
	zassert_true(ret > 0, "channel payload failed: %d", ret);

	ret = lichen_meshtastic_encode_region_presets_payload(&info, payload,
							      sizeof(payload));
	zassert_true(ret > 0, "region payload failed: %d", ret);

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));
	zassert_true(ret > 0, "node_info payload failed: %d", ret);
}

ZTEST(meshtastic_codec, test_config_sections_are_separate_oneofs)
{
	struct lichen_meshtastic_local_info info = {
		.has_bluetooth = true,
		.has_lora = true,
		.has_tx_power_dbm = true,
		.tx_power_dbm = 14,
	};
	const struct {
		enum lichen_meshtastic_config_section section;
		uint32_t oneof_field;
	} sections[] = {
		{ LICHEN_MESHTASTIC_CONFIG_DEVICE, 1U },
		{ LICHEN_MESHTASTIC_CONFIG_POSITION, 2U },
		{ LICHEN_MESHTASTIC_CONFIG_POWER, 3U },
		{ LICHEN_MESHTASTIC_CONFIG_NETWORK, 4U },
		{ LICHEN_MESHTASTIC_CONFIG_DISPLAY, 5U },
		{ LICHEN_MESHTASTIC_CONFIG_LORA, 6U },
		{ LICHEN_MESHTASTIC_CONFIG_BLUETOOTH, 7U },
		{ LICHEN_MESHTASTIC_CONFIG_SECURITY, 8U },
		{ LICHEN_MESHTASTIC_CONFIG_DEVICE_UI, 10U },
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t counts[12];

	for (size_t i = 0U; i < ARRAY_SIZE(sections); i++) {
		int ret = lichen_meshtastic_encode_config_section_payload(
			sections[i].section, &info, payload, sizeof(payload));

		zassert_true(ret > 0, "config section %u failed: %d",
			     (uint32_t)sections[i].section, ret);
		zassert_true(payload_count_fields(payload, (size_t)ret, counts,
						  ARRAY_SIZE(counts)));
		for (size_t field = 1U; field < ARRAY_SIZE(counts); field++) {
			zassert_equal(counts[field],
				      field == sections[i].oneof_field ? 1U : 0U,
				      "section %u unexpected Config field %u count %u",
				      (uint32_t)sections[i].section,
				      (uint32_t)field, counts[field]);
		}
	}

	zassert_equal(lichen_meshtastic_encode_config_section_payload(
			      (enum lichen_meshtastic_config_section)99, &info,
			      payload, sizeof(payload)),
		      -EINVAL);
}

ZTEST(meshtastic_codec, test_config_placeholders_are_explicit)
{
	struct lichen_meshtastic_local_info info = { 0 };
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *section;
	size_t section_len;
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_POSITION, &info, payload, sizeof(payload));
	zassert_true(ret > 0, "position config failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 2U, &section,
					   &section_len));
	zassert_true(payload_get_varint_field(section, section_len, 3U, &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(section, section_len, 7U, &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(section, section_len, 13U, &value));
	zassert_equal(value, 2U);

	ret = lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_POWER, &info, payload, sizeof(payload));
	zassert_true(ret > 0, "power config failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 3U, &section,
					   &section_len));
	zassert_true(payload_get_varint_field(section, section_len, 1U, &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(section, section_len, 4U, &value));
	zassert_equal(value, 0U);

	ret = lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_BLUETOOTH, &info, payload,
		sizeof(payload));
	zassert_true(ret > 0, "bluetooth config failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 7U, &section,
					   &section_len));
	zassert_true(payload_get_varint_field(section, section_len, 1U, &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(section, section_len, 2U, &value));
	zassert_equal(value, 2U);

	ret = lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_DEVICE_UI, &info, payload,
		sizeof(payload));
	zassert_true(ret > 0, "device_ui config failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 10U, &section,
					   &section_len));
	zassert_true(payload_get_varint_field(section, section_len, 1U, &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(section, section_len, 2U, &value));
	zassert_equal(value, 1U);
	zassert_true(payload_get_varint_field(section, section_len, 3U, &value));
	zassert_equal(value, 0U);

	info.has_bluetooth = true;
	ret = lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_BLUETOOTH, &info, payload,
		sizeof(payload));
	zassert_true(ret > 0, "bluetooth enabled config failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 7U, &section,
					   &section_len));
	zassert_true(payload_get_varint_field(section, section_len, 1U, &value));
	zassert_equal(value, 1U);
}

ZTEST(meshtastic_codec, test_metadata_payload_matches_current_schema)
{
	struct lichen_meshtastic_local_info info = {
		.firmware_version = "LICHEN compat 1.0",
		.has_bluetooth = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));

	zassert_true(ret > 0, "metadata payload failed: %d", ret);
	assert_metadata_payload(payload, (size_t)ret, "LICHEN compat 1.0", 1U,
				0x5fffU);

	info.has_bluetooth = false;
	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));

	zassert_true(ret > 0, "metadata payload failed: %d", ret);
	assert_metadata_payload(payload, (size_t)ret, "LICHEN compat 1.0", 0U,
				0x7fffU);
}

ZTEST(meshtastic_codec, test_node_info_omits_unknown_battery_metrics)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_battery = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *metrics;
	size_t metrics_len;
	uint8_t counts[8];
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 6U, &metrics,
					   &metrics_len));
	zassert_true(payload_count_fields(metrics, metrics_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		zassert_equal(counts[i], i == 5U ? 1U : 0U,
			      "unexpected DeviceMetrics field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U, &value));
	zassert_equal(value, 123U);
	zassert_false(payload_get_len_field(payload, (size_t)ret, 3U, &metrics,
					    &metrics_len));
}

ZTEST(meshtastic_codec, test_node_info_encodes_valid_position)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_latitude_e7 = true,
		.latitude_e7 = 476206130,
		.has_longitude_e7 = true,
		.longitude_e7 = -1223493000,
		.has_altitude_m = true,
		.altitude_m = 42,
		.has_fix_time_unix = true,
		.fix_time_unix = 1710000000U,
		.has_satellites = true,
		.satellites = 9U,
		.has_gnss_fix = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *position;
	size_t position_len;
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 3U, &position,
					   &position_len));
	zassert_true(payload_get_fixed32_field(position, position_len, 1U,
					       &value));
	zassert_equal(value, 476206130U);
	zassert_true(payload_get_fixed32_field(position, position_len, 2U,
					       &value));
	zassert_equal(value, (uint32_t)-1223493000);
	zassert_true(payload_get_varint_field(position, position_len, 3U,
					      &value));
	zassert_equal(value, 42U);
	zassert_true(payload_get_fixed32_field(position, position_len, 4U,
					       &value));
	zassert_equal(value, 1710000000U);
	zassert_true(payload_get_varint_field(position, position_len, 5U,
					      &value));
	zassert_equal(value, 2U);
	zassert_true(payload_get_varint_field(position, position_len, 6U,
					      &value));
	zassert_equal(value, 2U);
	zassert_true(payload_get_fixed32_field(position, position_len, 7U,
					       &value));
	zassert_equal(value, 1710000000U);
	zassert_true(payload_get_varint_field(position, position_len, 19U,
					      &value));
	zassert_equal(value, 9U);
}

ZTEST(meshtastic_codec, test_node_info_encodes_negative_altitude_as_int32_varint)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_latitude_e7 = true,
		.latitude_e7 = 476206130,
		.has_longitude_e7 = true,
		.longitude_e7 = -1223493000,
		.has_altitude_m = true,
		.altitude_m = -17,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *position;
	size_t position_len;
	uint64_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 3U, &position,
					   &position_len));
	zassert_true(payload_get_varint64_field(position, position_len, 3U,
						&value));
	zassert_equal(value, (uint64_t)(int64_t)-17);
}

ZTEST(meshtastic_codec, test_node_info_requires_lat_lon_for_position)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_fix_time_unix = true,
		.fix_time_unix = 1710000000U,
		.has_latitude_e7 = true,
		.latitude_e7 = 476206130,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *position;
	size_t position_len;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_false(payload_get_len_field(payload, (size_t)ret, 3U, &position,
					    &position_len));
}

ZTEST(meshtastic_codec, test_node_info_encodes_valid_battery_metrics)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_battery = true,
		.has_battery_percent = true,
		.battery_percent = 77U,
		.has_battery_voltage_mv = true,
		.battery_voltage_mv = 3700U,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *metrics;
	size_t metrics_len;
	uint8_t counts[8];
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 6U, &metrics,
					   &metrics_len));
	zassert_true(payload_count_fields(metrics, metrics_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		bool expected = (i == 1U || i == 2U || i == 5U);

		zassert_equal(counts[i], expected ? 1U : 0U,
			      "unexpected DeviceMetrics field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_varint_field(metrics, metrics_len, 1U, &value));
	zassert_equal(value, 77U);
	zassert_true(payload_get_fixed32_field(metrics, metrics_len, 2U, &value));
	zassert_equal(value, 0x406ccccdU);
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U, &value));
	zassert_equal(value, 123U);
}

ZTEST(meshtastic_codec, test_node_info_encodes_external_power_explicitly)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_external_power = true,
		.external_power = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *metrics;
	size_t metrics_len;
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 6U, &metrics,
					   &metrics_len));
	zassert_true(payload_get_varint_field(metrics, metrics_len, 1U, &value));
	zassert_equal(value, 101U);
}

ZTEST(meshtastic_codec,
      test_node_info_omits_out_of_range_battery_percent)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.uptime_seconds = 123U,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
		.has_battery = true,
		.has_battery_percent = true,
		.battery_percent = 101U,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	const uint8_t *metrics;
	size_t metrics_len;
	uint8_t counts[8];
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_node_info_payload(&info, payload,
							 sizeof(payload));

	zassert_true(ret > 0, "node_info payload failed: %d", ret);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 6U, &metrics,
					   &metrics_len));
	zassert_true(payload_count_fields(metrics, metrics_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		zassert_equal(counts[i], i == 5U ? 1U : 0U,
			      "unexpected DeviceMetrics field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_false(payload_get_varint_field(metrics, metrics_len, 1U,
					       &value));
	zassert_true(payload_get_varint_field(metrics, metrics_len, 5U, &value));
	zassert_equal(value, 123U);
}

ZTEST(meshtastic_codec, test_module_and_region_placeholders_match_policy)
{
	struct lichen_meshtastic_local_info info = { 0 };
	const uint8_t *telemetry;
	const uint8_t *preset_group;
	const uint8_t *region_group;
	size_t telemetry_len;
	size_t preset_group_len;
	size_t region_group_len;
	uint8_t counts[18];
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_module_config_payload(&info, payload,
							     sizeof(payload));
	zassert_true(ret > 0, "module payload failed: %d", ret);
	zassert_true(payload_count_fields(payload, (size_t)ret, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		zassert_equal(counts[i], i == 6U ? 1U : 0U,
			      "unexpected ModuleConfig field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_len_field(payload, (size_t)ret, 6U, &telemetry,
					   &telemetry_len));
	zassert_true(payload_count_fields(telemetry, telemetry_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		bool expected = (i == 1U || i == 2U || i == 14U);

		zassert_equal(counts[i], expected ? 1U : 0U,
			      "unexpected TelemetryConfig field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_varint_field(telemetry, telemetry_len, 1U,
					      &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(telemetry, telemetry_len, 2U,
					      &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(telemetry, telemetry_len, 14U,
					      &value));
	zassert_equal(value, 0U);

	ret = lichen_meshtastic_encode_region_presets_payload(&info, payload,
							      sizeof(payload));
	zassert_true(ret > 0, "region payload failed: %d", ret);
	zassert_true(payload_count_fields(payload, (size_t)ret, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		bool expected = (i == 1U || i == 2U);

		zassert_equal(counts[i], expected ? 1U : 0U,
			      "unexpected LoRaRegionPresetMap field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_len_field(payload, (size_t)ret, 1U, &preset_group,
					   &preset_group_len));
	zassert_true(payload_count_fields(preset_group, preset_group_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		bool expected = (i == 1U || i == 2U);

		zassert_equal(counts[i], expected ? 1U : 0U,
			      "unexpected LoRaPresetGroup field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_varint_field(preset_group, preset_group_len, 1U,
					      &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_varint_field(preset_group, preset_group_len, 2U,
					      &value));
	zassert_equal(value, 0U);
	zassert_true(payload_get_len_field(payload, (size_t)ret, 2U, &region_group,
					   &region_group_len));
	zassert_true(payload_count_fields(region_group, region_group_len, counts,
					  ARRAY_SIZE(counts)));
	for (size_t i = 1U; i < ARRAY_SIZE(counts); i++) {
		bool expected = (i == 1U || i == 2U);

		zassert_equal(counts[i], expected ? 1U : 0U,
			      "unexpected LoRaRegionPresets field %u count %u",
			      (uint32_t)i, counts[i]);
	}
	zassert_true(payload_get_varint_field(region_group, region_group_len, 1U,
					      &value));
	zassert_equal(value, 1U);
	zassert_true(payload_get_varint_field(region_group, region_group_len, 2U,
					      &value));
	zassert_equal(value, 0U);
}

ZTEST(meshtastic_codec, test_metadata_payload_rejects_meshtastic_branding)
{
	struct lichen_meshtastic_local_info info = {
		.firmware_version = "LICHEN MESHTASTIC 2.7.0",
		.has_bluetooth = false,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint32_t value = 0U;
	int ret;

	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));

	zassert_true(ret > 0, "metadata payload failed: %d", ret);
	zassert_true(payload_has_string(payload, (size_t)ret, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(payload, (size_t)ret, 1U,
					 "LICHEN MESHTASTIC 2.7.0"));
	zassert_true(payload_get_varint_field(payload, (size_t)ret, 9U, &value));
	zassert_equal(value, 255U);
	zassert_true(payload_get_varint_field(payload, (size_t)ret, 12U, &value));
	zassert_equal(value, 0x7fff);
}

ZTEST(meshtastic_codec, test_metadata_payload_requires_lichen_prefix)
{
	struct lichen_meshtastic_local_info info = {
		.firmware_version = "NOTLICHEN compat 1.0",
		.has_bluetooth = true,
	};
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));

	zassert_true(ret > 0, "metadata payload failed: %d", ret);
	zassert_true(payload_has_string(payload, (size_t)ret, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(payload, (size_t)ret, 1U,
					 "NOTLICHEN compat 1.0"));

	info.firmware_version = "LICHEN compat 1.0+board";
	ret = lichen_meshtastic_encode_metadata_payload(&info, payload,
							sizeof(payload));

	zassert_true(ret > 0, "metadata payload failed: %d", ret);
	zassert_true(payload_has_string(payload, (size_t)ret, 1U,
					"LICHEN compat 1.0+board"));
}

ZTEST(meshtastic_codec, test_encode_sync_payload_rejects_bad_buffers)
{
	struct lichen_meshtastic_local_info info = {
		.node_num = 0xaabbccddU,
		.long_name = "LICHEN native_sim",
		.short_name = "LICH",
	};
	uint8_t buf[4];

	memset(buf, 0x5a, sizeof(buf));
	zassert_equal(lichen_meshtastic_encode_my_info_payload(&info, NULL,
							       sizeof(buf)),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_encode_node_info_payload(&info, buf, 1U),
		      -ENOMEM);
	zassert_equal(buf[0], 0x5a, "short-buffer encode should not write output");
}

ZTEST_SUITE(meshtastic_codec, NULL, NULL, NULL, NULL, NULL);
