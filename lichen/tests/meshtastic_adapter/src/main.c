/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/codec.h>

struct test_ctx {
	uint8_t out[10][LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	size_t out_len[10];
	size_t out_count;
	size_t out_cap;
	uint32_t text_count;
	uint32_t last_text_id;
	size_t last_text_len;
	const char *firmware_version;
};

struct queue_status_view {
	uint32_t res;
	uint32_t free;
	uint32_t maxlen;
	uint32_t mesh_packet_id;
	bool has_res;
	bool has_mesh_packet_id;
};

struct from_radio_view {
	uint32_t field;
	const uint8_t *payload;
	size_t payload_len;
	uint32_t value;
};

static int test_enqueue(const uint8_t *from_radio, size_t len, void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (ctx->out_count == ctx->out_cap) {
		return -ENOMEM;
	}
	if (len > sizeof(ctx->out[0])) {
		return -EMSGSIZE;
	}

	memcpy(ctx->out[ctx->out_count], from_radio, len);
	ctx->out_len[ctx->out_count] = len;
	ctx->out_count++;
	return 0;
}

static int test_text(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct test_ctx *ctx = user_data;

	ctx->text_count++;
	ctx->last_text_id = packet->id;
	ctx->last_text_len = packet->payload_len;
	return 0;
}

static int test_local_info(struct lichen_meshtastic_local_info *info,
			   void *user_data);

static void init_adapter(struct lichen_meshtastic_adapter *adapter,
			 struct test_ctx *ctx, size_t out_cap)
{
	struct lichen_meshtastic_adapter_ops ops = {
		.enqueue_from_radio = test_enqueue,
		.handle_text = test_text,
		.get_local_info = test_local_info,
		.user_data = ctx,
		.queue_maxlen = 8U,
		.heartbeat_queue_status = true,
	};

	memset(ctx, 0, sizeof(*ctx));
	ctx->out_cap = out_cap;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

static void expect_bytes(const uint8_t *actual, size_t actual_len,
			 const uint8_t *expected, size_t expected_len)
{
	zassert_equal(actual_len, expected_len, "unexpected encoded length");
	zassert_mem_equal(actual, expected, expected_len, "unexpected encoded bytes");
}

static void decode_from_radio(const uint8_t *buf, size_t len,
			      struct from_radio_view *out);
static bool payload_has_string(const uint8_t *buf, size_t len, uint32_t field,
			       const char *value);
static bool payload_get_varint_field(const uint8_t *buf, size_t len,
				     uint32_t field, uint32_t *value);

static int test_local_info(struct lichen_meshtastic_local_info *info,
			   void *user_data)
{
	static const uint8_t device_id[] = {
		0x02, 0x00, 0x00, 0xff, 0xaa, 0xbb, 0xcc, 0xdd
	};
	struct test_ctx *ctx = user_data;

	memset(info, 0, sizeof(*info));
	info->node_num = 0xaabbccddU;
	info->min_app_version = 30200U;
	info->nodedb_count = 1U;
	info->uptime_seconds = 123U;
	info->long_name = "LICHEN native_sim";
	info->short_name = "LICH";
	info->firmware_version = ctx->firmware_version != NULL ?
					 ctx->firmware_version :
					 "LICHEN test 0.0.0";
	info->pio_env = "zephyr-native_sim";
	info->device_id = device_id;
	info->device_id_len = sizeof(device_id);
	info->has_bluetooth = true;
	info->has_lora = true;
	info->has_tx_power_dbm = true;
	info->tx_power_dbm = 14;
	return 0;
}

ZTEST(meshtastic_adapter, test_unbranded_firmware_version_uses_lichen_default)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	uint32_t excluded_modules = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "LICHEN mEsHtAsTiC 2.7.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_true(ctx.out_count > 1U);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(view.payload, view.payload_len, 1U,
					 "LICHEN mEsHtAsTiC 2.7.0"));
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 9U,
					      &excluded_modules));
	zassert_equal(excluded_modules, 255U);
	zassert_true(payload_get_varint_field(view.payload, view.payload_len, 12U,
					      &excluded_modules));
	zassert_equal(excluded_modules, 0x5fff);
}

ZTEST(meshtastic_adapter, test_firmware_version_requires_lichen_prefix)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "NOTLICHEN compat 1.0";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN Zephyr compat 0.0.0+unknown"));
	zassert_false(payload_has_string(view.payload, view.payload_len, 1U,
					 "NOTLICHEN compat 1.0"));

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ctx.firmware_version = "LICHEN compat 1.0+board";
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_true(payload_has_string(view.payload, view.payload_len, 1U,
					"LICHEN compat 1.0+board"));
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

static void decode_from_radio(const uint8_t *buf, size_t len,
			      struct from_radio_view *out)
{
	size_t pos = 0U;
	uint32_t key;
	uint32_t payload_len;

	memset(out, 0, sizeof(*out));
	zassert_equal(read_varint(buf, len, &pos, &key), 0);
	out->field = key >> 3;
	if ((key & 0x07U) == 2U) {
		zassert_equal(read_varint(buf, len, &pos, &payload_len), 0);
		zassert_true(payload_len <= len - pos);
		out->payload = &buf[pos];
		out->payload_len = payload_len;
	} else {
		zassert_equal(key & 0x07U, 0U);
		zassert_equal(read_varint(buf, len, &pos, &out->value), 0);
	}
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

static void decode_queue_status(const uint8_t *buf, size_t len,
				struct queue_status_view *out)
{
	size_t pos = 0U;
	uint32_t key;
	uint32_t inner_len;
	size_t end;

	memset(out, 0, sizeof(*out));
	zassert_equal(read_varint(buf, len, &pos, &key), 0);
	zassert_equal(key, 0x5aU);
	zassert_equal(read_varint(buf, len, &pos, &inner_len), 0);
	zassert_true(inner_len <= len - pos);
	end = pos + inner_len;

	while (pos < end) {
		uint32_t value;

		zassert_equal(read_varint(buf, end, &pos, &key), 0);
		zassert_equal(read_varint(buf, end, &pos, &value), 0);
		switch (key) {
		case 0x08:
			out->res = value;
			out->has_res = true;
			break;
		case 0x10:
			out->free = value;
			break;
		case 0x18:
			out->maxlen = value;
			break;
		case 0x20:
			out->mesh_packet_id = value;
			out->has_mesh_packet_id = true;
			break;
		default:
			zassert_unreachable("unexpected queueStatus key");
		}
	}
}

ZTEST(meshtastic_adapter, test_heartbeat_queues_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, heartbeat,
						    sizeof(heartbeat));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_equal(status.free, 7U);
	zassert_equal(status.maxlen, 8U);
	zassert_false(status.has_mesh_packet_id);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_69420_queues_stage1_sequence)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xac, 0x9e, 0x04 };
	const uint32_t fields[] = {
		LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO,
		LICHEN_MESHTASTIC_FROM_RADIO_METADATA,
		LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS,
		LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG,
		LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL,
		7U,
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, ARRAY_SIZE(fields));
	for (size_t i = 0U; i < ARRAY_SIZE(fields); i++) {
		struct from_radio_view view;

		decode_from_radio(ctx.out[i], ctx.out_len[i], &view);
		zassert_equal(view.field, fields[i], "field[%u]", (uint32_t)i);
	}
	expect_bytes(ctx.out[ARRAY_SIZE(fields) - 1U],
		     ctx.out_len[ARRAY_SIZE(fields) - 1U], complete,
		     sizeof(complete));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->want_config_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_69421_queues_node_db_sequence)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xad, 0x9e, 0x04 };
	const uint8_t complete[] = { 0x38, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 2U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[1], ctx.out_len[1], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_unknown_nonce_queues_full_sync)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	const uint8_t complete[] = { 0x38, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 8U);
	decode_from_radio(ctx.out[6], ctx.out_len[6], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	decode_from_radio(ctx.out[7], ctx.out_len[7], &view);
	zassert_equal(view.field, 7U);
	expect_bytes(ctx.out[7], ctx.out_len[7], complete, sizeof(complete));
}

ZTEST(meshtastic_adapter, test_want_config_full_sync_fits_gateway_default_queue)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xa5, 0xcb, 0x96, 0xad, 0x0a };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, 8U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 8U);
	decode_from_radio(ctx.out[7], ctx.out_len[7], &view);
	zassert_equal(view.field, 7U);
}

ZTEST(meshtastic_adapter, test_synthetic_node_and_channel_fields_are_stable)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_static[] = { 0x18, 0xac, 0x9e, 0x04 };
	const uint8_t want_nodes[] = { 0x18, 0xad, 0x9e, 0x04 };
	struct from_radio_view view;
	const uint8_t *channel_payload;
	const uint8_t *settings_payload;
	const uint8_t *user_payload;
	size_t channel_len;
	size_t settings_len;
	size_t user_len;
	uint32_t hw_model = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_static,
						    sizeof(want_static));
	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[5], ctx.out_len[5], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL);
	channel_payload = view.payload;
	channel_len = view.payload_len;
	zassert_true(payload_get_len_field(channel_payload, channel_len, 2U,
					   &settings_payload, &settings_len));
	zassert_true(payload_has_string(settings_payload, settings_len, 3U,
					"LICHEN"));

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_nodes,
						    sizeof(want_nodes));
	zassert_equal(ret, 0);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO);
	zassert_true(view.payload_len > 0U);
	zassert_true(payload_get_len_field(view.payload, view.payload_len, 2U,
					   &user_payload, &user_len));
	zassert_true(payload_has_string(user_payload, user_len, 2U,
					"LICHEN native_sim"));
	zassert_true(payload_get_varint_field(user_payload, user_len, 5U,
					      &hw_model));
	zassert_equal(hw_model, 255U);
}

ZTEST(meshtastic_adapter, test_disconnect_marks_session_only)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t disconnect[] = { 0x20, 0x01 };
	const uint8_t disconnect_false[] = { 0x20, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect_false,
						    sizeof(disconnect_false));
	zassert_equal(ret, 0);
	zassert_false(lichen_meshtastic_adapter_disconnected(&adapter));
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->disconnect_count,
		      0U);

	ret = lichen_meshtastic_adapter_process_raw(&adapter, disconnect,
						    sizeof(disconnect));

	zassert_equal(ret, 0);
	zassert_true(lichen_meshtastic_adapter_disconnected(&adapter));
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->disconnect_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_text_packet_routes_to_stub_and_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t text_packet[] = {
		0x0a, 0x17, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x09, 0x08, 0x01, 0x12, 0x05, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x35, 0x78, 0x56, 0x34, 0x12, 0x50, 0x01
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, text_packet,
						    sizeof(text_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 1U);
	zassert_equal(ctx.last_text_id, 0x12345678U);
	zassert_equal(ctx.last_text_len, 5U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 0U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345678U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->text_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_unsupported_packet_is_deterministic_noop)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t private_packet[] = {
		0x0a, 0x1c, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22,
		0x10, 0x08, 0x80, 0x02, 0x12, 0x0b, 0x75, 0x6e,
		0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
		0x64, 0x35, 0x79, 0x56, 0x34, 0x12
	};
	struct queue_status_view status;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, private_packet,
						    sizeof(private_packet));

	zassert_equal(ret, 0);
	zassert_equal(ctx.text_count, 0U);
	zassert_equal(ctx.out_count, 1U);
	decode_queue_status(ctx.out[0], ctx.out_len[0], &status);
	zassert_true(status.has_res);
	zassert_equal(status.res, 2U);
	zassert_true(status.has_mesh_packet_id);
	zassert_equal(status.mesh_packet_id, 0x12345679U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_stream_valid_and_split_frames)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t frame[] = { 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, frame, 3U);
	zassert_equal(ret, LICHEN_MESHTASTIC_ADAPTER_NEED_MORE);
	zassert_equal(ctx.out_count, 0U);

	ret = lichen_meshtastic_adapter_feed_stream(&adapter, &frame[3],
						   sizeof(frame) - 3U);
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_stream_rejects_malformed_and_resyncs)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t bad_magic[] = { 0x94, 0x00, 0x00, 0x02 };
	const uint8_t zero_len[] = { 0x94, 0xc3, 0x00, 0x00 };
	const uint8_t oversize[] = { 0x94, 0xc3, 0x01, 0xf9 };
	const uint8_t good[] = { 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, bad_magic,
							    sizeof(bad_magic)),
		      -EINVAL);
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, zero_len,
							    sizeof(zero_len)),
		      -EMSGSIZE);
	zassert_equal(lichen_meshtastic_adapter_feed_stream(&adapter, oversize,
							    sizeof(oversize)),
		      -EMSGSIZE);

	ret = lichen_meshtastic_adapter_feed_stream(&adapter, good, sizeof(good));
	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
}

ZTEST(meshtastic_adapter, test_stream_resyncs_within_same_buffer)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t noisy_good[] = {
		0x00, 0x94, 0x00, 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, noisy_good,
						   sizeof(noisy_good));
	zassert_equal(ret, 0, "ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_true(lichen_meshtastic_adapter_get_stats(&adapter)->
			     malformed_count >= 2U);
}

ZTEST(meshtastic_adapter, test_stream_resyncs_after_bad_frame_in_same_buffer)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t zero_len_good[] = {
		0x94, 0xc3, 0x00, 0x00, 0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	const uint8_t malformed_payload_good[] = {
		0x94, 0xc3, 0x00, 0x02, 0x18, 0x80,
		0x94, 0xc3, 0x00, 0x02, 0x3a, 0x00
	};
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter, zero_len_good,
						   sizeof(zero_len_good));
	zassert_equal(ret, 0, "zero_len ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_feed_stream(&adapter,
						   malformed_payload_good,
						   sizeof(malformed_payload_good));
	zassert_equal(ret, 0, "malformed ret=%d", ret);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->heartbeat_count,
		      1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_want_config_stage1_stops_on_backpressure)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t want_config[] = { 0x18, 0xac, 0x9e, 0x04 };
	struct from_radio_view view;
	int ret;

	init_adapter(&adapter, &ctx, 2U);
	ret = lichen_meshtastic_adapter_process_raw(&adapter, want_config,
						    sizeof(want_config));
	zassert_equal(ret, -ENOMEM);
	zassert_equal(ctx.out_count, 2U);
	decode_from_radio(ctx.out[0], ctx.out_len[0], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO);
	decode_from_radio(ctx.out[1], ctx.out_len[1], &view);
	zassert_equal(view.field, LICHEN_MESHTASTIC_FROM_RADIO_METADATA);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      enqueue_fail_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_unknown_raw_gets_unsupported_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t unknown_only[] = { 0x28, 0x01 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, unknown_only,
						    sizeof(unknown_only));

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_empty_raw_gets_unsupported_status)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t empty = 0U;
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, &empty, 0U);

	zassert_equal(ret, 0);
	zassert_equal(ctx.out_count, 1U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->
			      unsupported_packet_count,
			      1U);
}

ZTEST(meshtastic_adapter, test_malformed_raw_is_rejected)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	const uint8_t truncated_varint[] = { 0x18, 0x80 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, truncated_varint,
						    sizeof(truncated_varint));

	zassert_equal(ret, -EINVAL);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST(meshtastic_adapter, test_oversized_raw_is_rejected)
{
	struct lichen_meshtastic_adapter adapter;
	struct test_ctx ctx;
	uint8_t oversize[LICHEN_MESHTASTIC_TO_RADIO_MAX + 1U] = { 0 };
	int ret;

	init_adapter(&adapter, &ctx, ARRAY_SIZE(ctx.out));
	ret = lichen_meshtastic_adapter_process_raw(&adapter, oversize,
						    sizeof(oversize));

	zassert_equal(ret, -EMSGSIZE);
	zassert_equal(ctx.out_count, 0U);
	zassert_equal(lichen_meshtastic_adapter_get_stats(&adapter)->malformed_count,
		      1U);
}

ZTEST_SUITE(meshtastic_adapter, NULL, NULL, NULL, NULL, NULL);
