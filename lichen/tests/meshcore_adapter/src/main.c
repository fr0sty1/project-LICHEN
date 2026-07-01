/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <lichen/meshcore/adapter.h>

#define OUT_DEPTH 8

struct out_slot {
	uint8_t data[LICHEN_MESHCORE_FRAME_MAX];
	size_t len;
};

struct test_ctx {
	struct out_slot out[OUT_DEPTH];
	size_t count;
	size_t limit;
};

static int enqueue_cb(const uint8_t *frame, size_t len, void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (frame == NULL || len == 0U || len > sizeof(ctx->out[0].data)) {
		return -EINVAL;
	}
	if (ctx->count >= ctx->limit) {
		return -ENOMEM;
	}

	memcpy(ctx->out[ctx->count].data, frame, len);
	ctx->out[ctx->count].len = len;
	ctx->count++;
	return 0;
}

static uint32_t tx_free_cb(void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (ctx->limit <= ctx->count) {
		return 0U;
	}
	return (uint32_t)(ctx->limit - ctx->count);
}

static void init_adapter(struct lichen_meshcore_adapter *adapter,
			 struct test_ctx *ctx, size_t limit)
{
	const struct lichen_meshcore_adapter_ops ops = {
		.enqueue_tx = enqueue_cb,
		.tx_free = tx_free_cb,
		.user_data = ctx,
	};

	memset(ctx, 0, sizeof(*ctx));
	ctx->limit = limit;
	lichen_meshcore_adapter_init(adapter, &ops);
}

static void expect_error(const struct test_ctx *ctx, size_t slot, uint8_t err)
{
	zassert_true(slot < ctx->count);
	zassert_equal(ctx->out[slot].len, 2U);
	zassert_equal(ctx->out[slot].data[0], LICHEN_MESHCORE_RESP_ERR);
	zassert_equal(ctx->out[slot].data[1], err);
}

ZTEST(meshcore_adapter, test_phase1_startup_read_commands)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t app_start[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 't' };
	const uint8_t device_query[] = { 0x16, 0x03 };
	const uint8_t get_contacts[] = { 0x04 };
	const uint8_t get_channel[] = { 0x1f, 0x00 };
	const uint8_t sync_next[] = { 0x0a };
	const uint8_t get_batt[] = { 0x14 };
	const uint8_t get_time[] = { 0x05 };
	const uint8_t custom_vars[] = { 0x28 };
	const uint8_t autoadd[] = { 0x3b };
	const uint8_t flood_scope[] = { 0x40 };

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, app_start,
							  sizeof(app_start)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_SELF_INFO);
	zassert_equal(ctx.out[0].len, 64U);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, device_query,
							  sizeof(device_query)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_DEVICE_INFO);
	zassert_equal(ctx.out[0].len, 82U);
	zassert_equal(ctx.out[0].data[1], LICHEN_MESHCORE_APP_PROTOCOL_VERSION);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_contacts,
							  sizeof(get_contacts)), 0);
	zassert_equal(ctx.count, 2U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_CONTACTS_START);
	zassert_equal(sys_get_le32(&ctx.out[0].data[1]), 0U);
	zassert_equal(ctx.out[1].data[0], LICHEN_MESHCORE_RESP_END_OF_CONTACTS);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_channel,
							  sizeof(get_channel)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_CHANNEL_INFO);
	zassert_equal(ctx.out[0].len, 50U);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, sync_next,
							  sizeof(sync_next)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_batt,
							  sizeof(get_batt)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_BATT_AND_STORAGE);
	zassert_equal(ctx.out[0].len, 11U);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_time,
							  sizeof(get_time)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_CURR_TIME);
	zassert_equal(ctx.out[0].len, 5U);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, custom_vars,
							  sizeof(custom_vars)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_CUSTOM_VARS);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, autoadd,
							  sizeof(autoadd)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_AUTOADD_CONFIG);
	zassert_equal(ctx.out[0].len, 3U);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, flood_scope,
							  sizeof(flood_scope)), 0);
	zassert_equal(ctx.out[0].data[0],
		      LICHEN_MESHCORE_RESP_DEFAULT_FLOOD_SCOPE);
	zassert_equal(ctx.out[0].len, 1U);
}

ZTEST(meshcore_adapter, test_unsupported_and_unknown_commands_are_errors)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t self_advert[] = { 0x07 };
	const uint8_t raw_packet[] = { 0x41 };
	const uint8_t unknown_zero[] = { 0x00 };
	const uint8_t unknown_after_range[] = { 0x42 };
	const uint8_t unknown_ff[] = { 0xff };

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, self_advert,
							  sizeof(self_advert)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, raw_packet,
							  sizeof(raw_packet)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, unknown_zero,
							  sizeof(unknown_zero)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  unknown_after_range,
							  sizeof(unknown_after_range)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, unknown_ff,
							  sizeof(unknown_ff)), 0);

	zassert_equal(ctx.count, 5U);
	for (size_t i = 0U; i < ctx.count; i++) {
		expect_error(&ctx, i, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      unsupported_count, 5U);
}

static bool is_phase1_supported(uint8_t cmd)
{
	switch (cmd) {
	case LICHEN_MESHCORE_CMD_APP_START:
	case LICHEN_MESHCORE_CMD_GET_CONTACTS:
	case LICHEN_MESHCORE_CMD_GET_DEVICE_TIME:
	case LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE:
	case LICHEN_MESHCORE_CMD_GET_BATT_AND_STORAGE:
	case LICHEN_MESHCORE_CMD_DEVICE_QUERY:
	case LICHEN_MESHCORE_CMD_GET_CHANNEL:
	case LICHEN_MESHCORE_CMD_GET_CUSTOM_VARS:
	case LICHEN_MESHCORE_CMD_GET_AUTOADD_CONFIG:
	case LICHEN_MESHCORE_CMD_GET_DEFAULT_FLOOD_SCOPE:
		return true;
	default:
		return false;
	}
}

ZTEST(meshcore_adapter, test_all_valid_unsupported_commands_are_errors)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	for (uint8_t cmd = LICHEN_MESHCORE_CMD_APP_START;
	     cmd <= LICHEN_MESHCORE_CMD_SEND_RAW_PACKET; cmd++) {
		if (is_phase1_supported(cmd)) {
			continue;
		}

		ctx.count = 0U;
		zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, &cmd,
								  1U), 0,
			      "cmd 0x%02x", cmd);
		expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
	}
}

ZTEST(meshcore_adapter, test_malformed_lengths_return_illegal_arg)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t app_start_short[] = { 0x01, 0, 0 };
	const uint8_t device_query_short[] = { 0x16 };
	const uint8_t get_channel_short[] = { 0x1f };
	const uint8_t get_channel_not_found[] = { 0x1f, 0x01 };

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, NULL, 0U), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  app_start_short,
							  sizeof(app_start_short)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  device_query_short,
							  sizeof(device_query_short)), 0);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  get_channel_short,
							  sizeof(get_channel_short)), 0);
	expect_error(&ctx, 0, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	expect_error(&ctx, 1, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	expect_error(&ctx, 2, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
	expect_error(&ctx, 3, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  get_channel_not_found,
							  sizeof(get_channel_not_found)), 0);
	expect_error(&ctx, 0, LICHEN_MESHCORE_ERR_NOT_FOUND);
}

ZTEST(meshcore_adapter, test_serial_split_frame_dispatches_once)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	uint8_t serial[5];
	const uint8_t payload[] = { 0x0a };

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      payload, sizeof(payload), serial, sizeof(serial)),
		      4);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, serial, 2U),
		      0);
	zassert_equal(ctx.count, 0U);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, &serial[2],
							 2U), 0);
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      stream_frame_count, 1U);
}

ZTEST(meshcore_adapter, test_reset_clears_partial_stream)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	uint8_t serial[5];
	const uint8_t payload[] = { 0x0a };

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE,
			      payload, sizeof(payload), serial, sizeof(serial)),
		      4);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, serial, 2U),
		      0);
	lichen_meshcore_adapter_reset(&adapter);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, &serial[2],
							 2U), 0);
	zassert_equal(ctx.count, 0U);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      stream_frame_count, 0U);
}

ZTEST(meshcore_adapter, test_serial_malformed_and_oversize_are_rejected)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t bad_marker[] = { 0x3e, 0x01, 0x00, 0x0a };
	const uint8_t zero_len[] = { 0x3c, 0x00, 0x00 };
	const uint8_t oversize[] = {
		0x3c,
		(uint8_t)(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD + 1U),
		0x00,
	};

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, bad_marker,
							  sizeof(bad_marker)), 0);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, zero_len,
							  sizeof(zero_len)), 0);
	zassert_equal(lichen_meshcore_adapter_feed_stream(&adapter, oversize,
							  sizeof(oversize)), 0);
	zassert_equal(ctx.count, 0U);
	zassert_true(lichen_meshcore_adapter_get_stats(&adapter)->
		     malformed_count >= 3U);
}

ZTEST(meshcore_adapter, test_output_backpressure_propagates)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t get_contacts[] = { 0x04 };

	init_adapter(&adapter, &ctx, 1U);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_contacts,
							  sizeof(get_contacts)),
		      -ENOMEM);
	zassert_equal(ctx.count, 0U);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      enqueue_fail_count, 1U);
}

ZTEST(meshcore_adapter, test_multiframe_requires_capacity_callback)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t get_contacts[] = { 0x04 };
	const struct lichen_meshcore_adapter_ops ops = {
		.enqueue_tx = enqueue_cb,
		.user_data = &ctx,
	};

	memset(&ctx, 0, sizeof(ctx));
	ctx.limit = OUT_DEPTH;
	lichen_meshcore_adapter_init(&adapter, &ops);

	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, get_contacts,
							  sizeof(get_contacts)),
		      -ENOSYS);
	zassert_equal(ctx.count, 0U);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      enqueue_fail_count, 1U);
}

ZTEST(meshcore_adapter, test_serial_encoder_bounds)
{
	uint8_t out[4];
	const uint8_t payload[] = { 0x0a };

	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_DEVICE_TO_APP,
			      payload, sizeof(payload), out, sizeof(out)),
		      4);
	zassert_equal(out[0], LICHEN_MESHCORE_SERIAL_DEVICE_TO_APP);
	zassert_equal(sys_get_le16(&out[1]), 1U);
	zassert_equal(out[3], payload[0]);

	zassert_equal(lichen_meshcore_encode_serial_frame(0x99, payload,
							  sizeof(payload), out,
							  sizeof(out)),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_DEVICE_TO_APP,
			      payload, sizeof(payload), out, 3U),
		      -EINVAL);
	zassert_equal(lichen_meshcore_encode_serial_frame(
			      LICHEN_MESHCORE_SERIAL_DEVICE_TO_APP,
			      payload, 0U, out, sizeof(out)),
		      -EINVAL);
}

ZTEST_SUITE(meshcore_adapter, NULL, NULL, NULL, NULL, NULL);
