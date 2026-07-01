/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
#include <lichen/app_identity/app_identity.h>
#endif
#include <lichen/meshcore/adapter.h>

#include "meshcore_vectors.h"

#define OUT_DEPTH 8
#define SELF_INFO_PUBLIC_KEY_OFF 4U
#define SELF_INFO_PUBLIC_KEY_LEN 32U
#define SELF_INFO_NAME_OFF 58U
#define DEVICE_INFO_BUILD_OFF 8U
#define DEVICE_INFO_MODEL_OFF 20U
#define DEVICE_INFO_VERSION_OFF 60U

struct out_slot {
	uint8_t data[LICHEN_MESHCORE_FRAME_MAX];
	size_t len;
};

struct test_ctx {
	struct out_slot out[OUT_DEPTH];
	size_t count;
	size_t limit;
	uint8_t submit_channel;
	uint8_t submit_text_type;
	uint8_t submit_payload[LICHEN_MESHCORE_FRAME_MAX];
	size_t submit_payload_len;
	uint32_t submit_count;
	int submit_ret;
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

static int submit_text_cb(uint8_t channel, uint8_t text_type,
			  const uint8_t *payload, size_t payload_len,
			  void *user_data)
{
	struct test_ctx *ctx = user_data;

	if (ctx == NULL || (payload == NULL && payload_len > 0U) ||
	    payload_len > sizeof(ctx->submit_payload)) {
		return -EINVAL;
	}
	if (ctx->submit_ret < 0) {
		return ctx->submit_ret;
	}

	ctx->submit_channel = channel;
	ctx->submit_text_type = text_type;
	ctx->submit_payload_len = payload_len;
	if (payload_len > 0U) {
		memcpy(ctx->submit_payload, payload, payload_len);
	}
	ctx->submit_count++;
	return 0;
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

static void init_adapter_with_submit(struct lichen_meshcore_adapter *adapter,
				     struct test_ctx *ctx, size_t limit)
{
	const struct lichen_meshcore_adapter_ops ops = {
		.enqueue_tx = enqueue_cb,
		.tx_free = tx_free_cb,
		.submit_text = submit_text_cb,
		.user_data = ctx,
	};

	memset(ctx, 0, sizeof(*ctx));
	ctx->limit = limit;
	lichen_meshcore_adapter_init(adapter, &ops);
}

static void init_adapter_with_submit_no_tx_free(
	struct lichen_meshcore_adapter *adapter, struct test_ctx *ctx)
{
	const struct lichen_meshcore_adapter_ops ops = {
		.enqueue_tx = enqueue_cb,
		.submit_text = submit_text_cb,
		.user_data = ctx,
	};

	memset(ctx, 0, sizeof(*ctx));
	ctx->limit = OUT_DEPTH;
	lichen_meshcore_adapter_init(adapter, &ops);
}

static void expect_error(const struct test_ctx *ctx, size_t slot, uint8_t err)
{
	zassert_true(slot < ctx->count);
	zassert_equal(ctx->out[slot].len, 2U);
	zassert_equal(ctx->out[slot].data[0], LICHEN_MESHCORE_RESP_ERR);
	zassert_equal(ctx->out[slot].data[1], err);
}

static void expect_bytes(const struct test_ctx *ctx, size_t slot,
			 const uint8_t *expected, size_t expected_len)
{
	zassert_true(slot < ctx->count);
	zassert_equal(ctx->out[slot].len, expected_len, "slot %zu length", slot);
	zassert_mem_equal(ctx->out[slot].data, expected, expected_len,
			  "slot %zu bytes", slot);
}

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
static bool contains_bytes(const uint8_t *haystack, size_t haystack_len,
			   const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0U || haystack_len < needle_len) {
		return false;
	}

	for (size_t i = 0U; i <= haystack_len - needle_len; i++) {
		if (memcmp(&haystack[i], needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
}

static void before_each(const struct ztest_unit_test *test, void *fixture)
{
	ARG_UNUSED(test);
	ARG_UNUSED(fixture);
	lichen_app_identity_test_reset();
}

ZTEST_RULE(meshcore_adapter_identity_reset, before_each, NULL);
#endif

ZTEST(meshcore_adapter, test_canonical_app_compat_vectors)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;

	Z_TEST_SKIP_IFDEF(CONFIG_LICHEN_APP_IDENTITY);

	zassert_equal(MESHCORE_VECTOR_SOURCE_COUNT, 33U);
	zassert_equal(MESHCORE_VECTOR_ADAPTER_COUNT,
		      ARRAY_SIZE(meshcore_vectors));
	zassert_equal(MESHCORE_VECTOR_ADAPTER_COUNT, 27U);

	for (size_t i = 0U; i < ARRAY_SIZE(meshcore_vectors); i++) {
		const struct meshcore_vector *v = &meshcore_vectors[i];

		init_adapter(&adapter, &ctx, OUT_DEPTH);
		zassert_equal(lichen_meshcore_adapter_process_raw(
				      &adapter, v->request, v->request_len),
			      0, "%s dispatch failed", v->name);
		zassert_equal(ctx.count, v->response_count,
			      "%s response count", v->name);
		expect_bytes(&ctx, 0U, v->response0, v->response0_len);
		if (v->response_count == 2U) {
			expect_bytes(&ctx, 1U, v->response1,
				     v->response1_len);
		}
	}
}

ZTEST(meshcore_adapter, test_app_start_without_identity_is_degraded)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t app_start[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 't' };
	uint8_t zero_key[SELF_INFO_PUBLIC_KEY_LEN] = { 0 };

	Z_TEST_SKIP_IFDEF(CONFIG_LICHEN_APP_IDENTITY);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, app_start,
							  sizeof(app_start)), 0);
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_SELF_INFO);
	zassert_equal(ctx.out[0].len, 64U);
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_PUBLIC_KEY_OFF], zero_key,
			  sizeof(zero_key));
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_NAME_OFF], "LICHEN", 6U);
}

ZTEST(meshcore_adapter, test_app_start_without_published_identity_is_degraded)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t app_start[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 't' };
	uint8_t zero_key[SELF_INFO_PUBLIC_KEY_LEN] = { 0 };

	Z_TEST_SKIP_IFNDEF(CONFIG_LICHEN_APP_IDENTITY);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, app_start,
							  sizeof(app_start)), 0);
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_SELF_INFO);
	zassert_equal(ctx.out[0].len, 64U);
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_PUBLIC_KEY_OFF], zero_key,
			  sizeof(zero_key));
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_NAME_OFF], "LICHEN", 6U);
}

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
ZTEST(meshcore_adapter, test_app_start_uses_provider_self_identity)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t app_start[] = { 0x01, 0, 0, 0, 0, 0, 0, 0, 't' };
	struct lichen_app_identity_self self = {
		.eui64 = { 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01 },
		.public_key = {
			0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
			0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
			0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
			0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		},
		.display_name = "node-a",
		.firmware_name = "fw-a",
		.has_public_key = true,
	};

	zassert_ok(lichen_app_identity_set_self(&self));
	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, app_start,
							  sizeof(app_start)), 0);
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_SELF_INFO);
	zassert_equal(ctx.out[0].len, 64U);
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_PUBLIC_KEY_OFF],
			  self.public_key, sizeof(self.public_key));
	zassert_mem_equal(&ctx.out[0].data[SELF_INFO_NAME_OFF], "node-a", 6U);
}

ZTEST(meshcore_adapter, test_device_query_uses_provider_names_without_key)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t device_query[] = { 0x16, 0x03 };
	struct lichen_app_identity_self self = {
		.eui64 = { 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x02 },
		.public_key = {
			0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
			0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
			0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
			0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
		},
		.display_name = "node-a",
		.firmware_name = "fw-a",
		.has_public_key = true,
	};

	zassert_ok(lichen_app_identity_set_self(&self));
	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  device_query,
							  sizeof(device_query)), 0);
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_DEVICE_INFO);
	zassert_equal(ctx.out[0].len, 82U);
	zassert_equal(ctx.out[0].data[1], LICHEN_MESHCORE_APP_PROTOCOL_VERSION);
	zassert_mem_equal(&ctx.out[0].data[DEVICE_INFO_BUILD_OFF], "fw-a", 4U);
	zassert_mem_equal(&ctx.out[0].data[DEVICE_INFO_MODEL_OFF], "node-a", 6U);
	zassert_mem_equal(&ctx.out[0].data[DEVICE_INFO_VERSION_OFF], "fw-a", 4U);
	zassert_false(contains_bytes(ctx.out[0].data, ctx.out[0].len,
				     self.public_key, sizeof(self.public_key)));
}
#endif

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
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	struct lichen_app_identity_self self = {
		.eui64 = { 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x03 },
		.public_key = {
			0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
			0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
			0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		},
		.display_name = "node-b",
		.firmware_name = "fw-b",
		.has_public_key = true,
	};

	zassert_ok(lichen_app_identity_set_self(&self));
#endif

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

ZTEST(meshcore_adapter, test_send_channel_text_submits_local_message)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG,
		0x00, /* compatibility channel */
		0x00, /* plain text */
		'h', 'i',
	};

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, send,
							  sizeof(send)), 0);
	zassert_equal(ctx.submit_count, 1U);
	zassert_equal(ctx.submit_channel, 0U);
	zassert_equal(ctx.submit_text_type, 0U);
	zassert_equal(ctx.submit_payload_len, 2U);
	zassert_mem_equal(ctx.submit_payload, "hi", 2U);
	expect_bytes(&ctx, 0U, (const uint8_t[]){ LICHEN_MESHCORE_RESP_OK },
		     1U);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      submitted_text_count, 1U);
}

ZTEST(meshcore_adapter, test_send_channel_text_validation_errors)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t too_short[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00,
	};
	const uint8_t unknown_channel[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x01, 0x00, 'x',
	};
	const uint8_t unsupported_type[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x01, 'x',
	};
	const uint8_t invalid_utf8[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 0x80,
	};
	const uint8_t valid[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'x',
	};

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, too_short,
							  sizeof(too_short)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  unknown_channel,
							  sizeof(unknown_channel)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_NOT_FOUND);

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  unsupported_type,
							  sizeof(unsupported_type)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  invalid_utf8,
							  sizeof(invalid_utf8)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, valid,
							  sizeof(valid)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
}

ZTEST(meshcore_adapter, test_send_channel_text_callback_errors_map)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t valid[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'x',
	};

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	ctx.submit_ret = -EMSGSIZE;
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, valid,
							  sizeof(valid)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);

	init_adapter_with_submit(&adapter, &ctx, OUT_DEPTH);
	ctx.submit_ret = -ENOMEM;
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, valid,
							  sizeof(valid)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_TABLE_FULL);

	init_adapter_with_submit(&adapter, &ctx, 0U);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, valid,
							  sizeof(valid)), -ENOMEM);
	zassert_equal(ctx.submit_count, 0U);
	zassert_equal(ctx.count, 0U);

	init_adapter_with_submit_no_tx_free(&adapter, &ctx);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, valid,
							  sizeof(valid)), -ENOMEM);
	zassert_equal(ctx.submit_count, 0U);
	zassert_equal(ctx.count, 0U);
}

ZTEST(meshcore_adapter, test_send_direct_text_without_peer_is_not_found)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t direct[] = {
		LICHEN_MESHCORE_CMD_SEND_TXT_MSG,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		'h', 'i',
	};
	const uint8_t direct_short[] = {
		LICHEN_MESHCORE_CMD_SEND_TXT_MSG,
		0x01, 0x02, 0x03,
	};
	const uint8_t direct_invalid_utf8[] = {
		LICHEN_MESHCORE_CMD_SEND_TXT_MSG,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0xc0,
	};

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, direct,
							  sizeof(direct)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_NOT_FOUND);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, direct_short,
							  sizeof(direct_short)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter,
							  direct_invalid_utf8,
							  sizeof(direct_invalid_utf8)), 0);
	expect_error(&ctx, 0U, LICHEN_MESHCORE_ERR_ILLEGAL_ARG);
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
	case LICHEN_MESHCORE_CMD_SEND_TXT_MSG:
	case LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG:
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

ZTEST(meshcore_adapter, test_incoming_text_waiting_and_sync_next)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_meshcore_incoming_text event = {
		.id = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_ok(lichen_meshcore_adapter_emit_text(&adapter, &event));
	zassert_equal(ctx.count, 1U);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_PUSH_MSG_WAITING);

	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, sync_next,
							  sizeof(sync_next)), 0);
	zassert_equal(ctx.count, 2U);
	zassert_equal(ctx.out[1].data[0],
		      LICHEN_MESHCORE_RESP_CHANNEL_MSG_RECV_V3);
	zassert_equal(ctx.out[1].len, 13U);
	zassert_equal(sys_get_le32(&ctx.out[1].data[7]), event.id);
	zassert_mem_equal(&ctx.out[1].data[11], payload, sizeof(payload));

	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, sync_next,
							  sizeof(sync_next)), 0);
	zassert_equal(ctx.out[2].data[0], LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES);
}

ZTEST(meshcore_adapter, test_incoming_status_waiting_and_sync_next)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_meshcore_incoming_status event = {
		.request_id = 0x12345678U,
		.error_reason = 9U,
		.has_error_reason = true,
	};

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_ok(lichen_meshcore_adapter_emit_status(&adapter, &event));
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_PUSH_MSG_WAITING);

	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, sync_next,
							  sizeof(sync_next)), 0);
	zassert_equal(ctx.out[1].data[0], LICHEN_MESHCORE_PUSH_SEND_CONFIRMED);
	zassert_equal(ctx.out[1].len, 7U);
	zassert_equal(sys_get_le32(&ctx.out[1].data[1]), event.request_id);
	zassert_equal(ctx.out[1].data[5], event.error_reason);
	zassert_equal(ctx.out[1].data[6], 1U);
}

ZTEST(meshcore_adapter, test_incoming_queue_full_and_waiting_backpressure)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const uint8_t payload[] = { 'x' };
	const struct lichen_meshcore_incoming_text event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	init_adapter(&adapter, &ctx, 0U);
	zassert_equal(lichen_meshcore_adapter_emit_text(&adapter, &event),
		      -ENOMEM);
	zassert_equal(ctx.count, 0U);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      waiting_push_fail_count, 1U);

	ctx.limit = OUT_DEPTH;
	zassert_equal(lichen_meshcore_adapter_process_raw(&adapter, sync_next,
							  sizeof(sync_next)), 0);
	zassert_equal(ctx.out[0].data[0], LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES);

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	for (uint32_t i = 0U; i < CONFIG_LICHEN_MESHCORE_PENDING_EVENTS; i++) {
		zassert_ok(lichen_meshcore_adapter_emit_text(&adapter, &event));
	}
	zassert_equal(lichen_meshcore_adapter_emit_text(&adapter, &event),
		      -ENOMEM);
	zassert_equal(lichen_meshcore_adapter_get_stats(&adapter)->
		      pending_full_count, 1U);
}

ZTEST(meshcore_adapter, test_incoming_validation)
{
	struct lichen_meshcore_adapter adapter;
	struct test_ctx ctx;
	uint8_t too_big[LICHEN_MESHCORE_FRAME_MAX] = { 0 };
	const struct lichen_meshcore_incoming_text bad_text = {
		.payload = too_big,
		.payload_len = sizeof(too_big),
	};
	const struct lichen_meshcore_incoming_status bad_status = { 0 };
	const struct lichen_meshcore_incoming_status bad_reason = {
		.request_id = 1U,
		.error_reason = 256U,
		.has_error_reason = true,
	};

	init_adapter(&adapter, &ctx, OUT_DEPTH);
	zassert_equal(lichen_meshcore_adapter_emit_text(&adapter, NULL), -EINVAL);
	zassert_equal(lichen_meshcore_adapter_emit_text(&adapter, &bad_text),
		      -EMSGSIZE);
	zassert_equal(lichen_meshcore_adapter_emit_status(&adapter, NULL),
		      -EINVAL);
	zassert_equal(lichen_meshcore_adapter_emit_status(&adapter, &bad_status),
		      -ENOTSUP);
	zassert_equal(lichen_meshcore_adapter_emit_status(&adapter, &bad_reason),
		      -ERANGE);
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
