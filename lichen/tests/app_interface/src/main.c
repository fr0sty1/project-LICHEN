/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/app_interface/app_interface.h>

struct sink_ctx {
	uint32_t text_count;
	uint32_t status_count;
	uint32_t submit_count;
	int text_ret;
	int status_ret;
	int submit_ret;
	int get_status_ret;
	int get_config_ret;
	int set_config_ret;
	uint32_t last_from;
	uint32_t last_to;
	uint32_t last_id;
	uint32_t last_request_id;
	uint16_t rank;
	int8_t tx_power_dbm;
	uint8_t payload[CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD];
	size_t payload_len;
};

static int text_sink(const struct lichen_app_text_event *event, void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (event == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->text_ret < 0) {
		return ctx->text_ret;
	}

	ctx->text_count++;
	ctx->last_from = event->from;
	ctx->last_to = event->to;
	ctx->last_id = event->id;
	ctx->payload_len = event->payload_len;
	if (event->payload_len > 0U) {
		memcpy(ctx->payload, event->payload, event->payload_len);
	}
	return 0;
}

static int submit_text_sink(const struct lichen_app_text_event *event,
			    void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (event == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->submit_ret < 0) {
		return ctx->submit_ret;
	}

	ctx->submit_count++;
	ctx->last_from = event->from;
	ctx->last_to = event->to;
	ctx->last_id = event->id;
	ctx->payload_len = event->payload_len;
	if (event->payload_len > 0U) {
		memcpy(ctx->payload, event->payload, event->payload_len);
	}
	return 0;
}

static int status_sink(const struct lichen_app_status_event *event,
		       void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (event == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->status_ret < 0) {
		return ctx->status_ret;
	}

	ctx->status_count++;
	ctx->last_from = event->from;
	ctx->last_to = event->to;
	ctx->last_id = event->id;
	ctx->last_request_id = event->request_id;
	return 0;
}

static int get_status_sink(struct lichen_app_status_snapshot *status,
			   void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (status == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->get_status_ret < 0) {
		return ctx->get_status_ret;
	}

	status->rank = ctx->rank;
	status->uptime_seconds = 42U;
	status->role = "test";
	status->rpl_capable = true;
	return 0;
}

static int get_config_sink(struct lichen_app_config_snapshot *config,
			   void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (config == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->get_config_ret < 0) {
		return ctx->get_config_ret;
	}

	config->tx_power_dbm = ctx->tx_power_dbm;
	config->has_tx_power_dbm = true;
	return 0;
}

static int set_config_sink(const struct lichen_app_config_snapshot *config,
			   void *user_data)
{
	struct sink_ctx *ctx = user_data;

	if (config == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->set_config_ret < 0) {
		return ctx->set_config_ret;
	}

	if (config->has_tx_power_dbm) {
		ctx->tx_power_dbm = config->tx_power_dbm;
	}
	return 0;
}

static void reset_ctx(struct sink_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static struct lichen_app_interface_stats stats(void)
{
	struct lichen_app_interface_stats out;

	zassert_ok(lichen_app_interface_copy_stats(&out));
	return out;
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_app_interface_test_reset();
}

ZTEST(app_interface, test_text_fanout_to_multiple_sinks)
{
	struct sink_ctx a;
	struct sink_ctx b;
	const uint8_t payload[] = { 'h', 'i' };
	const struct lichen_app_text_event event = {
		.from = 1U,
		.to = 2U,
		.id = 3U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};
	const struct lichen_app_interface_sink sink_a = {
		.emit_text = text_sink,
		.user_data = &a,
	};
	const struct lichen_app_interface_sink sink_b = {
		.emit_text = text_sink,
		.user_data = &b,
	};

	reset_ctx(&a);
	reset_ctx(&b);
	zassert_ok(lichen_app_interface_register_sink(&sink_a, NULL));
	zassert_ok(lichen_app_interface_register_sink(&sink_b, NULL));
	zassert_ok(lichen_app_interface_emit_text(&event));

	zassert_equal(a.text_count, 1U);
	zassert_equal(b.text_count, 1U);
	zassert_mem_equal(a.payload, payload, sizeof(payload));
	zassert_equal(stats().text_delivery_count, 2U);
}

ZTEST(app_interface, test_status_fanout)
{
	struct sink_ctx ctx;
	const struct lichen_app_status_event event = {
		.from = 7U,
		.to = 8U,
		.id = 9U,
		.request_id = 0x12345678U,
		.has_id = true,
	};
	const struct lichen_app_interface_sink sink = {
		.emit_status = status_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_ok(lichen_app_interface_emit_status(&event));

	zassert_equal(ctx.status_count, 1U);
	zassert_equal(ctx.last_request_id, event.request_id);
	zassert_equal(stats().status_delivery_count, 1U);
}

ZTEST(app_interface, test_submit_text_uses_separate_sink)
{
	struct sink_ctx emit;
	struct sink_ctx submit;
	const uint8_t payload[] = { 'h', 'i' };
	const struct lichen_app_text_event event = {
		.from = 10U,
		.to = 20U,
		.id = 30U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};
	const struct lichen_app_interface_sink emit_sink = {
		.emit_text = text_sink,
		.user_data = &emit,
	};
	const struct lichen_app_interface_sink submit_sink = {
		.submit_text = submit_text_sink,
		.user_data = &submit,
	};

	reset_ctx(&emit);
	reset_ctx(&submit);
	zassert_ok(lichen_app_interface_register_sink(&emit_sink, NULL));
	zassert_ok(lichen_app_interface_register_sink(&submit_sink, NULL));
	zassert_ok(lichen_app_interface_submit_text(&event));

	zassert_equal(emit.text_count, 0U);
	zassert_equal(submit.submit_count, 1U);
	zassert_equal(submit.last_from, event.from);
	zassert_mem_equal(submit.payload, payload, sizeof(payload));
	zassert_equal(stats().text_submit_count, 1U);
	zassert_equal(stats().text_submit_delivery_count, 1U);
}

ZTEST(app_interface, test_no_subscriber_is_unsupported)
{
	const uint8_t payload[] = { 'x' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	zassert_equal(lichen_app_interface_emit_text(&event), -ENOTSUP);
	zassert_equal(lichen_app_interface_submit_text(&event), -ENOTSUP);
	zassert_equal(stats().no_subscriber_count, 2U);
}

ZTEST(app_interface, test_backpressure_propagates)
{
	struct sink_ctx ctx;
	const uint8_t payload[] = { 'x' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	const struct lichen_app_interface_sink sink = {
		.emit_text = text_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	ctx.text_ret = -ENOMEM;
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOMEM);
	zassert_equal(stats().backpressure_count, 1U);
}

ZTEST(app_interface, test_submit_backpressure_propagates)
{
	struct sink_ctx ctx;
	const uint8_t payload[] = { 'x' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	const struct lichen_app_interface_sink sink = {
		.submit_text = submit_text_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	ctx.submit_ret = -ENOMEM;
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_equal(lichen_app_interface_submit_text(&event), -ENOMEM);
	zassert_equal(stats().backpressure_count, 1U);
}

ZTEST(app_interface, test_partial_fanout_records_errors_but_succeeds)
{
	struct sink_ctx ok;
	struct sink_ctx full;
	const uint8_t payload[] = { 'x' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	const struct lichen_app_interface_sink sink_ok = {
		.emit_text = text_sink,
		.user_data = &ok,
	};
	const struct lichen_app_interface_sink sink_full = {
		.emit_text = text_sink,
		.user_data = &full,
	};

	reset_ctx(&ok);
	reset_ctx(&full);
	full.text_ret = -ENOMEM;
	zassert_ok(lichen_app_interface_register_sink(&sink_ok, NULL));
	zassert_ok(lichen_app_interface_register_sink(&sink_full, NULL));
	zassert_ok(lichen_app_interface_emit_text(&event));
	zassert_equal(stats().backpressure_count, 1U);
}

ZTEST(app_interface, test_invalid_inputs_and_payload_bounds)
{
	uint8_t payload[CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD + 1U] = { 0 };
	const struct lichen_app_text_event too_big = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	zassert_equal(lichen_app_interface_register_sink(NULL, NULL), -EINVAL);
	zassert_equal(lichen_app_interface_emit_text(NULL), -EINVAL);
	zassert_equal(lichen_app_interface_emit_status(NULL), -EINVAL);
	zassert_equal(lichen_app_interface_emit_text(&too_big), -EMSGSIZE);
	zassert_equal(lichen_app_interface_submit_text(&too_big), -EMSGSIZE);
	zassert_equal(stats().invalid_count, 4U);
}

ZTEST(app_interface, test_register_capacity_and_unregister)
{
	struct sink_ctx a;
	struct sink_ctx b;
	struct sink_ctx c;
	uint8_t id;
	const struct lichen_app_interface_sink sink_a = {
		.emit_text = text_sink,
		.user_data = &a,
	};
	const struct lichen_app_interface_sink sink_b = {
		.emit_text = text_sink,
		.user_data = &b,
	};
	const struct lichen_app_interface_sink sink_c = {
		.emit_text = text_sink,
		.user_data = &c,
	};

	reset_ctx(&a);
	reset_ctx(&b);
	reset_ctx(&c);
	zassert_ok(lichen_app_interface_register_sink(&sink_a, &id));
	zassert_ok(lichen_app_interface_register_sink(&sink_b, NULL));
	zassert_equal(lichen_app_interface_register_sink(&sink_c, NULL), -ENOMEM);
	zassert_ok(lichen_app_interface_unregister_sink(id));
	zassert_equal(lichen_app_interface_unregister_sink(id), -ENOENT);
	zassert_ok(lichen_app_interface_register_sink(&sink_c, NULL));
}

ZTEST(app_interface, test_status_and_config_provider_hooks)
{
	struct sink_ctx ctx;
	struct lichen_app_status_snapshot status;
	struct lichen_app_config_snapshot config;
	const struct lichen_app_interface_sink sink = {
		.get_status = get_status_sink,
		.get_config = get_config_sink,
		.set_config = set_config_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	ctx.rank = 17U;
	ctx.tx_power_dbm = 14;
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));

	zassert_ok(lichen_app_interface_get_status(&status));
	zassert_equal(status.rank, 17U);
	zassert_true(status.rpl_capable);

	zassert_ok(lichen_app_interface_get_config(&config));
	zassert_true(config.has_tx_power_dbm);
	zassert_equal(config.tx_power_dbm, 14);

	config.tx_power_dbm = 10;
	config.has_tx_power_dbm = true;
	zassert_ok(lichen_app_interface_set_config(&config));
	zassert_equal(ctx.tx_power_dbm, 10);
}

ZTEST(app_interface, test_provider_hooks_are_single_owner)
{
	struct sink_ctx a;
	struct sink_ctx b;
	const struct lichen_app_interface_sink status_owner = {
		.get_status = get_status_sink,
		.user_data = &a,
	};
	const struct lichen_app_interface_sink status_duplicate = {
		.get_status = get_status_sink,
		.user_data = &b,
	};
	const struct lichen_app_interface_sink config_owner = {
		.get_config = get_config_sink,
		.user_data = &a,
	};
	const struct lichen_app_interface_sink config_duplicate = {
		.set_config = set_config_sink,
		.user_data = &b,
	};
	const struct lichen_app_interface_sink submit_owner = {
		.submit_text = submit_text_sink,
		.user_data = &a,
	};
	const struct lichen_app_interface_sink submit_duplicate = {
		.submit_text = submit_text_sink,
		.user_data = &b,
	};

	reset_ctx(&a);
	reset_ctx(&b);
	zassert_ok(lichen_app_interface_register_sink(&status_owner, NULL));
	zassert_equal(lichen_app_interface_register_sink(&status_duplicate, NULL),
		      -EALREADY);
	lichen_app_interface_test_reset();

	zassert_ok(lichen_app_interface_register_sink(&config_owner, NULL));
	zassert_equal(lichen_app_interface_register_sink(&config_duplicate, NULL),
		      -EALREADY);
	lichen_app_interface_test_reset();

	zassert_ok(lichen_app_interface_register_sink(&submit_owner, NULL));
	zassert_equal(lichen_app_interface_register_sink(&submit_duplicate, NULL),
		      -EALREADY);
}

ZTEST(app_interface, test_missing_providers_are_unsupported)
{
	struct lichen_app_status_snapshot status;
	struct lichen_app_config_snapshot config = {
		.tx_power_dbm = 1,
		.has_tx_power_dbm = true,
	};

	zassert_equal(lichen_app_interface_get_status(&status), -ENOTSUP);
	zassert_equal(lichen_app_interface_get_config(&config), -ENOTSUP);
	zassert_equal(lichen_app_interface_set_config(&config), -ENOTSUP);
	zassert_equal(lichen_app_interface_get_status(NULL), -EINVAL);
	zassert_equal(lichen_app_interface_get_config(NULL), -EINVAL);
	zassert_equal(lichen_app_interface_set_config(NULL), -EINVAL);
	zassert_equal(lichen_app_interface_copy_stats(NULL), -EINVAL);
}

ZTEST_SUITE(app_interface, NULL, NULL, before, NULL, NULL);
