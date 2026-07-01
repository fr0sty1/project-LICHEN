/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/app_interface/app_interface.h>
#include <lichen/app_interface/hal_bridge.h>

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
	uint8_t last_to_iid[8];
	uint16_t rank;
	int8_t tx_power_dbm;
	struct lichen_app_location_time_snapshot location_time;
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
	if (event->has_to_iid) {
		memcpy(ctx->last_to_iid, event->to_iid,
		       sizeof(ctx->last_to_iid));
	}
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
	if (event->has_to_iid) {
		memcpy(ctx->last_to_iid, event->to_iid,
		       sizeof(ctx->last_to_iid));
	}
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
	status->power = (struct lichen_app_power_snapshot){
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = true,
		.battery_percent = 77U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = 3980U,
		.charging_valid = true,
		.charging = true,
		.external_power_valid = true,
		.external_power = false,
	};
	status->location_time = ctx->location_time;
	return 0;
}

static int get_minimal_status_sink(struct lichen_app_status_snapshot *status,
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
	const uint8_t to_iid[] = { 0x02, 0xaa, 0, 0, 1, 2, 3, 4 };
	const struct lichen_app_text_event event = {
		.from = 10U,
		.to = 20U,
		.id = 30U,
		.to_iid = { 0x02, 0xaa, 0, 0, 1, 2, 3, 4 },
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
		.has_to_iid = true,
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
	zassert_equal(submit.last_to, event.to);
	zassert_mem_equal(submit.last_to_iid, to_iid, sizeof(to_iid));
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
	ctx.location_time = (struct lichen_app_location_time_snapshot){
		.location_provider_available = true,
		.time_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.source_name = "gnss0",
		.fix_state_valid = true,
		.fix_state = LICHEN_APP_LOCATION_FIX_3D,
		.age_seconds_valid = true,
		.age_seconds = 5U,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
		.vertical_accuracy_mm_valid = true,
		.vertical_accuracy_mm = 7500U,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.fix_source_valid = true,
		.fix_source = LICHEN_APP_FIX_SOURCE_GNSS,
	};
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));

	zassert_ok(lichen_app_interface_get_status(&status));
	zassert_equal(status.rank, 17U);
	zassert_true(status.rpl_capable);
	zassert_true(status.power.battery_provider_available);
	zassert_true(status.power.pmic_provider_available);
	zassert_true(status.power.battery_percent_valid);
	zassert_equal(status.power.battery_percent, 77U);
	zassert_true(status.power.battery_voltage_mv_valid);
	zassert_equal(status.power.battery_voltage_mv, 3980U);
	zassert_true(status.power.charging_valid);
	zassert_true(status.power.charging);
	zassert_true(status.power.external_power_valid);
	zassert_false(status.power.external_power);
	zassert_true(status.location_time.location_provider_available);
	zassert_true(status.location_time.time_provider_available);
	zassert_true(status.location_time.source_class_valid);
	zassert_equal(status.location_time.source_class,
		      LICHEN_APP_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_str_equal(status.location_time.source_name, "gnss0");
	zassert_true(status.location_time.fix_state_valid);
	zassert_equal(status.location_time.fix_state, LICHEN_APP_LOCATION_FIX_3D);
	zassert_true(status.location_time.age_seconds_valid);
	zassert_equal(status.location_time.age_seconds, 5U);
	zassert_true(status.location_time.horizontal_accuracy_mm_valid);
	zassert_equal(status.location_time.horizontal_accuracy_mm, 2500U);
	zassert_true(status.location_time.vertical_accuracy_mm_valid);
	zassert_equal(status.location_time.vertical_accuracy_mm, 7500U);
	zassert_true(status.location_time.latitude_e7_valid);
	zassert_equal(status.location_time.latitude_e7, 476206130);
	zassert_true(status.location_time.longitude_e7_valid);
	zassert_equal(status.location_time.longitude_e7, -1223493000);
	zassert_true(status.location_time.altitude_m_valid);
	zassert_equal(status.location_time.altitude_m, 42);
	zassert_true(status.location_time.fix_time_unix_valid);
	zassert_equal(status.location_time.fix_time_unix, 1710000000U);
	zassert_true(status.location_time.satellites_valid);
	zassert_equal(status.location_time.satellites, 9U);
	zassert_true(status.location_time.fix_source_valid);
	zassert_equal(status.location_time.fix_source, LICHEN_APP_FIX_SOURCE_GNSS);

	zassert_ok(lichen_app_interface_get_config(&config));
	zassert_true(config.has_tx_power_dbm);
	zassert_equal(config.tx_power_dbm, 14);

	config.tx_power_dbm = 10;
	config.has_tx_power_dbm = true;
	zassert_ok(lichen_app_interface_set_config(&config));
	zassert_equal(ctx.tx_power_dbm, 10);
}

ZTEST(app_interface, test_status_provider_omitted_power_stays_unknown)
{
	struct sink_ctx ctx;
	struct lichen_app_status_snapshot status = {
		.power = {
			.battery_provider_available = true,
			.pmic_provider_available = true,
			.battery_percent_valid = true,
			.battery_percent = 77U,
			.battery_voltage_mv_valid = true,
			.battery_voltage_mv = 3980U,
			.charging_valid = true,
			.charging = true,
			.external_power_valid = true,
			.external_power = true,
		},
		.location_time = {
			.location_provider_available = true,
			.time_provider_available = true,
			.latitude_e7_valid = true,
			.latitude_e7 = 1,
			.longitude_e7_valid = true,
			.longitude_e7 = 2,
			.altitude_m_valid = true,
			.altitude_m = 3,
			.fix_time_unix_valid = true,
			.fix_time_unix = 4U,
			.satellites_valid = true,
			.satellites = 5U,
			.fix_source_valid = true,
			.fix_source = LICHEN_APP_FIX_SOURCE_GNSS,
		},
	};
	const struct lichen_app_interface_sink sink = {
		.get_status = get_minimal_status_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	ctx.rank = 17U;
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));

	zassert_ok(lichen_app_interface_get_status(&status));
	zassert_equal(status.rank, 17U);
	zassert_true(status.rpl_capable);
	zassert_false(status.power.battery_provider_available);
	zassert_false(status.power.pmic_provider_available);
	zassert_false(status.power.battery_percent_valid);
	zassert_equal(status.power.battery_percent, 0U);
	zassert_false(status.power.battery_voltage_mv_valid);
	zassert_equal(status.power.battery_voltage_mv, 0U);
	zassert_false(status.power.charging_valid);
	zassert_false(status.power.charging);
	zassert_false(status.power.external_power_valid);
	zassert_false(status.power.external_power);
	zassert_false(status.location_time.location_provider_available);
	zassert_false(status.location_time.time_provider_available);
	zassert_false(status.location_time.source_class_valid);
	zassert_equal(status.location_time.source_class,
		      LICHEN_APP_LOCATION_SOURCE_NONE);
	zassert_str_equal(status.location_time.source_name, "");
	zassert_false(status.location_time.fix_state_valid);
	zassert_equal(status.location_time.fix_state, LICHEN_APP_LOCATION_FIX_NONE);
	zassert_false(status.location_time.age_seconds_valid);
	zassert_equal(status.location_time.age_seconds, 0U);
	zassert_false(status.location_time.horizontal_accuracy_mm_valid);
	zassert_equal(status.location_time.horizontal_accuracy_mm, 0U);
	zassert_false(status.location_time.vertical_accuracy_mm_valid);
	zassert_equal(status.location_time.vertical_accuracy_mm, 0U);
	zassert_false(status.location_time.latitude_e7_valid);
	zassert_equal(status.location_time.latitude_e7, 0);
	zassert_false(status.location_time.longitude_e7_valid);
	zassert_equal(status.location_time.longitude_e7, 0);
	zassert_false(status.location_time.altitude_m_valid);
	zassert_equal(status.location_time.altitude_m, 0);
	zassert_false(status.location_time.fix_time_unix_valid);
	zassert_equal(status.location_time.fix_time_unix, 0U);
	zassert_false(status.location_time.satellites_valid);
	zassert_equal(status.location_time.satellites, 0U);
	zassert_false(status.location_time.fix_source_valid);
	zassert_equal(status.location_time.fix_source, LICHEN_APP_FIX_SOURCE_NONE);
}

ZTEST(app_interface, test_status_provider_stale_location_metadata_round_trips)
{
	struct sink_ctx ctx;
	struct lichen_app_status_snapshot status;
	const struct lichen_app_interface_sink sink = {
		.get_status = get_status_sink,
		.user_data = &ctx,
	};

	reset_ctx(&ctx);
	ctx.rank = 17U;
	ctx.location_time = (struct lichen_app_location_time_snapshot){
		.location_provider_available = true,
		.time_provider_available = false,
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC,
		.source_name = "manual",
		.fix_state_valid = true,
		.fix_state = LICHEN_APP_LOCATION_FIX_STALE,
		.age_seconds_valid = true,
		.age_seconds = 301U,
	};
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));

	zassert_ok(lichen_app_interface_get_status(&status));
	zassert_true(status.location_time.location_provider_available);
	zassert_false(status.location_time.time_provider_available);
	zassert_true(status.location_time.source_class_valid);
	zassert_equal(status.location_time.source_class,
		      LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC);
	zassert_str_equal(status.location_time.source_name, "manual");
	zassert_true(status.location_time.fix_state_valid);
	zassert_equal(status.location_time.fix_state, LICHEN_APP_LOCATION_FIX_STALE);
	zassert_true(status.location_time.age_seconds_valid);
	zassert_equal(status.location_time.age_seconds, 301U);
	zassert_false(status.location_time.latitude_e7_valid);
	zassert_false(status.location_time.longitude_e7_valid);
	zassert_false(status.location_time.fix_source_valid);
}

ZTEST(app_interface, test_location_time_hal_bridge_maps_provider_metadata)
{
	const struct lichen_hal_location_time_snapshot hal = {
		.location_provider_available = true,
		.time_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.source_name = "mesh-derived-location",
		.fix_state_valid = true,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.age_seconds_valid = true,
		.age_seconds = 7U,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
		.vertical_accuracy_mm_valid = true,
		.vertical_accuracy_mm = 7500U,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.fix_source_valid = true,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
	};
	struct lichen_app_location_time_snapshot app;

	zassert_equal(lichen_app_location_time_from_hal(NULL, &hal), -EINVAL);
	zassert_equal(lichen_app_location_time_from_hal(&app, NULL), -EINVAL);
	zassert_ok(lichen_app_location_time_from_hal(&app, &hal));

	zassert_true(app.location_provider_available);
	zassert_true(app.time_provider_available);
	zassert_true(app.source_class_valid);
	zassert_equal(app.source_class, LICHEN_APP_LOCATION_SOURCE_NETWORK);
	zassert_str_equal(app.source_name, "mesh-derived-location");
	zassert_true(app.fix_state_valid);
	zassert_equal(app.fix_state, LICHEN_APP_LOCATION_FIX_3D);
	zassert_true(app.age_seconds_valid);
	zassert_equal(app.age_seconds, 7U);
	zassert_true(app.horizontal_accuracy_mm_valid);
	zassert_equal(app.horizontal_accuracy_mm, 2500U);
	zassert_true(app.vertical_accuracy_mm_valid);
	zassert_equal(app.vertical_accuracy_mm, 7500U);
	zassert_true(app.latitude_e7_valid);
	zassert_equal(app.latitude_e7, 476206130);
	zassert_true(app.longitude_e7_valid);
	zassert_equal(app.longitude_e7, -1223493000);
	zassert_true(app.altitude_m_valid);
	zassert_equal(app.altitude_m, 42);
	zassert_true(app.fix_time_unix_valid);
	zassert_equal(app.fix_time_unix, 1710000000U);
	zassert_true(app.satellites_valid);
	zassert_equal(app.satellites, 9U);
	zassert_true(app.fix_source_valid);
	zassert_equal(app.fix_source, LICHEN_APP_FIX_SOURCE_GNSS);
}

ZTEST(app_interface, test_location_time_hal_bridge_maps_stale_metadata)
{
	const struct lichen_hal_location_time_snapshot hal = {
		.location_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.source_name = "manual",
		.fix_state_valid = true,
		.fix_state = LICHEN_HAL_LOCATION_FIX_STALE,
		.age_seconds_valid = true,
		.age_seconds = 301U,
	};
	struct lichen_app_location_time_snapshot app;

	zassert_ok(lichen_app_location_time_from_hal(&app, &hal));

	zassert_true(app.location_provider_available);
	zassert_false(app.time_provider_available);
	zassert_true(app.source_class_valid);
	zassert_equal(app.source_class, LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC);
	zassert_str_equal(app.source_name, "manual");
	zassert_true(app.fix_state_valid);
	zassert_equal(app.fix_state, LICHEN_APP_LOCATION_FIX_STALE);
	zassert_true(app.age_seconds_valid);
	zassert_equal(app.age_seconds, 301U);
	zassert_false(app.latitude_e7_valid);
	zassert_false(app.longitude_e7_valid);
	zassert_false(app.fix_source_valid);
	zassert_equal(app.fix_source, LICHEN_APP_FIX_SOURCE_NONE);
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
