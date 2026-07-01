/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include "ble_app_owner.h"
#include "ble_uart.h"

#define TEST_UUID_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

static const uint8_t s_nus_uuid_value[] = { TEST_UUID_VAL };

static const struct bt_data s_native_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, TEST_UUID_VAL),
};

static const struct bt_data s_named_sd[] = {
	BT_DATA(BT_DATA_NAME_SHORTENED, "LICHEN", sizeof("LICHEN") - 1U),
};

static void assert_flags_data(const struct bt_data *data)
{
	zassert_not_null(data);
	zassert_equal(data->type, BT_DATA_FLAGS);
	zassert_equal(data->data_len, 1U);
	zassert_equal(data->data[0], BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR);
}

static void assert_uuid128_data(const struct bt_data *data,
				const uint8_t *uuid_value)
{
	zassert_not_null(data);
	zassert_equal(data->type, BT_DATA_UUID128_ALL);
	zassert_equal(data->data_len, 16U);
	zassert_mem_equal(data->data, uuid_value, 16U);
}

static bool compiled_surface_enabled(enum ble_app_owner_surface surface)
{
	switch (surface) {
	case BLE_APP_OWNER_SURFACE_NATIVE:
		return IS_ENABLED(CONFIG_LORA_LICHEN_BLE);
	case BLE_APP_OWNER_SURFACE_MESHTASTIC:
		return IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE);
	case BLE_APP_OWNER_SURFACE_MESHCORE:
		return IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_BLE);
	default:
		return false;
	}
}

static bool any_compiled_surface_enabled(void)
{
	return IS_ENABLED(CONFIG_LORA_LICHEN_BLE) ||
	       IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE) ||
	       IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_BLE);
}

static bool surface_can_start(enum ble_app_owner_surface surface)
{
	if (!any_compiled_surface_enabled()) {
		return true;
	}

	return compiled_surface_enabled(surface);
}

static int expect_start_for_surface(const struct ble_app_owner_advertising *adv)
{
	const int ret = ble_app_owner_start(adv);

	if (surface_can_start(adv->surface)) {
		zassert_ok(ret);
	} else {
		zassert_equal(ret, -ENOTSUP);
	}

	return ret;
}

static void owner_before(void *fixture)
{
	ARG_UNUSED(fixture);
	ble_app_owner_test_reset();
}

ZTEST(ble_app_owner, test_current_product_modes_are_mutually_exclusive)
{
	zassert_ok(ble_app_owner_test_validate_modes(false, false, false));
	zassert_ok(ble_app_owner_test_validate_modes(true, false, false));
	zassert_ok(ble_app_owner_test_validate_modes(false, true, false));
	zassert_ok(ble_app_owner_test_validate_modes(false, false, true));
	zassert_equal(ble_app_owner_test_validate_modes(true, true, false),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(true, false, true),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(false, true, true),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(true, true, true),
		      -ENOTSUP);
}

ZTEST(ble_app_owner, test_native_advertising_shape_validates)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	zassert_ok(ble_app_owner_test_validate_advertising(&adv));
}

ZTEST(ble_app_owner, test_meshtastic_scan_response_shape_validates)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};

	zassert_ok(ble_app_owner_test_validate_advertising(&adv));
}

ZTEST(ble_app_owner, test_invalid_advertising_is_deterministic)
{
	const struct ble_app_owner_advertising no_ad = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising sd_without_data = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd_len = 1U,
		.name = "MeshCore-LICHEN",
	};
	const struct ble_app_owner_advertising no_name = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
	};
	const struct ble_app_owner_advertising bad_surface = {
		.surface = (enum ble_app_owner_surface)99,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	zassert_equal(ble_app_owner_test_validate_advertising(NULL), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&no_ad), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&sd_without_data),
		      -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&no_name), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&bad_surface),
		      -EINVAL);
}

ZTEST(ble_app_owner, test_start_is_single_enable_and_advertising_owner)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	struct ble_app_owner_test_state state;

	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_true(state.has_surface);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHTASTIC);
	zassert_equal_ptr(state.ad, s_native_ad);
	zassert_equal(state.ad_len, ARRAY_SIZE(s_native_ad));
	zassert_equal_ptr(state.sd, s_named_sd);
	zassert_equal(state.sd_len, ARRAY_SIZE(s_named_sd));

	zassert_ok(ble_app_owner_start(&adv));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
}

ZTEST(ble_app_owner, test_conflicting_surface_does_not_prepare_or_advertise)
{
	const struct ble_app_owner_advertising first = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising second = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};
	struct ble_app_owner_test_state state;

	if (expect_start_for_surface(&first) < 0) {
		return;
	}
	zassert_equal(ble_app_owner_start(&second),
		      surface_can_start(second.surface) ? -EALREADY : -ENOTSUP);
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_NATIVE);
}

ZTEST(ble_app_owner, test_restart_reuses_stored_advertising)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};
	struct ble_app_owner_test_state state;

	zassert_equal(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHCORE),
		      -EINVAL);
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_ok(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHCORE));
	zassert_equal(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHTASTIC),
		      -EINVAL);

	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 2U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHCORE);
	zassert_equal_ptr(state.ad, s_native_ad);
	zassert_equal_ptr(state.sd, s_named_sd);
}

ZTEST(ble_app_owner, test_stop_clears_active_advertising_owner)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	struct ble_app_owner_test_state state;

	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_MESHTASTIC),
		      -EINVAL);
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_NATIVE),
		      -EINVAL);
	zassert_ok(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_MESHTASTIC));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.adv_stop_count, 1U);
	zassert_false(state.has_surface);

	zassert_ok(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHTASTIC));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.adv_start_count, 2U);
	zassert_true(state.has_surface);
}

ZTEST(ble_app_owner, test_backend_failures_are_reported)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	ble_app_owner_test_set_backend(-EIO, 0, 0);
	if (surface_can_start(adv.surface)) {
		zassert_equal(ble_app_owner_start(&adv), -EIO);
	} else {
		zassert_equal(ble_app_owner_start(&adv), -ENOTSUP);
	}

	ble_app_owner_test_reset();
	ble_app_owner_test_set_backend(0, -EIO, 0);
	if (surface_can_start(adv.surface)) {
		zassert_equal(ble_app_owner_start(&adv), -EIO);
	} else {
		zassert_equal(ble_app_owner_start(&adv), -ENOTSUP);
	}

	ble_app_owner_test_reset();
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	ble_app_owner_test_set_backend(0, 0, -EIO);
	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_NATIVE), -EIO);
}

ZTEST(ble_app_owner, test_compiled_product_mode_accepts_only_matching_surface)
{
	const struct ble_app_owner_advertising native = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising meshtastic = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising meshcore = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};

	(void)expect_start_for_surface(&native);
	ble_app_owner_test_reset();
	(void)expect_start_for_surface(&meshtastic);
	ble_app_owner_test_reset();
	(void)expect_start_for_surface(&meshcore);
}

ZTEST(ble_app_owner, test_native_init_uses_owner_advertising)
{
	struct ble_app_owner_test_state state;

	if (!IS_ENABLED(CONFIG_LORA_LICHEN_BLE)) {
		ztest_test_skip();
	}

	zassert_ok(ble_uart_init());
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_NATIVE);
	zassert_equal(state.ad_len, 2U);
	zassert_equal(state.sd_len, 0U);
	assert_flags_data(&state.ad[0]);
	assert_uuid128_data(&state.ad[1], s_nus_uuid_value);
	zassert_true((state.adv_options & BT_LE_ADV_OPT_CONNECTABLE) != 0U);
	zassert_true((state.adv_options & BT_LE_ADV_OPT_USE_NAME) != 0U);
}

ZTEST_SUITE(ble_app_owner, NULL, NULL, owner_before, NULL, NULL);
