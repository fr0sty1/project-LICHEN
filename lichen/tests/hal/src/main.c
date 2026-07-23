/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/ztest.h>

#include <zephyr/drivers/adc/adc_emul.h>
#if DT_NODE_HAS_COMPAT(DT_ALIAS(pmic0), sbs_sbs_charger)
#include <zephyr/drivers/charger.h>
#endif
#if DT_NODE_HAS_COMPAT(DT_ALIAS(battery0), sbs_sbs_gauge_new_api)
/* Zephyr 3.7's fuel_gauge.h inline helpers (and emul) loop signed vs size_t,
 * triggering -Wsign-compare under LICHEN's -Werror.
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#include <zephyr/drivers/fuel_gauge.h>
#include <zephyr/drivers/emul.h>
#include <zephyr/drivers/emul_fuel_gauge.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif

#include <lichen/hal.h>

ZTEST(hal, test_headless_native_defaults_are_deterministic)
{
	const struct lichen_hal_capabilities *caps = lichen_hal_capabilities_get();

	if (IS_ENABLED(CONFIG_LICHEN_HAS_LORA) ||
	    IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		ztest_test_skip();
	}

	zassert_not_null(caps, "caps must be present");
	zassert_equal(caps->flags, 0U, "native_sim test should not claim hardware caps");
	zassert_equal(caps->radio, LICHEN_HAL_RADIO_NONE);
	zassert_equal(caps->ui, LICHEN_HAL_UI_HEADLESS);
	zassert_equal(caps->location, LICHEN_HAL_LOCATION_NONE);
	zassert_equal(caps->time, LICHEN_HAL_TIME_UPTIME);

	zassert_false(lichen_hal_has_capability(LICHEN_HAL_CAP_LORA));
	zassert_false(lichen_hal_has_capability(LICHEN_HAL_CAP_GNSS));
}

ZTEST(hal, test_loopback_lora_capability_when_enabled)
{
	const struct lichen_hal_capabilities *caps = lichen_hal_capabilities_get();
	const struct device *dev = NULL;

	if (!IS_ENABLED(CONFIG_LICHEN_HAS_LORA)) {
		ztest_test_skip();
	}

	zassert_true(lichen_hal_has_capability(LICHEN_HAL_CAP_LORA));
	zassert_equal(caps->radio, LICHEN_HAL_RADIO_LOOPBACK);
	zassert_equal(lichen_hal_capability_status(LICHEN_HAL_CAP_LORA), 0);
	zassert_equal(lichen_hal_lora_device_get(&dev), 0);
	zassert_not_null(dev);
}

ZTEST(hal, test_identity_reports_board_and_caps)
{
	const struct lichen_hal_capabilities *caps = lichen_hal_capabilities_get();
	struct lichen_hal_identity identity = { 0 };

	lichen_hal_identity_get(&identity);

	zassert_str_equal(identity.board_name, "native-hal-test");
	zassert_str_equal(identity.zephyr_board, CONFIG_BOARD);
	zassert_equal(identity.caps.flags, caps->flags);
	zassert_equal(identity.caps.radio, caps->radio);

	lichen_hal_identity_get(NULL);
}

ZTEST(hal, test_capability_status_rejects_invalid_queries)
{
	zassert_equal(lichen_hal_capability_status(0), -EINVAL);
	zassert_equal(lichen_hal_capability_status(LICHEN_HAL_CAP_LORA |
						  LICHEN_HAL_CAP_GNSS),
		      -EINVAL);
	zassert_equal(lichen_hal_capability_status(BIT(31)), -EINVAL);
}

ZTEST(hal, test_headless_status_apis_are_deterministic)
{
	const enum lichen_hal_capability unsupported_caps[] = {
		LICHEN_HAL_CAP_GNSS,
		LICHEN_HAL_CAP_BATTERY,
		LICHEN_HAL_CAP_PMIC,
		LICHEN_HAL_CAP_BUTTONS,
		LICHEN_HAL_CAP_LEDS,
		LICHEN_HAL_CAP_DISPLAY,
		LICHEN_HAL_CAP_EXTERNAL_FLASH,
		LICHEN_HAL_CAP_SERIAL_LOCAL,
		LICHEN_HAL_CAP_BLE_LOCAL,
	};

	for (size_t i = 0; i < ARRAY_SIZE(unsupported_caps); i++) {
		if (unsupported_caps[i] == LICHEN_HAL_CAP_BATTERY &&
		    IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
			continue;
		}
		if (unsupported_caps[i] == LICHEN_HAL_CAP_PMIC &&
		    IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
			continue;
		}
		zassert_equal(lichen_hal_capability_status(unsupported_caps[i]),
			      -ENOTSUP,
			      "capability %u should be unsupported",
			      (uint32_t)unsupported_caps[i]);
	}

	if (IS_ENABLED(CONFIG_LICHEN_HAS_LORA)) {
		zassert_equal(lichen_hal_capability_status(LICHEN_HAL_CAP_LORA), 0);
		zassert_equal(lichen_hal_lora_status(), 0);
	} else {
		zassert_equal(lichen_hal_capability_status(LICHEN_HAL_CAP_LORA),
			      -ENOTSUP);
		zassert_equal(lichen_hal_lora_status(), -ENOTSUP);
	}

	zassert_equal(lichen_hal_serial_local_status(), -ENOTSUP);
	zassert_equal(lichen_hal_ble_local_status(), -ENOTSUP);
	zassert_equal(lichen_hal_gnss_status(), -ENOTSUP);
	if (IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		zassert_ok(lichen_hal_battery_status());
	} else {
		zassert_equal(lichen_hal_battery_status(), -ENOTSUP);
	}
	if (IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
		zassert_ok(lichen_hal_pmic_status());
	} else {
		zassert_equal(lichen_hal_pmic_status(), -ENOTSUP);
	}
	zassert_equal(lichen_hal_buttons_status(), -ENOTSUP);
	zassert_equal(lichen_hal_leds_status(), -ENOTSUP);
	zassert_equal(lichen_hal_display_status(), -ENOTSUP);
	zassert_equal(lichen_hal_external_flash_status(), -ENOTSUP);
	zassert_equal(lichen_hal_location_status(), -ENOTSUP);
	zassert_equal(lichen_hal_time_status(), 0);
}

ZTEST(hal, test_absent_devices_return_unsupported)
{
	const struct device *dev = (const struct device *)0x1;
	struct gpio_dt_spec gpio = {
		.port = (const struct device *)0x1,
	};

	zassert_equal(lichen_hal_lora_device_get(NULL), -EINVAL);
	if (IS_ENABLED(CONFIG_LICHEN_HAS_LORA)) {
		zassert_equal(lichen_hal_lora_device_get(&dev), 0);
		zassert_not_null(dev);
	} else {
		zassert_equal(lichen_hal_lora_device_get(&dev), -ENOTSUP);
		zassert_is_null(dev);
	}

	dev = (const struct device *)0x1;
	zassert_equal(lichen_hal_gnss_device_get(NULL), -EINVAL);
	zassert_equal(lichen_hal_gnss_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

	dev = (const struct device *)0x1;
	zassert_equal(lichen_hal_display_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

	dev = (const struct device *)0x1;
	zassert_equal(lichen_hal_serial_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

	dev = (const struct device *)0x1;
	if (IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		zassert_ok(lichen_hal_battery_device_get(&dev));
		zassert_not_null(dev);
	} else {
		zassert_equal(lichen_hal_battery_device_get(&dev), -ENOTSUP);
		zassert_is_null(dev);
	}

	dev = (const struct device *)0x1;
	if (IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
		zassert_ok(lichen_hal_pmic_device_get(&dev));
		zassert_not_null(dev);
	} else {
		zassert_equal(lichen_hal_pmic_device_get(&dev), -ENOTSUP);
		zassert_is_null(dev);
	}

	zassert_equal(lichen_hal_led_get(NULL), -EINVAL);
	zassert_equal(lichen_hal_led_get(&gpio), -ENOTSUP);
	zassert_is_null(gpio.port);

	gpio.port = (const struct device *)0x1;
	zassert_equal(lichen_hal_button_get(NULL), -EINVAL);
	zassert_equal(lichen_hal_button_get(&gpio), -ENOTSUP);
	zassert_is_null(gpio.port);

	dev = (const struct device *)0x1;
	zassert_equal(lichen_hal_external_flash_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

	zassert_equal(lichen_hal_ble_local_status(), -ENOTSUP);
}

ZTEST(hal, test_power_snapshot_absent_providers_is_explicitly_unknown)
{
	struct lichen_hal_power_snapshot snapshot = {
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = true,
		.battery_percent = 42U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = 3700U,
		.charging_valid = true,
		.charging = true,
		.external_power_valid = true,
		.external_power = true,
	};

	zassert_equal(lichen_hal_power_snapshot_get(NULL), -EINVAL);
	zassert_ok(lichen_hal_power_snapshot_get(&snapshot));

	if (IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		zassert_true(snapshot.battery_provider_available);
	} else {
		zassert_false(snapshot.battery_provider_available);
	}
	if (IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
		zassert_true(snapshot.pmic_provider_available);
	} else {
		zassert_false(snapshot.pmic_provider_available);
	}
	if (IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		if (DT_NODE_HAS_COMPAT(DT_ALIAS(battery0), sbs_sbs_gauge_new_api)) {
			zassert_true(snapshot.battery_percent_valid);
		} else {
			zassert_false(snapshot.battery_percent_valid);
			zassert_equal(snapshot.battery_percent, 0U);
		}
		zassert_false(snapshot.battery_voltage_mv_valid);
		zassert_equal(snapshot.battery_voltage_mv, 0U);
	} else {
		zassert_false(snapshot.battery_percent_valid);
		zassert_equal(snapshot.battery_percent, 0U);
		zassert_false(snapshot.battery_voltage_mv_valid);
		zassert_equal(snapshot.battery_voltage_mv, 0U);
	}
	if (IS_ENABLED(CONFIG_LICHEN_HAS_PMIC) &&
	    DT_NODE_HAS_COMPAT(DT_ALIAS(pmic0), sbs_sbs_charger)) {
		zassert_true(snapshot.charging_valid);
		zassert_true(snapshot.external_power_valid);
	} else {
		zassert_false(snapshot.charging_valid);
		zassert_false(snapshot.charging);
		zassert_false(snapshot.external_power_valid);
		zassert_false(snapshot.external_power);
	}
}

ZTEST(hal, test_power_snapshot_reports_adc_backed_battery_voltage)
{
#if IS_ENABLED(CONFIG_ADC_EMUL) && \
	DT_NODE_HAS_STATUS(DT_ALIAS(battery0), okay) && \
	DT_NODE_HAS_STATUS(DT_NODELABEL(adc0), okay)
	const struct device *adc = NULL;
	const struct device *battery = NULL;
	struct lichen_hal_power_snapshot snapshot;

	if (!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		ztest_test_skip();
	}

	adc = DEVICE_DT_GET(DT_NODELABEL(adc0));
	zassert_true(device_is_ready(adc));
	zassert_ok(adc_emul_const_value_set(adc, 7U, 2400U));

	zassert_true(lichen_hal_has_capability(LICHEN_HAL_CAP_BATTERY));
	zassert_ok(lichen_hal_battery_status());
	zassert_ok(lichen_hal_battery_device_get(&battery));
	zassert_not_null(battery);

	zassert_ok(lichen_hal_power_snapshot_get(&snapshot));
	zassert_true(snapshot.battery_provider_available);
	zassert_true(snapshot.battery_voltage_mv_valid);
	zassert_within(snapshot.battery_voltage_mv, 4001U, 3U);
	zassert_false(snapshot.battery_percent_valid);
	zassert_false(snapshot.pmic_provider_available);
#else
	ztest_test_skip();
#endif
}

ZTEST(hal, test_power_snapshot_reports_fuel_gauge_and_charger_values)
{
#if DT_NODE_HAS_COMPAT(DT_ALIAS(battery0), sbs_sbs_gauge_new_api) && \
	DT_NODE_HAS_COMPAT(DT_ALIAS(pmic0), sbs_sbs_charger)
	const struct emul *battery_emul = EMUL_DT_GET(DT_ALIAS(battery0));
	const struct device *battery = NULL;
	const struct device *pmic = NULL;
	struct lichen_hal_power_snapshot snapshot;

	if (!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	    !IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
		ztest_test_skip();
	}

	zassert_ok(emul_fuel_gauge_set_battery_charging(
		battery_emul, 4000000U, 250000U));

	zassert_ok(lichen_hal_battery_device_get(&battery));
	zassert_not_null(battery);
	zassert_ok(lichen_hal_pmic_device_get(&pmic));
	zassert_not_null(pmic);

	zassert_ok(lichen_hal_power_snapshot_get(&snapshot));
	zassert_true(snapshot.battery_provider_available);
	zassert_true(snapshot.pmic_provider_available);
	zassert_true(snapshot.battery_percent_valid);
	zassert_equal(snapshot.battery_percent, 1U);
	zassert_true(snapshot.battery_voltage_mv_valid);
	zassert_equal(snapshot.battery_voltage_mv, 4000U);
	zassert_true(snapshot.charging_valid);
	zassert_false(snapshot.charging);
	zassert_true(snapshot.external_power_valid);
	zassert_false(snapshot.external_power);
#else
	ztest_test_skip();
#endif
}

ZTEST(hal, test_power_snapshot_rejects_out_of_range_percent)
{
	zassert_true(lichen_hal_power_test_percent_valid(0U));
	zassert_true(lichen_hal_power_test_percent_valid(100U));
	zassert_false(lichen_hal_power_test_percent_valid(101U));
	zassert_false(lichen_hal_power_test_percent_valid(UINT8_MAX));
}

ZTEST(hal, test_power_snapshot_maps_charger_states)
{
#if DT_NODE_HAS_COMPAT(DT_ALIAS(pmic0), sbs_sbs_charger)
	zassert_false(lichen_hal_power_test_charger_status_known(
		CHARGER_STATUS_UNKNOWN));
	zassert_true(lichen_hal_power_test_charger_status_known(
		CHARGER_STATUS_CHARGING));
	zassert_true(lichen_hal_power_test_charger_status_known(
		CHARGER_STATUS_DISCHARGING));
	zassert_true(lichen_hal_power_test_charger_status_known(
		CHARGER_STATUS_NOT_CHARGING));
	zassert_true(lichen_hal_power_test_charger_status_known(
		CHARGER_STATUS_FULL));
	zassert_false(lichen_hal_power_test_charger_status_known(INT_MAX));
	zassert_true(lichen_hal_power_test_charger_status_is_charging(
		CHARGER_STATUS_CHARGING));
	zassert_false(lichen_hal_power_test_charger_status_is_charging(
		CHARGER_STATUS_DISCHARGING));
	zassert_false(lichen_hal_power_test_charger_status_is_charging(INT_MAX));
	zassert_true(lichen_hal_power_test_charger_online_known(
		CHARGER_ONLINE_OFFLINE));
	zassert_true(lichen_hal_power_test_charger_online_known(
		CHARGER_ONLINE_FIXED));
	zassert_true(lichen_hal_power_test_charger_online_known(
		CHARGER_ONLINE_PROGRAMMABLE));
	zassert_false(lichen_hal_power_test_charger_online_known(INT_MAX));
	zassert_false(lichen_hal_power_test_charger_online_external_power(
		CHARGER_ONLINE_OFFLINE));
	zassert_true(lichen_hal_power_test_charger_online_external_power(
		CHARGER_ONLINE_FIXED));
	zassert_true(lichen_hal_power_test_charger_online_external_power(
		CHARGER_ONLINE_PROGRAMMABLE));
	zassert_false(lichen_hal_power_test_charger_online_external_power(INT_MAX));
#else
	ztest_test_skip();
#endif
}

ZTEST(hal, test_reset_diagnostics_and_request_boundaries)
{
	struct lichen_hal_reset_diagnostics_snapshot snapshot = {
		.reboot_supported = false,
		.warm_reboot_best_effort = true,
		.factory_reset_supported = true,
		.reset_cause_supported = true,
		.reset_cause_clear_supported = true,
		.reset_cause_valid = true,
		.reset_cause = UINT32_MAX,
		.supported_reset_cause_valid = true,
		.supported_reset_cause = UINT32_MAX,
		.reset_cause_raw_valid = true,
		.reset_cause_raw = UINT32_MAX,
		.supported_reset_cause_raw_valid = true,
		.supported_reset_cause_raw = UINT32_MAX,
		.retained_diagnostics_supported = true,
		.retained_crash_valid = true,
		.retained_crash_reason = UINT32_MAX,
	};
	enum lichen_hal_reset_request invalid =
		(enum lichen_hal_reset_request)UINT32_MAX;

	zassert_equal(lichen_hal_reset_diagnostics_snapshot_get(NULL), -EINVAL);
	zassert_ok(lichen_hal_reset_diagnostics_snapshot_get(&snapshot));
	zassert_equal(snapshot.reboot_supported, IS_ENABLED(CONFIG_REBOOT));
	zassert_equal(snapshot.warm_reboot_best_effort, IS_ENABLED(CONFIG_REBOOT));
	zassert_false(snapshot.factory_reset_supported);
	zassert_false(snapshot.retained_diagnostics_supported);
	zassert_false(snapshot.retained_crash_valid);
	zassert_equal(snapshot.retained_crash_reason, 0U);

	if (!snapshot.reset_cause_supported) {
		zassert_false(snapshot.reset_cause_valid);
		zassert_equal(snapshot.reset_cause, 0U);
		zassert_false(snapshot.supported_reset_cause_valid);
		zassert_equal(snapshot.supported_reset_cause, 0U);
	}
	if (!snapshot.reset_cause_valid) {
		zassert_false(snapshot.reset_cause_raw_valid);
		zassert_equal(snapshot.reset_cause_raw, 0U);
	}
	if (!snapshot.supported_reset_cause_valid) {
		zassert_false(snapshot.supported_reset_cause_raw_valid);
		zassert_equal(snapshot.supported_reset_cause_raw, 0U);
	}
	zassert_false(snapshot.reset_cause_clear_supported);
	zassert_equal(lichen_hal_reset_diagnostics_clear(), -ENOTSUP);

	zassert_equal(lichen_hal_reset_request(invalid), -EINVAL);
	zassert_equal(lichen_hal_reset_request(
			      LICHEN_HAL_RESET_REQUEST_FACTORY_RESET),
		      -ENOTSUP);

	lichen_hal_reset_test_clear_request();
	zassert_false(lichen_hal_reset_test_last_request_valid());
	if (IS_ENABLED(CONFIG_REBOOT)) {
		zassert_ok(lichen_hal_reboot_status());
		zassert_ok(lichen_hal_reset_request(
			LICHEN_HAL_RESET_REQUEST_COLD_REBOOT));
		zassert_true(lichen_hal_reset_test_last_request_valid());
		zassert_equal(lichen_hal_reset_test_last_request(),
			      LICHEN_HAL_RESET_REQUEST_COLD_REBOOT);

		zassert_ok(lichen_hal_reset_request(
			LICHEN_HAL_RESET_REQUEST_WARM_REBOOT));
		zassert_equal(lichen_hal_reset_test_last_request(),
			      LICHEN_HAL_RESET_REQUEST_WARM_REBOOT);
	} else {
		zassert_equal(lichen_hal_reboot_status(), -ENOTSUP);
		zassert_equal(lichen_hal_reset_request(
				      LICHEN_HAL_RESET_REQUEST_COLD_REBOOT),
			      -ENOTSUP);
		zassert_false(lichen_hal_reset_test_last_request_valid());
	}
}

ZTEST(hal, test_location_time_snapshot_absent_providers_is_explicitly_unknown)
{
	struct lichen_hal_location_time_snapshot snapshot = {
		.location_provider_available = true,
		.time_provider_available = true,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.altitude_cm_valid = true,
		.altitude_cm = 4249,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.fix_source_valid = true,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
	};

	zassert_equal(lichen_hal_location_time_snapshot_get(NULL), -EINVAL);
	lichen_hal_location_time_test_set_snapshot(NULL);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_false(snapshot.location_provider_available);
	zassert_false(snapshot.time_provider_available);
	zassert_false(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 0);
	zassert_false(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, 0);
	zassert_false(snapshot.altitude_m_valid);
	zassert_equal(snapshot.altitude_m, 0);
	zassert_false(snapshot.altitude_cm_valid);
	zassert_equal(snapshot.altitude_cm, 0);
	zassert_false(snapshot.fix_time_unix_valid);
	zassert_equal(snapshot.fix_time_unix, 0U);
	zassert_false(snapshot.satellites_valid);
	zassert_equal(snapshot.satellites, 0U);
	zassert_false(snapshot.fix_source_valid);
	zassert_equal(snapshot.fix_source, LICHEN_HAL_FIX_SOURCE_NONE);
}

ZTEST(hal, test_location_time_snapshot_test_hook_round_trips_and_resets)
{
	const struct lichen_hal_location_time_snapshot injected = {
		.location_provider_available = true,
		.time_provider_available = true,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.altitude_cm_valid = true,
		.altitude_cm = 4249,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.fix_source_valid = true,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_time_test_set_snapshot(&injected);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.location_provider_available);
	zassert_true(snapshot.time_provider_available);
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 476206130);
	zassert_true(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, -1223493000);
	zassert_true(snapshot.altitude_m_valid);
	zassert_equal(snapshot.altitude_m, 42);
	zassert_true(snapshot.altitude_cm_valid);
	zassert_equal(snapshot.altitude_cm, 4249);
	zassert_true(snapshot.fix_time_unix_valid);
	zassert_equal(snapshot.fix_time_unix, 1710000000U);
	zassert_true(snapshot.satellites_valid);
	zassert_equal(snapshot.satellites, 9U);
	zassert_true(snapshot.fix_source_valid);
	zassert_equal(snapshot.fix_source, LICHEN_HAL_FIX_SOURCE_GNSS);

	lichen_hal_location_time_test_set_snapshot(NULL);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_false(snapshot.latitude_e7_valid);
	zassert_false(snapshot.fix_time_unix_valid);
}

ZTEST(hal, test_time_provider_uptime_only_does_not_synthesize_wall_clock)
{
	struct lichen_hal_time_snapshot snapshot = {
		.wall_clock_valid = true,
		.unix_time_valid = true,
		.unix_time = 1U,
	};

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(123000);
	zassert_equal(lichen_hal_time_snapshot_get(NULL), -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));

	zassert_true(snapshot.provider_available);
	zassert_false(snapshot.wall_clock_valid);
	zassert_false(snapshot.unix_time_valid);
	zassert_equal(snapshot.unix_time, 0U);
	zassert_equal(snapshot.build_epoch,
		      (uint32_t)CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX);
	zassert_equal(snapshot.effective_epoch_floor,
		      (uint32_t)CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX);
}

ZTEST(hal, test_time_provider_build_epoch_floor_and_diagnostics)
{
	const struct lichen_hal_time_sample below_floor = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "gnss0",
		.unix_time_valid = true,
		.unix_time = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX - 1U,
	};
	const struct lichen_hal_time_sample at_floor = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "gnss0",
		.unix_time_valid = true,
		.unix_time = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX,
		.accuracy_ms_valid = true,
		.accuracy_ms = 1000U,
		.quality_valid = true,
		.quality = 90U,
	};
	const struct lichen_hal_time_sample invalid_source = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NONE,
		.unix_time_valid = true,
		.unix_time = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX,
	};
	const uint32_t provision_epoch =
		CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX + 100U;
	const struct lichen_hal_time_sample below_provision_floor = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "mesh",
		.unix_time_valid = true,
		.unix_time = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX + 50U,
	};
	struct lichen_hal_time_snapshot snapshot;

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_time_provision_epoch_set(provision_epoch, true));
	zassert_equal(lichen_hal_time_submit(&below_provision_floor), -ERANGE);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class, LICHEN_HAL_TIME_SOURCE_NETWORK);
	zassert_false(snapshot.passed_epoch_floor);
	zassert_true(snapshot.rejection_source_class_valid);
	zassert_equal(snapshot.rejection_source_class,
		      LICHEN_HAL_TIME_SOURCE_NETWORK);
	zassert_str_equal(snapshot.rejection_source_name, "mesh");
	zassert_false(snapshot.rejection_passed_epoch_floor);
	lichen_hal_time_provision_epoch_clear();
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.wall_clock_valid);
	zassert_false(snapshot.source_class_valid);
	zassert_false(snapshot.passed_epoch_floor);
	zassert_equal(snapshot.last_rejection, LICHEN_HAL_TIME_REJECT_NONE);
	zassert_false(snapshot.rejection_source_class_valid);

	zassert_equal(lichen_hal_time_submit(NULL), -EINVAL);
	zassert_equal(lichen_hal_time_submit(&below_floor), -ERANGE);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.wall_clock_valid);
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(snapshot.source_name, "gnss0");
	zassert_false(snapshot.unix_time_valid);
	zassert_false(snapshot.passed_epoch_floor);
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR);
	zassert_true(snapshot.rejection_source_class_valid);
	zassert_equal(snapshot.rejection_source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(snapshot.rejection_source_name, "gnss0");
	zassert_false(snapshot.rejection_passed_epoch_floor);

	zassert_equal(lichen_hal_time_submit(&invalid_source), -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.wall_clock_valid);
	zassert_false(snapshot.source_class_valid);
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_INVALID_SOURCE);
	zassert_false(snapshot.rejection_source_class_valid);

	lichen_hal_time_provision_epoch_clear();
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.wall_clock_valid);
	zassert_false(snapshot.unix_time_valid);
	zassert_false(snapshot.source_class_valid);
	zassert_false(snapshot.passed_epoch_floor);

	zassert_ok(lichen_hal_time_submit(&at_floor));
	lichen_hal_location_test_set_uptime_ms(6000);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_true(snapshot.wall_clock_valid);
	zassert_true(snapshot.unix_time_valid);
	zassert_equal(snapshot.unix_time,
		      CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX + 5U);
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(snapshot.source_name, "gnss0");
	zassert_true(snapshot.age_seconds_valid);
	zassert_equal(snapshot.age_seconds, 5U);
	zassert_true(snapshot.accuracy_ms_valid);
	zassert_equal(snapshot.accuracy_ms, 1000U);
	zassert_true(snapshot.quality_valid);
	zassert_equal(snapshot.quality, 90U);
	zassert_true(snapshot.passed_epoch_floor);
}

ZTEST(hal, test_time_provider_provision_epoch_floor_and_recovery)
{
	const uint32_t build_epoch = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX;
	const uint32_t provision_epoch = build_epoch + 100U;
	const uint32_t poisoned_epoch =
		build_epoch + CONFIG_LICHEN_TIME_PROVISION_MAX_LEAD_S + 1U;
	const struct lichen_hal_time_sample between = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "mesh",
		.unix_time_valid = true,
		.unix_time = build_epoch + 50U,
	};
	const struct lichen_hal_time_sample after_provision = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "mesh",
		.unix_time_valid = true,
		.unix_time = provision_epoch,
	};
	struct lichen_hal_time_snapshot snapshot;

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_equal(lichen_hal_time_provision_epoch_set(provision_epoch, false),
		      -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.effective_epoch_floor, build_epoch);
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED);

	zassert_equal(lichen_hal_time_provision_epoch_set(build_epoch - 1U, true),
		      -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_PROVISION_INVALID);

	zassert_ok(lichen_hal_time_provision_epoch_set(provision_epoch, true));
	zassert_equal(lichen_hal_time_submit(&between), -ERANGE);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_true(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.provision_epoch, provision_epoch);
	zassert_equal(snapshot.effective_epoch_floor, provision_epoch);
	zassert_false(snapshot.wall_clock_valid);

	zassert_ok(lichen_hal_time_submit(&after_provision));
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_true(snapshot.wall_clock_valid);
	zassert_equal(snapshot.unix_time, provision_epoch);

	zassert_equal(lichen_hal_time_provision_epoch_set(poisoned_epoch, true),
		      -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_true(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.effective_epoch_floor, provision_epoch);
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE);

	lichen_hal_time_provision_epoch_clear();
	lichen_hal_time_clear();
	zassert_equal(lichen_hal_time_provision_epoch_set(poisoned_epoch, true),
		      -EINVAL);
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.last_rejection,
		      LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE);
	zassert_ok(lichen_hal_time_submit(&between));
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.effective_epoch_floor, build_epoch);
	zassert_true(snapshot.wall_clock_valid);
	zassert_equal(snapshot.unix_time, build_epoch + 50U);

	zassert_ok(lichen_hal_time_provision_epoch_set(provision_epoch, true));
	lichen_hal_time_provision_epoch_clear();
	zassert_ok(lichen_hal_time_snapshot_get(&snapshot));
	zassert_false(snapshot.provision_epoch_valid);
	zassert_equal(snapshot.effective_epoch_floor, build_epoch);
}

ZTEST(hal, test_time_provider_precedence_stale_and_gnss_location_separation)
{
	const uint32_t build_epoch = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX;
	const struct lichen_hal_location_sample gnss_location = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.latitude_e7_valid = true,
		.latitude_e7 = 10,
		.longitude_e7_valid = true,
		.longitude_e7 = 20,
		.fix_time_unix_valid = true,
		.fix_time_unix = build_epoch - 1U,
	};
	const struct lichen_hal_time_sample stale_first = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "stale-gnss",
		.unix_time_valid = true,
		.unix_time = build_epoch + 30U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 0,
		.quality_valid = true,
		.quality = 60U,
	};
	const struct lichen_hal_time_sample diagnostic_first = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "diagnostic-gnss",
		.unix_time_valid = true,
		.unix_time = build_epoch - 1U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
	};
	const struct lichen_hal_time_sample network = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "mesh",
		.unix_time_valid = true,
		.unix_time = build_epoch + 10U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
	};
	const struct lichen_hal_time_sample below_floor_after_stored = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "bad-gnss",
		.unix_time_valid = true,
		.unix_time = build_epoch - 1U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 2000,
	};
	const struct lichen_hal_time_sample manual = {
		.source_class = LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC,
		.source_name = "manual",
		.unix_time_valid = true,
		.unix_time = build_epoch + 20U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 2000,
	};
	const struct lichen_hal_time_sample lower_trust_backwards = {
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "mesh",
		.unix_time_valid = true,
		.unix_time = build_epoch + 1U,
	};
	struct lichen_hal_location_time_snapshot location;
	struct lichen_hal_time_snapshot time;

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_equal(lichen_hal_time_submit(&diagnostic_first), -ERANGE);
	zassert_ok(lichen_hal_time_submit(&network));
	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 2) * 1000);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_false(time.wall_clock_valid);
	zassert_false(time.unix_time_valid);
	zassert_true(time.source_class_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_NETWORK);
	zassert_str_equal(time.source_name, "mesh");
	zassert_true(time.age_seconds_valid);
	zassert_equal(time.age_seconds,
		      CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 1U);

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_time_submit(&network));
	lichen_hal_location_test_set_uptime_ms(2000);
	zassert_equal(lichen_hal_time_submit(&below_floor_after_stored), -ERANGE);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_true(time.wall_clock_valid);
	zassert_true(time.unix_time_valid);
	zassert_true(time.source_class_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_NETWORK);
	zassert_str_equal(time.source_name, "mesh");
	zassert_true(time.rejection_source_class_valid);
	zassert_equal(time.rejection_source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(time.rejection_source_name, "bad-gnss");
	zassert_false(time.rejection_passed_epoch_floor);

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_time_submit(&network));
	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 2) * 1000);
	zassert_equal(lichen_hal_time_submit(&below_floor_after_stored), -ERANGE);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_false(time.wall_clock_valid);
	zassert_false(time.unix_time_valid);
	zassert_true(time.source_class_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(time.source_name, "bad-gnss");
	zassert_false(time.passed_epoch_floor);
	zassert_equal(time.last_rejection,
		      LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR);

	lichen_hal_location_clear();
	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_location_submit(&gnss_location));
	zassert_ok(lichen_hal_location_time_snapshot_get(&location));
	zassert_true(location.latitude_e7_valid);
	zassert_true(location.fix_time_unix_valid);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_false(time.wall_clock_valid);

	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 1) * 1000);
	zassert_equal(lichen_hal_time_submit(&stale_first), -ETIME);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_false(time.wall_clock_valid);
	zassert_false(time.unix_time_valid);
	zassert_true(time.source_class_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_GNSS);
	zassert_str_equal(time.source_name, "stale-gnss");
	zassert_true(time.age_seconds_valid);
	zassert_equal(time.age_seconds,
		      CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 1U);
	zassert_true(time.quality_valid);
	zassert_equal(time.quality, 60U);
	zassert_equal(time.last_rejection, LICHEN_HAL_TIME_REJECT_STALE);

	lichen_hal_time_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_time_submit(&network));
	lichen_hal_location_test_set_uptime_ms(2000);
	zassert_ok(lichen_hal_time_submit(&manual));
	lichen_hal_location_test_set_uptime_ms(3000);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_true(time.wall_clock_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC);
	zassert_equal(time.unix_time, build_epoch + 21U);

	zassert_equal(lichen_hal_time_submit(&lower_trust_backwards), -EALREADY);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_equal(time.last_rejection, LICHEN_HAL_TIME_REJECT_LOWER_TRUST);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC);

	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 10) * 1000);
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	zassert_false(time.wall_clock_valid);
	zassert_false(time.unix_time_valid);
	zassert_true(time.source_class_valid);
	zassert_equal(time.source_class, LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC);
	zassert_str_equal(time.source_name, "manual");
	zassert_true(time.age_seconds_valid);
	zassert_equal(time.age_seconds,
		      CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S + 8U);
}

ZTEST(hal, test_location_provider_submit_fresh_gnss_fix)
{
	const struct lichen_hal_location_sample sample = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
			.longitude_e7_valid = true,
			.longitude_e7 = -1223493000,
			.altitude_m_valid = true,
			.altitude_m = 42,
			.altitude_cm_valid = true,
			.altitude_cm = 4249,
			.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_time_test_set_snapshot(NULL);
	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(6000);
	zassert_ok(lichen_hal_location_submit(&sample));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_true(snapshot.location_provider_available);
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_str_equal(snapshot.source_name, "gnss0");
	zassert_true(snapshot.fix_state_valid);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_3D);
	zassert_true(snapshot.age_seconds_valid);
	zassert_equal(snapshot.age_seconds, 5U);
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 476206130);
	zassert_true(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, -1223493000);
	zassert_true(snapshot.altitude_m_valid);
	zassert_equal(snapshot.altitude_m, 42);
	zassert_true(snapshot.altitude_cm_valid);
	zassert_equal(snapshot.altitude_cm, 4249);
	zassert_true(snapshot.fix_time_unix_valid);
	zassert_equal(snapshot.fix_time_unix, 1710000000U);
	zassert_true(snapshot.satellites_valid);
	zassert_equal(snapshot.satellites, 9U);
	zassert_true(snapshot.horizontal_accuracy_mm_valid);
	zassert_equal(snapshot.horizontal_accuracy_mm, 2500U);
	zassert_true(snapshot.fix_source_valid);
	zassert_equal(snapshot.fix_source, LICHEN_HAL_FIX_SOURCE_GNSS);
}

ZTEST(hal, test_location_provider_stale_fix_suppresses_position_fields)
{
	const int64_t old_fix_ms = 1000;
	const struct lichen_hal_location_sample sample = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = old_fix_ms,
		.latitude_e7_valid = true,
		.latitude_e7 = 100,
		.longitude_e7_valid = true,
		.longitude_e7 = 200,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.altitude_cm_valid = true,
		.altitude_cm = 4249,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000001U,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 2) * 1000);
	zassert_ok(lichen_hal_location_submit(&sample));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_true(snapshot.location_provider_available);
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_true(snapshot.fix_state_valid);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_STALE);
	zassert_true(snapshot.age_seconds_valid);
	zassert_false(snapshot.latitude_e7_valid);
	zassert_false(snapshot.longitude_e7_valid);
	zassert_false(snapshot.altitude_m_valid);
	zassert_false(snapshot.altitude_cm_valid);
	zassert_false(snapshot.fix_time_unix_valid);
	zassert_false(snapshot.fix_source_valid);
}

ZTEST(hal, test_location_provider_rejects_invalid_partial_position)
{
	const struct lichen_hal_location_sample invalid = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
	};
	const struct lichen_hal_location_sample no_position_fix = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
	};

	zassert_equal(lichen_hal_location_submit(NULL), -EINVAL);
	zassert_equal(lichen_hal_location_submit(&invalid), -EINVAL);
	zassert_equal(lichen_hal_location_submit(&no_position_fix), -EINVAL);
}

ZTEST(hal, test_location_provider_source_precedence_and_stale_fallback)
{
	const int64_t fresh_lower_priority_fix_ms = 12000;
	const struct lichen_hal_location_sample gnss = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = fresh_lower_priority_fix_ms,
		.latitude_e7_valid = true,
		.latitude_e7 = 10,
		.longitude_e7_valid = true,
		.longitude_e7 = 20,
	};
	const struct lichen_hal_location_sample manual = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "manual",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 11000,
		.latitude_e7_valid = true,
		.latitude_e7 = 30,
		.longitude_e7_valid = true,
		.longitude_e7 = 40,
	};
	const struct lichen_hal_location_sample fresh_network = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "mesh",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 900000,
		.latitude_e7_valid = true,
		.latitude_e7 = 50,
		.longitude_e7_valid = true,
		.longitude_e7 = 60,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(12000);
	zassert_ok(lichen_hal_location_submit(&manual));
	zassert_ok(lichen_hal_location_submit(&gnss));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC);
	zassert_equal(snapshot.latitude_e7, 30);

	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 12) * 1000);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_equal(snapshot.latitude_e7, 10);
	zassert_equal(snapshot.longitude_e7, 20);

	lichen_hal_location_test_set_uptime_ms(901000);
	zassert_ok(lichen_hal_location_submit(&fresh_network));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class, LICHEN_HAL_LOCATION_SOURCE_NETWORK);
	zassert_equal(snapshot.latitude_e7, 50);
	zassert_equal(snapshot.longitude_e7, 60);
}

ZTEST(hal, test_location_provider_stale_manual_falls_back_to_network)
{
	const struct lichen_hal_location_sample manual = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "manual",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
		.latitude_e7_valid = true,
		.latitude_e7 = 30,
		.longitude_e7_valid = true,
		.longitude_e7 = 40,
	};
	const struct lichen_hal_location_sample network = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "mesh",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 900000,
		.latitude_e7_valid = true,
		.latitude_e7 = 50,
		.longitude_e7_valid = true,
		.longitude_e7 = 60,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(901000);
	zassert_ok(lichen_hal_location_submit(&manual));
	zassert_ok(lichen_hal_location_submit(&network));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_equal(snapshot.source_class, LICHEN_HAL_LOCATION_SOURCE_NETWORK);
	zassert_str_equal(snapshot.source_name, "mesh");
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 50);
	zassert_true(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, 60);
}

ZTEST(hal, test_location_provider_no_fix_does_not_block_usable_fix)
{
	const struct lichen_hal_location_sample gnss = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
		.latitude_e7_valid = true,
		.latitude_e7 = 10,
		.longitude_e7_valid = true,
		.longitude_e7 = 20,
	};
	const struct lichen_hal_location_sample client_no_fix = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT,
		.fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX,
		.source_name = "phone",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 2000,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(3000);
	zassert_ok(lichen_hal_location_submit(&gnss));
	zassert_ok(lichen_hal_location_submit(&client_no_fix));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_3D);
	zassert_true(snapshot.latitude_e7_valid);
}

ZTEST(hal, test_location_provider_fresh_no_fix_metadata_beats_stale_high_priority)
{
	const struct lichen_hal_location_sample manual = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "manual",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
		.latitude_e7_valid = true,
		.latitude_e7 = 30,
		.longitude_e7_valid = true,
		.longitude_e7 = 40,
	};
	const struct lichen_hal_location_sample network_no_fix = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX,
		.source_name = "mesh",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 900000,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(2000);
	zassert_ok(lichen_hal_location_submit(&manual));
	lichen_hal_location_test_set_uptime_ms(901000);
	zassert_ok(lichen_hal_location_submit(&network_no_fix));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class, LICHEN_HAL_LOCATION_SOURCE_NETWORK);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_NO_FIX);
	zassert_false(snapshot.latitude_e7_valid);
}

ZTEST(hal, test_location_provider_rejects_bad_source_and_clamps_future_time)
{
	const struct lichen_hal_location_sample bad_fix_source = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.fix_source = (enum lichen_hal_fix_source)99,
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
		.longitude_e7_valid = true,
		.longitude_e7 = 2,
	};
	const struct lichen_hal_location_sample future = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "mesh",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 60000,
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
		.longitude_e7_valid = true,
		.longitude_e7 = 2,
	};
	const struct lichen_hal_location_sample before_boot = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = -1,
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
		.longitude_e7_valid = true,
		.longitude_e7 = 2,
	};
	const struct lichen_hal_location_sample oldest_time = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = INT64_MIN,
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
		.longitude_e7_valid = true,
		.longitude_e7 = 2,
	};
	struct lichen_hal_location_time_snapshot snapshot;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_equal(lichen_hal_location_submit(&bad_fix_source), -EINVAL);
	zassert_ok(lichen_hal_location_submit(&before_boot));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.age_seconds_valid);
	zassert_equal(snapshot.age_seconds, 1U);
	zassert_true(snapshot.latitude_e7_valid);
	lichen_hal_location_clear();

	zassert_ok(lichen_hal_location_submit(&oldest_time));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.age_seconds_valid);
	zassert_equal(snapshot.age_seconds, UINT32_MAX);
	zassert_false(snapshot.latitude_e7_valid);
	lichen_hal_location_clear();

	zassert_ok(lichen_hal_location_submit(&future));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.age_seconds_valid);
	zassert_equal(snapshot.age_seconds, 0U);
	zassert_true(snapshot.latitude_e7_valid);

	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 2) * 1000);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_STALE);
	zassert_false(snapshot.latitude_e7_valid);
}

ZTEST(hal, test_duty_cycle_ccp13)
{
	struct lichen_duty_cycle_ctx t; uint32_t m; lichen_duty_cycle_init(&t,10); m=3600*10; zassert_equal(lichen_duty_cycle_remaining_ms(&t,0),m); zassert_equal(lichen_duty_cycle_usage_permille(&t,0),0); lichen_duty_cycle_record_tx(&t,0,200); zassert_equal(lichen_duty_cycle_remaining_ms(&t,1000),m-200); zassert_equal(lichen_duty_cycle_usage_permille(&t,1000),0); lichen_duty_cycle_init(&t,10); lichen_duty_cycle_record_tx(&t,0,200); zassert_equal(lichen_duty_cycle_remaining_ms(&t,3600201),m); lichen_duty_cycle_init(&t,10); lichen_duty_cycle_record_tx(&t,0,36000); zassert_equal(lichen_duty_cycle_next_tx_available_ms(&t,0,100),3600000); zassert_equal(lichen_duty_cycle_next_tx_available_ms(&t,0,36001),(uint64_t)-1); lichen_duty_cycle_init(&t,100); zassert_equal(lichen_duty_cycle_remaining_ms(&t,0),3600*100); zassert_true(lichen_duty_cycle_can_transmit(&t,0,100));
}

ZTEST(hal, test_duty_cycle_tracker_matches_ccp13_vectors)
{
#ifdef CONFIG_LICHEN_DUTY_CYCLE
	struct lichen_duty_cycle_ctx ctx;
	lichen_duty_cycle_init(&ctx, 10);
	zassert_equal(lichen_duty_cycle_remaining_ms(&ctx, 0), 36000U);
	zassert_equal(lichen_duty_cycle_usage_permille(&ctx, 0), 0U);
	lichen_duty_cycle_record_tx(&ctx, 0, 200);
	zassert_equal(lichen_duty_cycle_remaining_ms(&ctx, 1000), 35800U);
	zassert_equal(lichen_duty_cycle_usage_permille(&ctx, 1000), 0U);
	zassert_true(lichen_duty_cycle_can_transmit(&ctx, 1000, 100));
	lichen_duty_cycle_init(&ctx, 10);
	lichen_duty_cycle_record_tx(&ctx, 0, 200);
	zassert_equal(lichen_duty_cycle_remaining_ms(&ctx, 3600201), 36000U);
	lichen_duty_cycle_init(&ctx, 10);
	lichen_duty_cycle_record_tx(&ctx, 0, 36000);
	zassert_equal(lichen_duty_cycle_next_tx_available_ms(&ctx, 0, 100), 3600000ULL);
	zassert_equal(lichen_duty_cycle_next_tx_available_ms(&ctx, 0, 36001), 18446744073709551615ULL);
	lichen_duty_cycle_init(&ctx, 100);
	zassert_equal(lichen_duty_cycle_remaining_ms(&ctx, 0), 360000U);
#else
	ztest_test_skip();
#endif
}

static void hal_after(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_hal_location_time_test_set_snapshot(NULL);
	lichen_hal_location_clear();
	lichen_hal_time_clear();
	lichen_hal_time_provision_epoch_clear();
	lichen_hal_location_test_use_real_uptime();
}

ZTEST_SUITE(hal, NULL, NULL, NULL, hal_after, NULL);
