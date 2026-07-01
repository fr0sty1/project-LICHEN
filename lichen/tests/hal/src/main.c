/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/ztest.h>

#include <lichen/hal.h>

ZTEST(hal, test_headless_native_defaults_are_deterministic)
{
	const struct lichen_hal_capabilities *caps = lichen_hal_capabilities_get();

	if (IS_ENABLED(CONFIG_LICHEN_HAS_LORA)) {
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
	zassert_equal(lichen_hal_battery_status(), -ENOTSUP);
	zassert_equal(lichen_hal_pmic_status(), -ENOTSUP);
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
	zassert_equal(lichen_hal_battery_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

	dev = (const struct device *)0x1;
	zassert_equal(lichen_hal_pmic_device_get(&dev), -ENOTSUP);
	zassert_is_null(dev);

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
	zassert_false(snapshot.battery_percent_valid);
	zassert_equal(snapshot.battery_percent, 0U);
	zassert_false(snapshot.battery_voltage_mv_valid);
	zassert_equal(snapshot.battery_voltage_mv, 0U);
	zassert_false(snapshot.charging_valid);
	zassert_false(snapshot.charging);
	zassert_false(snapshot.external_power_valid);
	zassert_false(snapshot.external_power);
}

ZTEST_SUITE(hal, NULL, NULL, NULL, NULL, NULL);
