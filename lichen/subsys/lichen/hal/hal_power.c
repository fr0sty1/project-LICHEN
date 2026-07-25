/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/sensor.h>
#if IS_ENABLED(CONFIG_CHARGER)
#include <zephyr/drivers/charger.h>
#endif
#if IS_ENABLED(CONFIG_FUEL_GAUGE)
/* Zephyr 3.7's fuel_gauge.h inline helpers loop a signed index against
 * a size_t bound, which trips LICHEN's -Werror=sign-compare.
 */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#include <zephyr/drivers/fuel_gauge.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

static void read_voltage_divider_battery(const struct device *dev,
					 struct lichen_hal_power_snapshot *snapshot)
{
#if IS_ENABLED(CONFIG_SENSOR)
	struct sensor_value voltage;
	int64_t voltage_mv;
	int ret;

	ret = sensor_sample_fetch_chan(dev, SENSOR_CHAN_VOLTAGE);
	if (ret == 0) {
		ret = sensor_channel_get(dev, SENSOR_CHAN_VOLTAGE, &voltage);
	}
	if (ret == 0 && voltage.val1 >= 0 && voltage.val2 >= 0) {
		voltage_mv = (int64_t)voltage.val1 * 1000 + voltage.val2 / 1000;
		if (voltage_mv > 0 && voltage_mv <= UINT16_MAX) {
			snapshot->battery_voltage_mv_valid = true;
			snapshot->battery_voltage_mv = (uint16_t)voltage_mv;
		}
	}
#else
	ARG_UNUSED(dev);
	ARG_UNUSED(snapshot);
#endif
}

#if IS_ENABLED(CONFIG_FUEL_GAUGE) || defined(CONFIG_ZTEST)
static bool power_percent_valid(uint8_t percent)
{
	return percent <= 100U;
}
#endif

#if IS_ENABLED(CONFIG_CHARGER) || defined(CONFIG_ZTEST)
static bool charger_status_known(int status)
{
#if IS_ENABLED(CONFIG_CHARGER)
	return status == CHARGER_STATUS_CHARGING ||
	       status == CHARGER_STATUS_DISCHARGING ||
	       status == CHARGER_STATUS_NOT_CHARGING ||
	       status == CHARGER_STATUS_FULL;
#else
	ARG_UNUSED(status);
	return false;
#endif
}

static bool charger_status_is_charging(int status)
{
#if IS_ENABLED(CONFIG_CHARGER)
	return charger_status_known(status) && status == CHARGER_STATUS_CHARGING;
#else
	ARG_UNUSED(status);
	return false;
#endif
}

static bool charger_online_is_external_power(int online)
{
#if IS_ENABLED(CONFIG_CHARGER)
	return online == CHARGER_ONLINE_FIXED ||
	       online == CHARGER_ONLINE_PROGRAMMABLE;
#else
	ARG_UNUSED(online);
	return false;
#endif
}

static bool charger_online_known(int online)
{
#if IS_ENABLED(CONFIG_CHARGER)
	return online == CHARGER_ONLINE_OFFLINE ||
	       online == CHARGER_ONLINE_FIXED ||
	       online == CHARGER_ONLINE_PROGRAMMABLE;
#else
	ARG_UNUSED(online);
	return false;
#endif
}
#endif

#ifdef CONFIG_ZTEST
bool lichen_hal_power_test_percent_valid(uint8_t percent)
{
	return power_percent_valid(percent);
}

bool lichen_hal_power_test_charger_status_known(int status)
{
	return charger_status_known(status);
}

bool lichen_hal_power_test_charger_status_is_charging(int status)
{
	return charger_status_is_charging(status);
}

bool lichen_hal_power_test_charger_online_external_power(int online)
{
	return charger_online_is_external_power(online);
}

bool lichen_hal_power_test_charger_online_known(int online)
{
	return charger_online_known(online);
}
#endif

static void read_fuel_gauge_battery(const struct device *dev,
				    struct lichen_hal_power_snapshot *snapshot)
{
#if IS_ENABLED(CONFIG_FUEL_GAUGE)
	union fuel_gauge_prop_val value;
	int ret;

	ret = fuel_gauge_get_prop(dev, FUEL_GAUGE_RELATIVE_STATE_OF_CHARGE,
				  &value);
	if (ret == 0 && power_percent_valid(value.relative_state_of_charge)) {
		snapshot->battery_percent_valid = true;
		snapshot->battery_percent = value.relative_state_of_charge;
	}

	ret = fuel_gauge_get_prop(dev, FUEL_GAUGE_VOLTAGE, &value);
	if (ret == 0 && value.voltage > 0) {
		int32_t voltage_mv = value.voltage / 1000;

		if (voltage_mv > 0 && voltage_mv <= UINT16_MAX) {
			snapshot->battery_voltage_mv_valid = true;
			snapshot->battery_voltage_mv = (uint16_t)voltage_mv;
		}
	}
#else
	ARG_UNUSED(dev);
	ARG_UNUSED(snapshot);
#endif
}

static void read_charger_pmic(const struct device *dev,
			      struct lichen_hal_power_snapshot *snapshot)
{
#if IS_ENABLED(CONFIG_CHARGER)
	union charger_propval value;
	int ret;

	ret = charger_get_prop(dev, CHARGER_PROP_STATUS, &value);
	if (ret == 0 && charger_status_known(value.status)) {
		snapshot->charging_valid = true;
		snapshot->charging = charger_status_is_charging(value.status);
	}

	ret = charger_get_prop(dev, CHARGER_PROP_ONLINE, &value);
	if (ret == 0 && charger_online_known(value.online)) {
		snapshot->external_power_valid = true;
		snapshot->external_power =
			charger_online_is_external_power(value.online);
	}
#else
	ARG_UNUSED(dev);
	ARG_UNUSED(snapshot);
#endif
}

int lichen_hal_power_snapshot_get(struct lichen_hal_power_snapshot *snapshot)
{
	const struct device *dev;
	int ret;

	if (snapshot == NULL) {
		return -EINVAL;
	}

	*snapshot = (struct lichen_hal_power_snapshot){ 0 };

	ret = lichen_hal_battery_device_get(&dev);
	if (ret == 0) {
		snapshot->battery_provider_available = true;
		if (LICHEN_HAL_BATTERY_IS_FUEL_GAUGE) {
			read_fuel_gauge_battery(dev, snapshot);
		} else if (LICHEN_HAL_BATTERY_IS_VOLTAGE_DIVIDER) {
			read_voltage_divider_battery(dev, snapshot);
		}
	}

	ret = lichen_hal_pmic_device_get(&dev);
	if (ret == 0) {
		snapshot->pmic_provider_available = true;
		if (LICHEN_HAL_PMIC_IS_CHARGER) {
			read_charger_pmic(dev, snapshot);
		}
	}

	return 0;
}
