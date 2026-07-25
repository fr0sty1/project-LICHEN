/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_LORA) ||
	     (IS_ENABLED(CONFIG_LORA) &&
	      DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay)),
	     "CONFIG_LICHEN_HAS_LORA requires an okay chosen zephyr,lora");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_GNSS) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(gnss0), okay),
	     "CONFIG_LICHEN_HAS_GNSS requires an okay gnss0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BUTTONS) ||
	     (DT_NODE_HAS_STATUS(DT_ALIAS(sw0), okay) &&
	      DT_NODE_HAS_PROP(DT_ALIAS(sw0), gpios)),
	     "CONFIG_LICHEN_HAS_BUTTONS requires sw0 alias with gpios property");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_LEDS) ||
	     (DT_NODE_HAS_STATUS(DT_ALIAS(led0), okay) &&
	      DT_NODE_HAS_PROP(DT_ALIAS(led0), gpios)),
	     "CONFIG_LICHEN_HAS_LEDS requires led0 alias with gpios property");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_DISPLAY) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_display), okay) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(display0), okay),
	     "CONFIG_LICHEN_HAS_DISPLAY requires an okay chosen zephyr,display or display0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(battery0), okay),
	     "CONFIG_LICHEN_HAS_BATTERY requires an okay battery0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	     (LICHEN_HAL_BATTERY_IS_VOLTAGE_DIVIDER ||
	      LICHEN_HAL_BATTERY_IS_FUEL_GAUGE),
	     "CONFIG_LICHEN_HAS_BATTERY requires battery0 to be voltage-divider or fuel-gauge");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	     !LICHEN_HAL_BATTERY_IS_VOLTAGE_DIVIDER ||
	     IS_ENABLED(CONFIG_SENSOR),
	     "voltage-divider battery0 requires CONFIG_SENSOR");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	     !LICHEN_HAL_BATTERY_IS_FUEL_GAUGE ||
	     IS_ENABLED(CONFIG_FUEL_GAUGE),
	     "fuel-gauge battery0 requires CONFIG_FUEL_GAUGE");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY) ||
	     LICHEN_HAL_BATTERY_DRIVER_ENABLED,
	     "CONFIG_LICHEN_HAS_BATTERY requires the concrete battery0 driver");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_PMIC) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(pmic0), okay),
	     "CONFIG_LICHEN_HAS_PMIC requires an okay pmic0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_PMIC) ||
	     !LICHEN_HAL_PMIC_IS_CHARGER ||
	     IS_ENABLED(CONFIG_CHARGER),
	     "charger pmic0 requires CONFIG_CHARGER");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_PMIC) ||
	     LICHEN_HAL_PMIC_DRIVER_ENABLED,
	     "CONFIG_LICHEN_HAS_PMIC requires the concrete pmic0 driver");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_EXTERNAL_FLASH) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(external_flash0), okay),
	     "CONFIG_LICHEN_HAS_EXTERNAL_FLASH requires an okay external-flash0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BLE_LOCAL) ||
	     IS_ENABLED(CONFIG_BT_HCI),
	     "CONFIG_LICHEN_HAS_BLE_LOCAL requires CONFIG_BT_HCI");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_SERIAL_LOCAL) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(lichen_native_uart), okay) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_uart_pipe), okay) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_slip_uart), okay) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_shell_uart), okay) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_console), okay),
	     "CONFIG_LICHEN_HAS_SERIAL_LOCAL requires an okay chosen serial local device");

BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SX126X) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), semtech_sx1261) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), semtech_sx1262),
	     "LICHEN_RADIO_MODEL_SX126X requires chosen zephyr,lora to be semtech,sx1261 or semtech,sx1262");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SX127X) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), semtech_sx1272) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), semtech_sx1276),
	     "LICHEN_RADIO_MODEL_SX127X requires chosen zephyr,lora to be semtech,sx1272 or semtech,sx1276");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_LR1110) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), semtech_lr1110),
	     "LICHEN_RADIO_MODEL_LR1110 requires chosen zephyr,lora to be semtech,lr1110");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_STM32WL) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), st_stm32wl_subghz_radio),
	     "LICHEN_RADIO_MODEL_STM32WL requires chosen zephyr,lora to be st,stm32wl-subghz-radio");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SIM) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), lichen_lora_sim),
	     "LICHEN_RADIO_MODEL_SIM requires chosen zephyr,lora to be lichen,lora-sim");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_LOOPBACK) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), lichen_lora_loopback),
	     "LICHEN_RADIO_MODEL_LOOPBACK requires chosen zephyr,lora to be lichen,lora-loopback");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_RENODE) ||
	     DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_lora), lichen_lora_renode),
	     "LICHEN_RADIO_MODEL_RENODE requires chosen zephyr,lora to be lichen,lora-renode");

#if IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SX126X)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_SX126X
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SX127X)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_SX127X
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_LR1110)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_LR1110
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_STM32WL)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_STM32WL
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_SIM)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_SIM
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_LOOPBACK)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_LOOPBACK
#elif IS_ENABLED(CONFIG_LICHEN_RADIO_MODEL_RENODE)
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_RENODE
#else
#define LICHEN_HAL_RADIO_MODEL_VALUE LICHEN_HAL_RADIO_NONE
#endif

#if IS_ENABLED(CONFIG_LICHEN_UI_PROFILE_HANDHELD)
#define LICHEN_HAL_UI_PROFILE_VALUE LICHEN_HAL_UI_HANDHELD
#elif IS_ENABLED(CONFIG_LICHEN_UI_PROFILE_TRACKER)
#define LICHEN_HAL_UI_PROFILE_VALUE LICHEN_HAL_UI_TRACKER
#else
#define LICHEN_HAL_UI_PROFILE_VALUE LICHEN_HAL_UI_HEADLESS
#endif

#if IS_ENABLED(CONFIG_LICHEN_LOCATION_PROVIDER_GNSS)
#define LICHEN_HAL_LOCATION_PROVIDER_VALUE LICHEN_HAL_LOCATION_GNSS
#else
#define LICHEN_HAL_LOCATION_PROVIDER_VALUE LICHEN_HAL_LOCATION_NONE
#endif

#if IS_ENABLED(CONFIG_LICHEN_TIME_PROVIDER_GNSS)
#define LICHEN_HAL_TIME_PROVIDER_VALUE LICHEN_HAL_TIME_GNSS
#else
#define LICHEN_HAL_TIME_PROVIDER_VALUE LICHEN_HAL_TIME_UPTIME
#endif

const struct lichen_hal_capabilities lichen_hal_caps = {
	.flags =
		COND_CODE_1(CONFIG_LICHEN_HAS_LORA, (LICHEN_HAL_CAP_LORA), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_BLE_LOCAL, (LICHEN_HAL_CAP_BLE_LOCAL), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_SERIAL_LOCAL, (LICHEN_HAL_CAP_SERIAL_LOCAL), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_GNSS, (LICHEN_HAL_CAP_GNSS), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_BATTERY, (LICHEN_HAL_CAP_BATTERY), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_PMIC, (LICHEN_HAL_CAP_PMIC), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_BUTTONS, (LICHEN_HAL_CAP_BUTTONS), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_LEDS, (LICHEN_HAL_CAP_LEDS), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_DISPLAY, (LICHEN_HAL_CAP_DISPLAY), (0)) |
		COND_CODE_1(CONFIG_LICHEN_HAS_EXTERNAL_FLASH, (LICHEN_HAL_CAP_EXTERNAL_FLASH), (0)),
	.radio = LICHEN_HAL_RADIO_MODEL_VALUE,
	.ui = LICHEN_HAL_UI_PROFILE_VALUE,
	.location = LICHEN_HAL_LOCATION_PROVIDER_VALUE,
	.time = LICHEN_HAL_TIME_PROVIDER_VALUE,
};

const struct lichen_hal_capabilities *lichen_hal_capabilities_get(void)
{
	return &lichen_hal_caps;
}

bool lichen_hal_has_capability(enum lichen_hal_capability capability)
{
	return (lichen_hal_caps.flags & capability) != 0;
}

void lichen_hal_identity_get(struct lichen_hal_identity *identity)
{
	const char *name = CONFIG_LICHEN_BOARD_NAME;

	if (identity == NULL) {
		return;
	}

	if (name[0] == '\0') {
		name = CONFIG_BOARD;
	}

	identity->board_name = name;
	identity->zephyr_board = CONFIG_BOARD;
	identity->caps = lichen_hal_caps;
}

static bool is_single_capability(enum lichen_hal_capability capability)
{
	uint32_t value = (uint32_t)capability;

	return value != 0U &&
	       (value & (value - 1U)) == 0U &&
	       (value & ~LICHEN_HAL_KNOWN_CAPS) == 0U;
}

int lichen_hal_capability_status(enum lichen_hal_capability capability)
{
	const struct device *dev;
	struct gpio_dt_spec gpio;

	if (!is_single_capability(capability)) {
		return -EINVAL;
	}

	if (!lichen_hal_has_capability(capability)) {
		return -ENOTSUP;
	}

	switch (capability) {
	case LICHEN_HAL_CAP_LORA:
		return lichen_hal_lora_device_get(&dev);
	case LICHEN_HAL_CAP_BLE_LOCAL:
		return lichen_hal_ble_local_status();
	case LICHEN_HAL_CAP_SERIAL_LOCAL:
		return lichen_hal_serial_device_get(&dev);
	case LICHEN_HAL_CAP_GNSS:
		return lichen_hal_gnss_device_get(&dev);
	case LICHEN_HAL_CAP_BATTERY:
		return lichen_hal_battery_device_get(&dev);
	case LICHEN_HAL_CAP_PMIC:
		return lichen_hal_pmic_device_get(&dev);
	case LICHEN_HAL_CAP_BUTTONS:
		return lichen_hal_button_get(&gpio);
	case LICHEN_HAL_CAP_LEDS:
		return lichen_hal_led_get(&gpio);
	case LICHEN_HAL_CAP_DISPLAY:
		return lichen_hal_display_device_get(&dev);
	case LICHEN_HAL_CAP_EXTERNAL_FLASH:
		return lichen_hal_external_flash_device_get(&dev);
	default:
		return -EINVAL;
	}
}

int lichen_hal_lora_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_LORA);
}

int lichen_hal_serial_local_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_SERIAL_LOCAL);
}

int lichen_hal_gnss_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_GNSS);
}

int lichen_hal_battery_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_BATTERY);
}

int lichen_hal_pmic_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_PMIC);
}

int lichen_hal_buttons_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_BUTTONS);
}

int lichen_hal_leds_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_LEDS);
}

int lichen_hal_display_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_DISPLAY);
}

int lichen_hal_external_flash_status(void)
{
	return lichen_hal_capability_status(LICHEN_HAL_CAP_EXTERNAL_FLASH);
}

int lichen_hal_location_status(void)
{
	switch (lichen_hal_caps.location) {
	case LICHEN_HAL_LOCATION_NONE:
		return -ENOTSUP;
	case LICHEN_HAL_LOCATION_GNSS:
		return lichen_hal_capability_status(LICHEN_HAL_CAP_GNSS);
	default:
		return -EINVAL;
	}
}

int lichen_hal_time_status(void)
{
	switch (lichen_hal_caps.time) {
	case LICHEN_HAL_TIME_UPTIME:
		return 0;
	case LICHEN_HAL_TIME_GNSS:
		return lichen_hal_capability_status(LICHEN_HAL_CAP_GNSS);
	default:
		return -EINVAL;
	}
}

bool lichen_hal_synthetic_device_identity_allowed(void)
{
	return IS_ENABLED(CONFIG_BOARD_NATIVE_SIM);
}

int lichen_hal_synthetic_device_identity_get(uint8_t *id, size_t id_len)
{
	if (id == NULL) {
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_BOARD_NATIVE_SIM)
	static const uint8_t sim_hwid[] = {
		'n', 'a', 't', 'i', 'v', 'e', '_', 's', 'i', 'm',
		(uint8_t)CONFIG_NATIVE_SIMULATOR_MCU_N,
	};

	if (id_len < sizeof(sim_hwid)) {
		return -ENOMEM;
	}

	memcpy(id, sim_hwid, sizeof(sim_hwid));
	return sizeof(sim_hwid);
#else
	ARG_UNUSED(id_len);
	return -ENOTSUP;
#endif
}
