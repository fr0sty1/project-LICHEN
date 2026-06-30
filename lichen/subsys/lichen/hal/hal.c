/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>

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
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_PMIC) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(pmic0), okay),
	     "CONFIG_LICHEN_HAS_PMIC requires an okay pmic0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_EXTERNAL_FLASH) ||
	     DT_NODE_HAS_STATUS(DT_ALIAS(external_flash0), okay),
	     "CONFIG_LICHEN_HAS_EXTERNAL_FLASH requires an okay external-flash0 alias");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_BLE_LOCAL) ||
	     IS_ENABLED(CONFIG_BT_HCI),
	     "CONFIG_LICHEN_HAS_BLE_LOCAL requires CONFIG_BT_HCI");
BUILD_ASSERT(!IS_ENABLED(CONFIG_LICHEN_HAS_SERIAL_LOCAL) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(lichen_native_uart), okay) ||
	     DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_uart_pipe), okay) ||
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

static const struct lichen_hal_capabilities s_caps = {
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
	return &s_caps;
}

bool lichen_hal_has_capability(enum lichen_hal_capability capability)
{
	return (s_caps.flags & capability) != 0;
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
	identity->caps = s_caps;
}

int lichen_hal_lora_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}

	*dev = NULL;

	if (!IS_ENABLED(CONFIG_LICHEN_HAS_LORA)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay)
	const struct device *candidate = DEVICE_DT_GET(DT_CHOSEN(zephyr_lora));

	if (!device_is_ready(candidate)) {
		return -ENODEV;
	}

	*dev = candidate;
	return 0;
#else
	return -ENODEV;
#endif
}

static int return_device_if_ready(const struct device **out,
				  const struct device *candidate)
{
	if (!device_is_ready(candidate)) {
		return -ENODEV;
	}

	*out = candidate;
	return 0;
}

int lichen_hal_gnss_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}

	*dev = NULL;

	if (!IS_ENABLED(CONFIG_LICHEN_HAS_GNSS)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(gnss0), okay)
	const struct device *candidate = DEVICE_DT_GET(DT_ALIAS(gnss0));

	if (!device_is_ready(candidate)) {
		return -ENODEV;
	}

	*dev = candidate;
	return 0;
#else
	return -ENODEV;
#endif
}

int lichen_hal_display_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	*dev = NULL;
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_DISPLAY)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_display), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(zephyr_display)));
#elif DT_NODE_HAS_STATUS(DT_ALIAS(display0), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_ALIAS(display0)));
#else
	return -ENODEV;
#endif
}

int lichen_hal_serial_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	*dev = NULL;
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_SERIAL_LOCAL)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_CHOSEN(lichen_native_uart), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(lichen_native_uart)));
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_uart_pipe), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(zephyr_uart_pipe)));
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_shell_uart), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(zephyr_shell_uart)));
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_console), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(zephyr_console)));
#else
	return -ENODEV;
#endif
}

int lichen_hal_battery_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	*dev = NULL;
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_BATTERY)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(battery0), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_ALIAS(battery0)));
#else
	return -ENODEV;
#endif
}

int lichen_hal_pmic_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	*dev = NULL;
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_PMIC)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(pmic0), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_ALIAS(pmic0)));
#else
	return -ENODEV;
#endif
}

int lichen_hal_led_get(struct gpio_dt_spec *spec)
{
	if (spec == NULL) {
		return -EINVAL;
	}
	*spec = (struct gpio_dt_spec){ 0 };
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_LEDS)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(led0), okay) && DT_NODE_HAS_PROP(DT_ALIAS(led0), gpios)
	*spec = (struct gpio_dt_spec)GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
	if (!gpio_is_ready_dt(spec)) {
		*spec = (struct gpio_dt_spec){ 0 };
		return -ENODEV;
	}

	return 0;
#else
	return -ENODEV;
#endif
}

int lichen_hal_button_get(struct gpio_dt_spec *spec)
{
	if (spec == NULL) {
		return -EINVAL;
	}
	*spec = (struct gpio_dt_spec){ 0 };
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_BUTTONS)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(sw0), okay) && DT_NODE_HAS_PROP(DT_ALIAS(sw0), gpios)
	*spec = (struct gpio_dt_spec)GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);
	if (!gpio_is_ready_dt(spec)) {
		*spec = (struct gpio_dt_spec){ 0 };
		return -ENODEV;
	}

	return 0;
#else
	return -ENODEV;
#endif
}

int lichen_hal_external_flash_device_get(const struct device **dev)
{
	if (dev == NULL) {
		return -EINVAL;
	}
	*dev = NULL;
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_EXTERNAL_FLASH)) {
		return -ENOTSUP;
	}

#if DT_NODE_HAS_STATUS(DT_ALIAS(external_flash0), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_ALIAS(external_flash0)));
#else
	return -ENODEV;
#endif
}

int lichen_hal_ble_local_status(void)
{
	if (!IS_ENABLED(CONFIG_LICHEN_HAS_BLE_LOCAL)) {
		return -ENOTSUP;
	}

	if (!IS_ENABLED(CONFIG_BT) ||
	    !IS_ENABLED(CONFIG_BT_PERIPHERAL) ||
	    !IS_ENABLED(CONFIG_BT_HCI)) {
		return -ENODEV;
	}

	return 0;
}
