/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

static int __maybe_unused return_device_if_ready(const struct device **out,
						 const struct device *candidate)
{
	if (!device_is_ready(candidate)) {
		return -ENODEV;
	}

	*out = candidate;
	return 0;
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
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_slip_uart), okay)
	return return_device_if_ready(dev, DEVICE_DT_GET(DT_CHOSEN(zephyr_slip_uart)));
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
