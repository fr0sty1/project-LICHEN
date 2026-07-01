/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_HAL_H_
#define LICHEN_HAL_H_

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/util.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lichen_hal_capability {
	LICHEN_HAL_CAP_LORA = BIT(0),
	LICHEN_HAL_CAP_BLE_LOCAL = BIT(1),
	LICHEN_HAL_CAP_SERIAL_LOCAL = BIT(2),
	LICHEN_HAL_CAP_GNSS = BIT(3),
	LICHEN_HAL_CAP_BATTERY = BIT(4),
	LICHEN_HAL_CAP_PMIC = BIT(5),
	LICHEN_HAL_CAP_BUTTONS = BIT(6),
	LICHEN_HAL_CAP_LEDS = BIT(7),
	LICHEN_HAL_CAP_DISPLAY = BIT(8),
	LICHEN_HAL_CAP_EXTERNAL_FLASH = BIT(9),
};

enum lichen_hal_radio_model {
	LICHEN_HAL_RADIO_NONE,
	LICHEN_HAL_RADIO_SX126X,
	LICHEN_HAL_RADIO_SX127X,
	LICHEN_HAL_RADIO_LR1110,
	LICHEN_HAL_RADIO_STM32WL,
	LICHEN_HAL_RADIO_SIM,
	LICHEN_HAL_RADIO_LOOPBACK,
	LICHEN_HAL_RADIO_RENODE,
};

enum lichen_hal_ui_profile {
	LICHEN_HAL_UI_HEADLESS,
	LICHEN_HAL_UI_TRACKER,
	LICHEN_HAL_UI_HANDHELD,
};

enum lichen_hal_location_provider {
	LICHEN_HAL_LOCATION_NONE,
	LICHEN_HAL_LOCATION_GNSS,
};

enum lichen_hal_time_provider {
	LICHEN_HAL_TIME_UPTIME,
	LICHEN_HAL_TIME_GNSS,
};

struct lichen_hal_capabilities {
	uint32_t flags;
	enum lichen_hal_radio_model radio;
	enum lichen_hal_ui_profile ui;
	enum lichen_hal_location_provider location;
	enum lichen_hal_time_provider time;
};

struct lichen_hal_identity {
	const char *board_name;
	const char *zephyr_board;
	struct lichen_hal_capabilities caps;
};

const struct lichen_hal_capabilities *lichen_hal_capabilities_get(void);
bool lichen_hal_has_capability(enum lichen_hal_capability capability);
void lichen_hal_identity_get(struct lichen_hal_identity *identity);

int lichen_hal_lora_device_get(const struct device **dev);
int lichen_hal_gnss_device_get(const struct device **dev);
int lichen_hal_display_device_get(const struct device **dev);
int lichen_hal_serial_device_get(const struct device **dev);
int lichen_hal_battery_device_get(const struct device **dev);
int lichen_hal_pmic_device_get(const struct device **dev);
int lichen_hal_external_flash_device_get(const struct device **dev);
int lichen_hal_led_get(struct gpio_dt_spec *spec);
int lichen_hal_button_get(struct gpio_dt_spec *spec);
int lichen_hal_ble_local_status(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_HAL_H_ */
