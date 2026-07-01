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

struct lichen_hal_power_snapshot {
	bool battery_provider_available;
	bool pmic_provider_available;
	bool battery_percent_valid;
	uint8_t battery_percent;
	bool battery_voltage_mv_valid;
	uint16_t battery_voltage_mv;
	bool charging_valid;
	bool charging;
	bool external_power_valid;
	bool external_power;
};

enum lichen_hal_fix_source {
	LICHEN_HAL_FIX_SOURCE_NONE,
	LICHEN_HAL_FIX_SOURCE_GNSS,
};

struct lichen_hal_location_time_snapshot {
	bool location_provider_available;
	bool time_provider_available;
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool fix_time_unix_valid;
	uint32_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
	bool fix_source_valid;
	enum lichen_hal_fix_source fix_source;
};

/*
 * Some Zephyr registration macros require a compile-time device expression
 * rather than a runtime getter. Keep those devicetree details behind HAL names
 * so applications do not open-code board aliases.
 */
#if DT_NODE_HAS_STATUS(DT_ALIAS(gnss0), okay)
#define LICHEN_HAL_GNSS_DEVICE DEVICE_DT_GET(DT_ALIAS(gnss0))
#endif

const struct lichen_hal_capabilities *lichen_hal_capabilities_get(void);
bool lichen_hal_has_capability(enum lichen_hal_capability capability);
void lichen_hal_identity_get(struct lichen_hal_identity *identity);

int lichen_hal_capability_status(enum lichen_hal_capability capability);
int lichen_hal_lora_status(void);
int lichen_hal_ble_local_status(void);
int lichen_hal_serial_local_status(void);
int lichen_hal_gnss_status(void);
int lichen_hal_battery_status(void);
int lichen_hal_pmic_status(void);
int lichen_hal_buttons_status(void);
int lichen_hal_leds_status(void);
int lichen_hal_display_status(void);
int lichen_hal_external_flash_status(void);
int lichen_hal_location_status(void);
int lichen_hal_time_status(void);

int lichen_hal_lora_device_get(const struct device **dev);
int lichen_hal_gnss_device_get(const struct device **dev);
int lichen_hal_display_device_get(const struct device **dev);
int lichen_hal_serial_device_get(const struct device **dev);
int lichen_hal_battery_device_get(const struct device **dev);
int lichen_hal_pmic_device_get(const struct device **dev);
int lichen_hal_external_flash_device_get(const struct device **dev);
int lichen_hal_led_get(struct gpio_dt_spec *spec);
int lichen_hal_button_get(struct gpio_dt_spec *spec);
int lichen_hal_power_snapshot_get(struct lichen_hal_power_snapshot *snapshot);
int lichen_hal_location_time_snapshot_get(
	struct lichen_hal_location_time_snapshot *snapshot);

#ifdef CONFIG_ZTEST
void lichen_hal_location_time_test_set_snapshot(
	const struct lichen_hal_location_time_snapshot *snapshot);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_HAL_H_ */
