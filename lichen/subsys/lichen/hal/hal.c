/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#if IS_ENABLED(CONFIG_HWINFO)
#include <zephyr/drivers/hwinfo.h>
#endif
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
#if IS_ENABLED(CONFIG_REBOOT)
#include <zephyr/sys/reboot.h>
#endif
#include <zephyr/sys/util.h>

#include <lichen/hal.h>

#define LICHEN_HAL_KNOWN_CAPS \
	(LICHEN_HAL_CAP_LORA | LICHEN_HAL_CAP_BLE_LOCAL | \
	 LICHEN_HAL_CAP_SERIAL_LOCAL | LICHEN_HAL_CAP_GNSS | \
	 LICHEN_HAL_CAP_BATTERY | LICHEN_HAL_CAP_PMIC | \
	 LICHEN_HAL_CAP_BUTTONS | LICHEN_HAL_CAP_LEDS | \
	 LICHEN_HAL_CAP_DISPLAY | LICHEN_HAL_CAP_EXTERNAL_FLASH)

#define LICHEN_HAL_BATTERY_NODE DT_ALIAS(battery0)
#define LICHEN_HAL_PMIC_NODE DT_ALIAS(pmic0)

#define LICHEN_HAL_BATTERY_IS_VOLTAGE_DIVIDER \
	DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, voltage_divider)
#define LICHEN_HAL_BATTERY_IS_FUEL_GAUGE \
	(DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, maxim_max17048) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, sbs_sbs_gauge_new_api) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, ti_bq27z746))
#define LICHEN_HAL_BATTERY_DRIVER_ENABLED \
	((DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, voltage_divider) && \
	  IS_ENABLED(CONFIG_VOLTAGE_DIVIDER)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, maxim_max17048) && \
	  IS_ENABLED(CONFIG_MAX17048)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, sbs_sbs_gauge_new_api) && \
	  IS_ENABLED(CONFIG_SBS_GAUGE_NEW_API)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, ti_bq27z746) && \
	  IS_ENABLED(CONFIG_BQ27Z746)))
#define LICHEN_HAL_PMIC_IS_CHARGER \
	(DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, sbs_sbs_charger) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq24190) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq25180) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, maxim_max20335_charger))
#define LICHEN_HAL_PMIC_DRIVER_ENABLED \
	((DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, sbs_sbs_charger) && \
	  IS_ENABLED(CONFIG_SBS_CHARGER)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq24190) && \
	  IS_ENABLED(CONFIG_CHARGER_BQ24190)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq25180) && \
	  IS_ENABLED(CONFIG_CHARGER_BQ25180)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, maxim_max20335_charger) && \
	  IS_ENABLED(CONFIG_CHARGER_MAX20335)) || \
	 !LICHEN_HAL_PMIC_IS_CHARGER)

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

#ifdef CONFIG_ZTEST
static struct lichen_hal_location_time_snapshot s_test_location_time_snapshot;
static bool s_has_test_location_time_snapshot;
static bool s_use_test_uptime;
static int64_t s_test_uptime_ms;
static bool s_test_reset_request_valid;
static enum lichen_hal_reset_request s_test_reset_request;
#endif

struct location_provider_state {
	struct lichen_hal_location_sample samples[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
	char source_names[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1]
			 [sizeof(((struct lichen_hal_location_time_snapshot *)0)->source_name)];
	bool has_sample[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
};

struct time_provider_state {
	struct lichen_hal_time_sample samples[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1];
	struct lichen_hal_time_sample diagnostic_sample;
	char source_names[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1]
			 [sizeof(((struct lichen_hal_time_snapshot *)0)->source_name)];
	char diagnostic_source_name
		[sizeof(((struct lichen_hal_time_snapshot *)0)->source_name)];
	bool has_sample[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1];
	bool has_diagnostic_sample;
	bool provision_epoch_valid;
	uint32_t provision_epoch;
	enum lichen_hal_time_rejection_reason last_rejection;
};

static struct location_provider_state s_location_state;
static K_MUTEX_DEFINE(s_location_mutex);
static struct time_provider_state s_time_state;
static K_MUTEX_DEFINE(s_time_mutex);

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

static bool is_single_capability(enum lichen_hal_capability capability)
{
	uint32_t value = (uint32_t)capability;

	return value != 0U &&
	       (value & (value - 1U)) == 0U &&
	       (value & ~LICHEN_HAL_KNOWN_CAPS) == 0U;
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
	switch (s_caps.location) {
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
	switch (s_caps.time) {
	case LICHEN_HAL_TIME_UPTIME:
		return 0;
	case LICHEN_HAL_TIME_GNSS:
		return lichen_hal_capability_status(LICHEN_HAL_CAP_GNSS);
	default:
		return -EINVAL;
	}
}

static int __maybe_unused return_device_if_ready(const struct device **out,
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

int lichen_hal_reboot_status(void)
{
	return IS_ENABLED(CONFIG_REBOOT) ? 0 : -ENOTSUP;
}

#if IS_ENABLED(CONFIG_HWINFO)
static uint32_t reset_cause_from_zephyr(uint32_t cause)
{
	uint32_t out = 0U;

	if ((cause & RESET_PIN) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PIN;
	}
	if ((cause & RESET_SOFTWARE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_SOFTWARE;
	}
	if ((cause & RESET_BROWNOUT) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_BROWNOUT;
	}
	if ((cause & RESET_POR) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_POWER_ON;
	}
	if ((cause & RESET_WATCHDOG) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_WATCHDOG;
	}
	if ((cause & RESET_DEBUG) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_DEBUG;
	}
	if ((cause & RESET_SECURITY) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_SECURITY;
	}
	if ((cause & RESET_LOW_POWER_WAKE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_LOW_POWER_WAKE;
	}
	if ((cause & RESET_CPU_LOCKUP) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_CPU_LOCKUP;
	}
	if ((cause & RESET_PARITY) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PARITY;
	}
	if ((cause & RESET_PLL) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PLL;
	}
	if ((cause & RESET_CLOCK) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_CLOCK;
	}
	if ((cause & RESET_HARDWARE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_HARDWARE;
	}
	if ((cause & RESET_USER) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_USER;
	}
	if ((cause & RESET_TEMPERATURE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_TEMPERATURE;
	}

	return out;
}
#endif

static bool valid_reset_request(enum lichen_hal_reset_request request)
{
	return request >= LICHEN_HAL_RESET_REQUEST_COLD_REBOOT &&
	       request <= LICHEN_HAL_RESET_REQUEST_FACTORY_RESET;
}

int lichen_hal_reset_request(enum lichen_hal_reset_request request)
{
	if (!valid_reset_request(request)) {
		return -EINVAL;
	}
	if (request == LICHEN_HAL_RESET_REQUEST_FACTORY_RESET) {
		return -ENOTSUP;
	}
	if (!IS_ENABLED(CONFIG_REBOOT)) {
		return -ENOTSUP;
	}

#ifdef CONFIG_ZTEST
	s_test_reset_request = request;
	s_test_reset_request_valid = true;
	return 0;
#else
#if IS_ENABLED(CONFIG_REBOOT)
	if (request == LICHEN_HAL_RESET_REQUEST_WARM_REBOOT) {
		sys_reboot(SYS_REBOOT_WARM);
	} else {
		sys_reboot(SYS_REBOOT_COLD);
	}

	return -EIO;
#else
	return -ENOTSUP;
#endif
#endif
}

int lichen_hal_reset_diagnostics_snapshot_get(
	struct lichen_hal_reset_diagnostics_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return -EINVAL;
	}

	*snapshot = (struct lichen_hal_reset_diagnostics_snapshot){ 0 };
	snapshot->reboot_supported = lichen_hal_reboot_status() == 0;
	snapshot->warm_reboot_best_effort = snapshot->reboot_supported;

#if IS_ENABLED(CONFIG_HWINFO)
	uint32_t reset_cause = 0U;
	uint32_t supported_reset_cause = 0U;
	int ret;

	ret = hwinfo_get_supported_reset_cause(&supported_reset_cause);
	if (ret == 0) {
		snapshot->reset_cause_supported = true;
		snapshot->supported_reset_cause_valid = true;
		snapshot->supported_reset_cause =
			reset_cause_from_zephyr(supported_reset_cause);
		snapshot->supported_reset_cause_raw_valid = true;
		snapshot->supported_reset_cause_raw = supported_reset_cause;
	}

	ret = hwinfo_get_reset_cause(&reset_cause);
	if (ret == 0) {
		snapshot->reset_cause_supported = true;
		snapshot->reset_cause_valid = true;
		snapshot->reset_cause = reset_cause_from_zephyr(reset_cause);
		snapshot->reset_cause_raw_valid = true;
		snapshot->reset_cause_raw = reset_cause;
	}
#endif

	return 0;
}

int lichen_hal_reset_diagnostics_clear(void)
{
	/*
	 * Zephyr has hwinfo_clear_reset_cause(), but no non-destructive
	 * capability probe for it. Keep clear unsupported until a HAL-owned
	 * backend policy can prove support without snapshot side effects.
	 */
	return -ENOTSUP;
}

static bool valid_source_class(enum lichen_hal_location_source_class source_class)
{
	return source_class > LICHEN_HAL_LOCATION_SOURCE_NONE &&
	       source_class <= LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
}

static bool valid_fix_state(enum lichen_hal_location_fix_state fix_state)
{
	return fix_state >= LICHEN_HAL_LOCATION_FIX_NONE &&
	       fix_state <= LICHEN_HAL_LOCATION_FIX_ERROR &&
	       fix_state != LICHEN_HAL_LOCATION_FIX_STALE;
}

static bool valid_fix_source(enum lichen_hal_fix_source fix_source)
{
	return fix_source >= LICHEN_HAL_FIX_SOURCE_NONE &&
	       fix_source <= LICHEN_HAL_FIX_SOURCE_GNSS;
}

static bool valid_time_source_class(
	enum lichen_hal_time_source_class source_class)
{
	return source_class > LICHEN_HAL_TIME_SOURCE_NONE &&
	       source_class <= LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
}

static bool valid_position_e7(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

static int64_t location_now_ms(void)
{
#ifdef CONFIG_ZTEST
	if (s_use_test_uptime) {
		return s_test_uptime_ms;
	}
#endif
	return k_uptime_get();
}

static uint32_t location_age_seconds(const struct lichen_hal_location_sample *sample)
{
	int64_t now = location_now_ms();
	int64_t observed = sample->observed_uptime_ms;
	uint64_t elapsed_ms;

	if (now <= observed) {
		return 0U;
	}
	if (observed < 0 && now >= 0) {
		elapsed_ms = (uint64_t)now + (uint64_t)(-(observed + 1)) + 1U;
	} else {
		elapsed_ms = (uint64_t)(now - observed);
	}
	if (elapsed_ms / 1000U > UINT32_MAX) {
		return UINT32_MAX;
	}

	return (uint32_t)(elapsed_ms / 1000U);
}

static uint32_t elapsed_seconds_since_ms(int64_t observed)
{
	int64_t now = location_now_ms();
	uint64_t elapsed_ms;

	if (now <= observed) {
		return 0U;
	}
	if (observed < 0 && now >= 0) {
		elapsed_ms = (uint64_t)now + (uint64_t)(-(observed + 1)) + 1U;
	} else {
		elapsed_ms = (uint64_t)(now - observed);
	}
	if (elapsed_ms / 1000U > UINT32_MAX) {
		return UINT32_MAX;
	}

	return (uint32_t)(elapsed_ms / 1000U);
}

static uint32_t time_age_seconds(const struct lichen_hal_time_sample *sample)
{
	return elapsed_seconds_since_ms(sample->observed_uptime_ms);
}

static uint32_t time_build_epoch(void)
{
	return (uint32_t)CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX;
}

static uint32_t time_effective_epoch_floor_locked(void)
{
	uint32_t floor = time_build_epoch();

	if (s_time_state.provision_epoch_valid &&
	    s_time_state.provision_epoch > floor) {
		floor = s_time_state.provision_epoch;
	}

	return floor;
}

static bool provision_epoch_in_lead_bound(uint32_t provision_epoch)
{
	uint32_t build_epoch = time_build_epoch();
	uint64_t max_epoch = (uint64_t)build_epoch +
			     (uint64_t)CONFIG_LICHEN_TIME_PROVISION_MAX_LEAD_S;

	return provision_epoch >= build_epoch && provision_epoch <= max_epoch;
}

static int time_source_priority(enum lichen_hal_time_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC:
		return 6;
	case LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT:
		return 5;
	case LICHEN_HAL_TIME_SOURCE_NETWORK:
		return 4;
	case LICHEN_HAL_TIME_SOURCE_GNSS:
		return 3;
	case LICHEN_HAL_TIME_SOURCE_INTERNAL_RTC:
		return 2;
	case LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL:
		return 1;
	case LICHEN_HAL_TIME_SOURCE_NONE:
	default:
		return 0;
	}
}

static bool time_sample_is_stale(const struct lichen_hal_time_sample *sample)
{
	return time_age_seconds(sample) > CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S;
}

static bool time_sample_passes_floor_locked(
	const struct lichen_hal_time_sample *sample)
{
	return sample->unix_time_valid &&
	       sample->unix_time >= time_effective_epoch_floor_locked();
}

static bool time_sample_can_establish_locked(
	const struct lichen_hal_time_sample *sample)
{
	return sample->source_class != LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL &&
	       time_sample_passes_floor_locked(sample) &&
	       !time_sample_is_stale(sample);
}

static uint32_t time_sample_current_unix(
	const struct lichen_hal_time_sample *sample)
{
	uint64_t current = (uint64_t)sample->unix_time +
			   (uint64_t)time_age_seconds(sample);

	return current > UINT32_MAX ? UINT32_MAX : (uint32_t)current;
}

static const struct lichen_hal_time_sample *select_time_sample_locked(void)
{
	for (int source = LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_TIME_SOURCE_NONE; source--) {
		const struct lichen_hal_time_sample *sample =
			&s_time_state.samples[source];

		if (!s_time_state.has_sample[source]) {
			continue;
		}
		if (time_sample_can_establish_locked(sample)) {
			return sample;
		}
	}

	return NULL;
}

static const struct lichen_hal_time_sample *select_time_diagnostic_sample_locked(void)
{
	if (s_time_state.has_diagnostic_sample &&
	    s_time_state.last_rejection == LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR) {
		return &s_time_state.diagnostic_sample;
	}
	for (int source = LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_TIME_SOURCE_NONE; source--) {
		if (s_time_state.has_sample[source]) {
			return &s_time_state.samples[source];
		}
	}

	return NULL;
}

static bool sample_is_stale(const struct lichen_hal_location_sample *sample)
{
	return location_age_seconds(sample) >
	       CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S;
}

static bool sample_has_usable_fix(const struct lichen_hal_location_sample *sample)
{
	return sample->latitude_e7_valid && sample->longitude_e7_valid &&
	       (sample->fix_state == LICHEN_HAL_LOCATION_FIX_2D ||
		sample->fix_state == LICHEN_HAL_LOCATION_FIX_3D);
}

static const struct lichen_hal_location_sample *select_location_sample(void)
{
	const struct lichen_hal_location_sample *best_metadata = NULL;

	for (int source = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_LOCATION_SOURCE_NONE; source--) {
		const struct lichen_hal_location_sample *sample =
			&s_location_state.samples[source];

		if (!s_location_state.has_sample[source]) {
			continue;
		}
		if (!sample_is_stale(sample) && sample_has_usable_fix(sample)) {
			return sample;
		}
	}

	for (int source = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_LOCATION_SOURCE_NONE; source--) {
		const struct lichen_hal_location_sample *sample =
			&s_location_state.samples[source];

		if (!s_location_state.has_sample[source]) {
			continue;
		}
		if (!sample_is_stale(sample)) {
			return sample;
		}
		if (best_metadata == NULL) {
			best_metadata = sample;
		}
	}

	return best_metadata;
}

int lichen_hal_location_submit(const struct lichen_hal_location_sample *sample)
{
	struct lichen_hal_location_sample copy;

	if (sample == NULL) {
		return -EINVAL;
	}
	if (!valid_source_class(sample->source_class) ||
	    !valid_fix_state(sample->fix_state) ||
	    !valid_fix_source(sample->fix_source)) {
		return -EINVAL;
	}
	if (sample->fix_source == LICHEN_HAL_FIX_SOURCE_GNSS &&
	    sample->source_class != LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE &&
	    sample->source_class != LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE) {
		return -EINVAL;
	}
	if (sample->latitude_e7_valid != sample->longitude_e7_valid) {
		return -EINVAL;
	}
	if (sample->latitude_e7_valid &&
	    !valid_position_e7(sample->latitude_e7, sample->longitude_e7)) {
		return -EINVAL;
	}
	if ((sample->fix_state == LICHEN_HAL_LOCATION_FIX_2D ||
	     sample->fix_state == LICHEN_HAL_LOCATION_FIX_3D) &&
	    (!sample->latitude_e7_valid || !sample->longitude_e7_valid)) {
		return -EINVAL;
	}
	copy = *sample;
	if (!copy.observed_uptime_ms_valid) {
		copy.observed_uptime_ms = location_now_ms();
		copy.observed_uptime_ms_valid = true;
	} else if (copy.observed_uptime_ms > location_now_ms()) {
		copy.observed_uptime_ms = location_now_ms();
	}

	k_mutex_lock(&s_location_mutex, K_FOREVER);
	s_location_state.samples[copy.source_class] = copy;
	if (sample->source_name != NULL) {
		strncpy(s_location_state.source_names[copy.source_class],
			sample->source_name,
			sizeof(s_location_state.source_names[copy.source_class]) - 1U);
		s_location_state.source_names[copy.source_class]
			[sizeof(s_location_state.source_names[copy.source_class]) - 1U] = '\0';
	} else {
		s_location_state.source_names[copy.source_class][0] = '\0';
	}
	s_location_state.samples[copy.source_class].source_name =
		s_location_state.source_names[copy.source_class];
	s_location_state.has_sample[copy.source_class] = true;
	k_mutex_unlock(&s_location_mutex);

	return 0;
}

int lichen_hal_location_clear_source(
	enum lichen_hal_location_source_class source_class)
{
	if (!valid_source_class(source_class)) {
		return -EINVAL;
	}

	k_mutex_lock(&s_location_mutex, K_FOREVER);
	s_location_state.samples[source_class] =
		(struct lichen_hal_location_sample){ 0 };
	s_location_state.source_names[source_class][0] = '\0';
	s_location_state.has_sample[source_class] = false;
	k_mutex_unlock(&s_location_mutex);

	return 0;
}

void lichen_hal_location_clear(void)
{
	k_mutex_lock(&s_location_mutex, K_FOREVER);
	s_location_state = (struct location_provider_state){ 0 };
	k_mutex_unlock(&s_location_mutex);
}

static void time_set_rejection_locked(
	enum lichen_hal_time_rejection_reason reason)
{
	s_time_state.last_rejection = reason;
}

static void time_store_sample_locked(const struct lichen_hal_time_sample *sample)
{
	s_time_state.samples[sample->source_class] = *sample;
	if (sample->source_name != NULL) {
		strncpy(s_time_state.source_names[sample->source_class],
			sample->source_name,
			sizeof(s_time_state.source_names[sample->source_class]) - 1U);
		s_time_state.source_names[sample->source_class]
			[sizeof(s_time_state.source_names[sample->source_class]) - 1U] = '\0';
	} else {
		s_time_state.source_names[sample->source_class][0] = '\0';
	}
	s_time_state.samples[sample->source_class].source_name =
		s_time_state.source_names[sample->source_class];
	s_time_state.has_sample[sample->source_class] = true;
}

static void time_store_diagnostic_sample_locked(
	const struct lichen_hal_time_sample *sample)
{
	s_time_state.diagnostic_sample = *sample;
	if (sample->source_name != NULL) {
		strncpy(s_time_state.diagnostic_source_name,
			sample->source_name,
			sizeof(s_time_state.diagnostic_source_name) - 1U);
		s_time_state.diagnostic_source_name
			[sizeof(s_time_state.diagnostic_source_name) - 1U] = '\0';
	} else {
		s_time_state.diagnostic_source_name[0] = '\0';
	}
	s_time_state.diagnostic_sample.source_name =
		s_time_state.diagnostic_source_name;
	s_time_state.has_diagnostic_sample = true;
}

static void time_clear_diagnostic_sample_locked(void)
{
	memset(&s_time_state.diagnostic_sample, 0,
	       sizeof(s_time_state.diagnostic_sample));
	memset(s_time_state.diagnostic_source_name, 0,
	       sizeof(s_time_state.diagnostic_source_name));
	s_time_state.has_diagnostic_sample = false;
}

int lichen_hal_time_provision_epoch_set(uint32_t provision_epoch,
					bool authenticated)
{
	k_mutex_lock(&s_time_mutex, K_FOREVER);
	if (!authenticated) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED);
		k_mutex_unlock(&s_time_mutex);
		return -EINVAL;
	}
	if (provision_epoch == 0U || provision_epoch < time_build_epoch()) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_INVALID);
		k_mutex_unlock(&s_time_mutex);
		return -EINVAL;
	}
	if (!provision_epoch_in_lead_bound(provision_epoch)) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE);
		k_mutex_unlock(&s_time_mutex);
		return -EINVAL;
	}

	s_time_state.provision_epoch = provision_epoch;
	s_time_state.provision_epoch_valid = true;
	time_clear_diagnostic_sample_locked();
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&s_time_mutex);
	return 0;
}

void lichen_hal_time_provision_epoch_clear(void)
{
	k_mutex_lock(&s_time_mutex, K_FOREVER);
	s_time_state.provision_epoch_valid = false;
	s_time_state.provision_epoch = 0U;
	time_clear_diagnostic_sample_locked();
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&s_time_mutex);
}

int lichen_hal_time_submit(const struct lichen_hal_time_sample *sample)
{
	struct lichen_hal_time_sample copy;
	const struct lichen_hal_time_sample *selected;

	if (sample == NULL) {
		return -EINVAL;
	}
	if (!valid_time_source_class(sample->source_class)) {
		k_mutex_lock(&s_time_mutex, K_FOREVER);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_INVALID_SOURCE);
		k_mutex_unlock(&s_time_mutex);
		return -EINVAL;
	}
	if (sample->source_class == LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL ||
	    !sample->unix_time_valid) {
		k_mutex_lock(&s_time_mutex, K_FOREVER);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_MISSING_TIMESTAMP);
		k_mutex_unlock(&s_time_mutex);
		return -EINVAL;
	}

	copy = *sample;
	if (!copy.observed_uptime_ms_valid) {
		copy.observed_uptime_ms = location_now_ms();
		copy.observed_uptime_ms_valid = true;
	} else if (copy.observed_uptime_ms > location_now_ms()) {
		copy.observed_uptime_ms = location_now_ms();
	}

	k_mutex_lock(&s_time_mutex, K_FOREVER);
	if (!time_sample_passes_floor_locked(&copy)) {
		time_store_diagnostic_sample_locked(&copy);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR);
		k_mutex_unlock(&s_time_mutex);
		return -ERANGE;
	}
	if (time_sample_is_stale(&copy)) {
		time_clear_diagnostic_sample_locked();
		time_store_sample_locked(&copy);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_STALE);
		k_mutex_unlock(&s_time_mutex);
		return -ETIME;
	}

	selected = select_time_sample_locked();
	if (selected != NULL &&
	    time_source_priority(copy.source_class) <
	    time_source_priority(selected->source_class) &&
	    copy.unix_time < time_sample_current_unix(selected)) {
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_LOWER_TRUST);
		k_mutex_unlock(&s_time_mutex);
		return -EALREADY;
	}

	time_clear_diagnostic_sample_locked();
	time_store_sample_locked(&copy);
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&s_time_mutex);
	return 0;
}

void lichen_hal_time_clear(void)
{
	k_mutex_lock(&s_time_mutex, K_FOREVER);
	memset(s_time_state.samples, 0, sizeof(s_time_state.samples));
	memset(s_time_state.source_names, 0, sizeof(s_time_state.source_names));
	memset(s_time_state.has_sample, 0, sizeof(s_time_state.has_sample));
	time_clear_diagnostic_sample_locked();
	s_time_state.last_rejection = LICHEN_HAL_TIME_REJECT_NONE;
	k_mutex_unlock(&s_time_mutex);
}

int lichen_hal_time_snapshot_get(struct lichen_hal_time_snapshot *snapshot)
{
	const struct lichen_hal_time_sample *selected;
	const struct lichen_hal_time_sample *rejected;
	bool selected_valid = false;

	if (snapshot == NULL) {
		return -EINVAL;
	}

	*snapshot = (struct lichen_hal_time_snapshot){ 0 };
	snapshot->provider_available = lichen_hal_time_status() == 0;
	snapshot->build_epoch = time_build_epoch();

	k_mutex_lock(&s_time_mutex, K_FOREVER);
	snapshot->effective_epoch_floor = time_effective_epoch_floor_locked();
	snapshot->provision_epoch_valid = s_time_state.provision_epoch_valid;
	snapshot->provision_epoch = s_time_state.provision_epoch;
	snapshot->last_rejection = s_time_state.last_rejection;

	selected = select_time_sample_locked();
	selected_valid = selected != NULL;
	if (selected == NULL) {
		selected = select_time_diagnostic_sample_locked();
	}
	rejected = s_time_state.has_diagnostic_sample &&
		   s_time_state.last_rejection == LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR ?
		   &s_time_state.diagnostic_sample : NULL;
	if (selected != NULL) {
		struct lichen_hal_time_sample sample = *selected;
		char source_name[sizeof(snapshot->source_name)];

		if (sample.source_name == NULL) {
			source_name[0] = '\0';
			if (sample.source_class >= LICHEN_HAL_TIME_SOURCE_NONE &&
			    sample.source_class <= LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC) {
				strncpy(source_name,
					s_time_state.source_names[sample.source_class],
					sizeof(source_name) - 1U);
				source_name[sizeof(source_name) - 1U] = '\0';
			}
			sample.source_name = source_name;
		}

		snapshot->wall_clock_valid = selected_valid;
		snapshot->source_class_valid = true;
		snapshot->source_class = sample.source_class;
		strncpy(snapshot->source_name, sample.source_name,
			sizeof(snapshot->source_name) - 1U);
		snapshot->source_name[sizeof(snapshot->source_name) - 1U] = '\0';
		snapshot->unix_time_valid = selected_valid;
		if (selected_valid) {
			snapshot->unix_time = time_sample_current_unix(&sample);
		}
		snapshot->age_seconds_valid = sample.observed_uptime_ms_valid;
		snapshot->age_seconds = time_age_seconds(&sample);
		snapshot->accuracy_ms_valid = sample.accuracy_ms_valid;
		snapshot->accuracy_ms = sample.accuracy_ms;
		snapshot->quality_valid = sample.quality_valid;
		snapshot->quality = sample.quality;
		snapshot->passed_epoch_floor =
			time_sample_passes_floor_locked(&sample);
	}
	if (rejected != NULL) {
		snapshot->rejection_source_class_valid = true;
		snapshot->rejection_source_class = rejected->source_class;
		if (rejected->source_name != NULL) {
			strncpy(snapshot->rejection_source_name,
				rejected->source_name,
				sizeof(snapshot->rejection_source_name) - 1U);
			snapshot->rejection_source_name
				[sizeof(snapshot->rejection_source_name) - 1U] = '\0';
		}
		snapshot->rejection_passed_epoch_floor =
			time_sample_passes_floor_locked(rejected);
	}
	k_mutex_unlock(&s_time_mutex);

	return 0;
}

static void snapshot_from_sample(struct lichen_hal_location_time_snapshot *snapshot,
				 const struct lichen_hal_location_sample *sample)
{
	const bool stale = sample_is_stale(sample);

	snapshot->location_provider_available = true;
	snapshot->source_class_valid = true;
	snapshot->source_class = sample->source_class;
	if (sample->source_name != NULL) {
		strncpy(snapshot->source_name, sample->source_name,
			sizeof(snapshot->source_name) - 1U);
		snapshot->source_name[sizeof(snapshot->source_name) - 1U] = '\0';
	}
	snapshot->fix_state_valid = true;
	snapshot->fix_state = stale ? LICHEN_HAL_LOCATION_FIX_STALE :
				      sample->fix_state;
	snapshot->age_seconds_valid = sample->observed_uptime_ms_valid;
	snapshot->age_seconds = location_age_seconds(sample);
	snapshot->horizontal_accuracy_mm_valid =
		!stale && sample->horizontal_accuracy_mm_valid;
	snapshot->horizontal_accuracy_mm = sample->horizontal_accuracy_mm;
	snapshot->vertical_accuracy_mm_valid =
		!stale && sample->vertical_accuracy_mm_valid;
	snapshot->vertical_accuracy_mm = sample->vertical_accuracy_mm;
	snapshot->fix_source_valid =
		!stale && sample_has_usable_fix(sample) &&
		sample->fix_source != LICHEN_HAL_FIX_SOURCE_NONE;
	snapshot->fix_source = sample->fix_source;
	snapshot->satellites_valid = !stale && sample->satellites_valid;
	snapshot->satellites = sample->satellites;
	snapshot->fix_time_unix_valid = !stale && sample->fix_time_unix_valid;
	snapshot->fix_time_unix = sample->fix_time_unix;
	snapshot->altitude_m_valid = !stale && sample->altitude_m_valid;
	snapshot->altitude_m = sample->altitude_m;
	snapshot->altitude_cm_valid = !stale && sample->altitude_cm_valid;
	snapshot->altitude_cm = sample->altitude_cm;

	if (!stale && sample_has_usable_fix(sample)) {
		snapshot->latitude_e7_valid = true;
		snapshot->latitude_e7 = sample->latitude_e7;
		snapshot->longitude_e7_valid = true;
		snapshot->longitude_e7 = sample->longitude_e7;
	}
}

int lichen_hal_location_time_snapshot_get(
	struct lichen_hal_location_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_ZTEST
	if (s_has_test_location_time_snapshot) {
		*snapshot = s_test_location_time_snapshot;
		return 0;
	}
#endif

	*snapshot = (struct lichen_hal_location_time_snapshot){ 0 };

	const struct lichen_hal_location_sample *selected;

	k_mutex_lock(&s_location_mutex, K_FOREVER);
	selected = select_location_sample();
	if (selected != NULL) {
		struct lichen_hal_location_sample sample = *selected;
		char source_name[sizeof(snapshot->source_name)];

		strncpy(source_name,
			s_location_state.source_names[sample.source_class],
			sizeof(source_name) - 1U);
		source_name[sizeof(source_name) - 1U] = '\0';
		sample.source_name = source_name;

		k_mutex_unlock(&s_location_mutex);
		snapshot_from_sample(snapshot, &sample);
		snapshot->time_provider_available =
			s_caps.time == LICHEN_HAL_TIME_GNSS &&
			lichen_hal_time_status() == 0;
		return 0;
	}
	k_mutex_unlock(&s_location_mutex);

	snapshot->location_provider_available =
		lichen_hal_location_status() == 0;
	snapshot->time_provider_available =
		s_caps.time == LICHEN_HAL_TIME_GNSS && lichen_hal_time_status() == 0;

	if (s_caps.location == LICHEN_HAL_LOCATION_GNSS &&
	    snapshot->location_provider_available) {
		snapshot->source_class_valid = true;
		snapshot->source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE;
		(void)snprintf(snapshot->source_name, sizeof(snapshot->source_name),
			       "gnss0");
		snapshot->fix_state_valid = true;
		snapshot->fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX;
		snapshot->fix_source = LICHEN_HAL_FIX_SOURCE_GNSS;
	}

	return 0;
}

#ifdef CONFIG_LICHEN_DUTY_CYCLE
#define LICHEN_DUTY_CYCLE_WINDOW_MS 3600000ULL

static void prune(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	uint64_t ws = now > LICHEN_DUTY_CYCLE_WINDOW_MS ? now - LICHEN_DUTY_CYCLE_WINDOW_MS : 0ULL;
	while (t->len > 0) {
		uint8_t idx = t->head;
		uint64_t e = t->records[idx] + (uint64_t)t->durations[idx];
		if (e <= ws) {
			t->head = (t->head + 1U) % 32U;
			t->len--;
		} else break;
	}
}

static uint32_t total_tx(const struct lichen_duty_cycle_ctx *t, uint64_t now) {
	uint64_t ws = now > LICHEN_DUTY_CYCLE_WINDOW_MS ? now - LICHEN_DUTY_CYCLE_WINDOW_MS : 0ULL;
	uint32_t tot = 0;
	for (uint8_t i = 0; i < t->len; i++) {
		uint8_t k = (t->head + i) % 32U;
		uint64_t ts = t->records[k];
		uint32_t d = t->durations[k];
		if (ts >= ws) {
			if (tot > UINT32_MAX - d) tot = UINT32_MAX; else tot += d;
		} else {
			uint64_t e = ts + (uint64_t)d;
			if (e > ws) {
				uint32_t o = (uint32_t)(e - ws);
				if (tot > UINT32_MAX - o) tot = UINT32_MAX; else tot += o;
			}
		}
	}
	return tot;
}

void lichen_duty_cycle_init(struct lichen_duty_cycle_ctx *t, uint16_t permille) {
	t->head = 0;
	t->len = 0;
	t->duty_permille = (permille == 0 || permille > 1000) ? LICHEN_DUTY_CYCLE_DEFAULT_PERMILLE : permille;
}

bool lichen_duty_cycle_record_tx(struct lichen_duty_cycle_ctx *t, uint64_t ts, uint32_t dur) {
	prune(t, ts);
	if (t->len == 32) return false;
	uint8_t idx = (t->head + t->len) % 32U;
	t->records[idx] = ts;
	t->durations[idx] = dur;
	t->len++;
	return true;
}

uint32_t lichen_duty_cycle_remaining_ms(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	prune(t, now);
	uint32_t m = (LICHEN_DUTY_CYCLE_WINDOW_MS / 1000ULL) * t->duty_permille;
	uint32_t u = total_tx(t, now);
	return m > u ? m - u : 0;
}

uint16_t lichen_duty_cycle_usage_permille(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	prune(t, now);
	uint32_t u = total_tx(t, now);
	return (uint16_t)((uint64_t)u * 1000ULL / LICHEN_DUTY_CYCLE_WINDOW_MS);
}

uint64_t lichen_duty_cycle_next_tx_available_ms(struct lichen_duty_cycle_ctx *t, uint64_t now, uint32_t dur) {
	prune(t, now);
	uint32_t m = (LICHEN_DUTY_CYCLE_WINDOW_MS / 1000ULL) * t->duty_permille;
	uint32_t u = total_tx(t, now);
	if ((uint64_t)u + (uint64_t)dur <= (uint64_t)m) return now;
	uint32_t need = (uint32_t)((uint64_t)u + (uint64_t)dur - (uint64_t)m);
	uint32_t f = 0;
	for (uint8_t i = 0; i < t->len; i++) {
		uint8_t k = (t->head + i) % 32U;
		uint32_t d = t->durations[k];
		if (f > UINT32_MAX - d) f = UINT32_MAX; else f += d;
		if (f >= need) return t->records[k] + LICHEN_DUTY_CYCLE_WINDOW_MS;
	}
	return (uint64_t)-1;
}

bool lichen_duty_cycle_can_transmit(struct lichen_duty_cycle_ctx *t, uint64_t now, uint32_t dur) {
	return lichen_duty_cycle_remaining_ms(t, now) >= dur;
}
#endif

#ifdef CONFIG_ZTEST
void lichen_hal_location_test_set_uptime_ms(int64_t uptime_ms)
{
	s_test_uptime_ms = uptime_ms;
	s_use_test_uptime = true;
}

void lichen_hal_location_test_use_real_uptime(void)
{
	s_use_test_uptime = false;
	s_test_uptime_ms = 0;
}

int64_t lichen_hal_location_test_now_ms(void)
{
	return location_now_ms();
}

void lichen_hal_location_time_test_set_snapshot(
	const struct lichen_hal_location_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		s_has_test_location_time_snapshot = false;
		s_test_location_time_snapshot =
			(struct lichen_hal_location_time_snapshot){ 0 };
		return;
	}

	s_test_location_time_snapshot = *snapshot;
	s_has_test_location_time_snapshot = true;
}

bool lichen_hal_reset_test_last_request_valid(void)
{
	return s_test_reset_request_valid;
}

enum lichen_hal_reset_request lichen_hal_reset_test_last_request(void)
{
	return s_test_reset_request;
}

void lichen_hal_reset_test_clear_request(void)
{
	s_test_reset_request_valid = false;
	s_test_reset_request = LICHEN_HAL_RESET_REQUEST_COLD_REBOOT;
}
#endif
