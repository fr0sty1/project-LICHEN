/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>

#define LICHEN_HAL_KNOWN_CAPS \
	(LICHEN_HAL_CAP_LORA | LICHEN_HAL_CAP_BLE_LOCAL | \
	 LICHEN_HAL_CAP_SERIAL_LOCAL | LICHEN_HAL_CAP_GNSS | \
	 LICHEN_HAL_CAP_BATTERY | LICHEN_HAL_CAP_PMIC | \
	 LICHEN_HAL_CAP_BUTTONS | LICHEN_HAL_CAP_LEDS | \
	 LICHEN_HAL_CAP_DISPLAY | LICHEN_HAL_CAP_EXTERNAL_FLASH)

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
#endif

struct location_provider_state {
	struct lichen_hal_location_sample samples[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
	char source_names[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1]
			 [sizeof(((struct lichen_hal_location_time_snapshot *)0)->source_name)];
	bool has_sample[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
};

static struct location_provider_state s_location_state;
static K_MUTEX_DEFINE(s_location_mutex);

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
	}

	ret = lichen_hal_pmic_device_get(&dev);
	if (ret == 0) {
		snapshot->pmic_provider_available = true;
	}

	return 0;
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

	if (now <= observed) {
		return 0U;
	}
	if ((uint64_t)(now - observed) / 1000U > UINT32_MAX) {
		return UINT32_MAX;
	}

	return (uint32_t)((now - observed) / 1000);
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
	if ((sample->fix_state == LICHEN_HAL_LOCATION_FIX_2D ||
	     sample->fix_state == LICHEN_HAL_LOCATION_FIX_3D) &&
	    (!sample->latitude_e7_valid || !sample->longitude_e7_valid)) {
		return -EINVAL;
	}
	if (sample->observed_uptime_ms_valid && sample->observed_uptime_ms < 0) {
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

void lichen_hal_location_clear(void)
{
	k_mutex_lock(&s_location_mutex, K_FOREVER);
	s_location_state = (struct location_provider_state){ 0 };
	k_mutex_unlock(&s_location_mutex);
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
		strcpy(snapshot->source_name, "gnss0");
		snapshot->fix_state_valid = true;
		snapshot->fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX;
		snapshot->fix_source = LICHEN_HAL_FIX_SOURCE_GNSS;
	}

	return 0;
}

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
#endif
