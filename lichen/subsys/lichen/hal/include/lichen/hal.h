/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_HAL_H_
#define LICHEN_HAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/util.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

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

enum lichen_hal_time_source_class {
	LICHEN_HAL_TIME_SOURCE_NONE,
	LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL,
	LICHEN_HAL_TIME_SOURCE_INTERNAL_RTC,
	LICHEN_HAL_TIME_SOURCE_GNSS,
	LICHEN_HAL_TIME_SOURCE_NETWORK,
	LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT,
	LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC,
};

enum lichen_hal_time_rejection_reason {
	LICHEN_HAL_TIME_REJECT_NONE,
	LICHEN_HAL_TIME_REJECT_INVALID_SOURCE,
	LICHEN_HAL_TIME_REJECT_MISSING_TIMESTAMP,
	LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR,
	LICHEN_HAL_TIME_REJECT_STALE,
	LICHEN_HAL_TIME_REJECT_LOWER_TRUST,
	LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED,
	LICHEN_HAL_TIME_REJECT_PROVISION_INVALID,
	LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE,
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

enum lichen_hal_location_source_class {
	LICHEN_HAL_LOCATION_SOURCE_NONE,
	LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
	LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE,
	LICHEN_HAL_LOCATION_SOURCE_NETWORK,
	LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT,
	LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
};

enum lichen_hal_location_fix_state {
	LICHEN_HAL_LOCATION_FIX_NONE,
	LICHEN_HAL_LOCATION_FIX_NO_FIX,
	LICHEN_HAL_LOCATION_FIX_2D,
	LICHEN_HAL_LOCATION_FIX_3D,
	LICHEN_HAL_LOCATION_FIX_STALE,
	LICHEN_HAL_LOCATION_FIX_ERROR,
};

struct lichen_hal_location_time_snapshot {
	bool location_provider_available;
	bool time_provider_available;
	bool source_class_valid;
	enum lichen_hal_location_source_class source_class;
	char source_name[24];
	bool fix_state_valid;
	enum lichen_hal_location_fix_state fix_state;
	bool age_seconds_valid;
	uint32_t age_seconds;
	bool horizontal_accuracy_mm_valid;
	uint32_t horizontal_accuracy_mm;
	bool vertical_accuracy_mm_valid;
	uint32_t vertical_accuracy_mm;
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool altitude_cm_valid;
	int32_t altitude_cm;
	bool fix_time_unix_valid;
	uint64_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
	bool fix_source_valid;
	enum lichen_hal_fix_source fix_source;
};

struct lichen_hal_time_snapshot {
	bool provider_available;
	bool wall_clock_valid;
	bool source_class_valid;
	enum lichen_hal_time_source_class source_class;
	char source_name[24];
	bool unix_time_valid;
	uint64_t unix_time;
	bool age_seconds_valid;
	uint32_t age_seconds;
	bool accuracy_ms_valid;
	uint32_t accuracy_ms;
	bool quality_valid;
	uint8_t quality;
	bool passed_epoch_floor;
	enum lichen_hal_time_rejection_reason last_rejection;
	bool rejection_source_class_valid;
	enum lichen_hal_time_source_class rejection_source_class;
	char rejection_source_name[24];
	bool rejection_passed_epoch_floor;
	uint32_t effective_epoch_floor;
	uint32_t build_epoch;
	bool provision_epoch_valid;
	uint32_t provision_epoch;
};

struct lichen_hal_time_sample {
	enum lichen_hal_time_source_class source_class;
	const char *source_name;
	bool unix_time_valid;
	uint32_t unix_time;
	bool observed_uptime_ms_valid;
	int64_t observed_uptime_ms;
	bool accuracy_ms_valid;
	uint32_t accuracy_ms;
	bool quality_valid;
	uint8_t quality;
};

struct lichen_hal_location_sample {
	enum lichen_hal_location_source_class source_class;
	enum lichen_hal_location_fix_state fix_state;
	enum lichen_hal_fix_source fix_source;
	const char *source_name;
	bool observed_uptime_ms_valid;
	int64_t observed_uptime_ms;
	bool horizontal_accuracy_mm_valid;
	uint32_t horizontal_accuracy_mm;
	bool vertical_accuracy_mm_valid;
	uint32_t vertical_accuracy_mm;
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool altitude_cm_valid;
	int32_t altitude_cm;
	bool fix_time_unix_valid;
	uint32_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
};

enum lichen_hal_reset_request {
	LICHEN_HAL_RESET_REQUEST_COLD_REBOOT,
	LICHEN_HAL_RESET_REQUEST_WARM_REBOOT,
	LICHEN_HAL_RESET_REQUEST_FACTORY_RESET,
};

enum lichen_hal_reset_cause {
	LICHEN_HAL_RESET_CAUSE_PIN = BIT(0),
	LICHEN_HAL_RESET_CAUSE_SOFTWARE = BIT(1),
	LICHEN_HAL_RESET_CAUSE_BROWNOUT = BIT(2),
	LICHEN_HAL_RESET_CAUSE_POWER_ON = BIT(3),
	LICHEN_HAL_RESET_CAUSE_WATCHDOG = BIT(4),
	LICHEN_HAL_RESET_CAUSE_DEBUG = BIT(5),
	LICHEN_HAL_RESET_CAUSE_SECURITY = BIT(6),
	LICHEN_HAL_RESET_CAUSE_LOW_POWER_WAKE = BIT(7),
	LICHEN_HAL_RESET_CAUSE_CPU_LOCKUP = BIT(8),
	LICHEN_HAL_RESET_CAUSE_PARITY = BIT(9),
	LICHEN_HAL_RESET_CAUSE_PLL = BIT(10),
	LICHEN_HAL_RESET_CAUSE_CLOCK = BIT(11),
	LICHEN_HAL_RESET_CAUSE_HARDWARE = BIT(12),
	LICHEN_HAL_RESET_CAUSE_USER = BIT(13),
	LICHEN_HAL_RESET_CAUSE_TEMPERATURE = BIT(14),
};

struct lichen_hal_reset_diagnostics_snapshot {
	bool reboot_supported;
	bool warm_reboot_best_effort;
	bool factory_reset_supported;
	bool reset_cause_supported;
	bool reset_cause_clear_supported;
	bool reset_cause_valid;
	uint32_t reset_cause;
	bool supported_reset_cause_valid;
	uint32_t supported_reset_cause;
	bool reset_cause_raw_valid;
	uint32_t reset_cause_raw;
	bool supported_reset_cause_raw_valid;
	uint32_t supported_reset_cause_raw;
	bool retained_diagnostics_supported;
	bool retained_crash_valid;
	uint32_t retained_crash_reason;
};

/*
 * Some Zephyr registration macros require a compile-time device expression
 * rather than a runtime getter. Keep those devicetree details behind HAL names
 * so applications do not open-code board aliases.
 */
#if DT_NODE_HAS_STATUS(DT_ALIAS(gnss0), okay)
#define LICHEN_HAL_GNSS_DEVICE DEVICE_DT_GET(DT_ALIAS(gnss0))
#endif

#define LICHEN_HAL_HAS_LORA_DEVICE DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay)

const struct lichen_hal_capabilities *_Nonnull lichen_hal_capabilities_get(void);
bool lichen_hal_has_capability(enum lichen_hal_capability capability);
void lichen_hal_identity_get(struct lichen_hal_identity *_Nonnull identity);
bool lichen_hal_synthetic_device_identity_allowed(void);
int lichen_hal_synthetic_device_identity_get(uint8_t *_Nonnull id, size_t id_len);

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

int lichen_hal_lora_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_gnss_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_display_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_serial_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_battery_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_pmic_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_external_flash_device_get(const struct device *_Nullable *_Nonnull dev);
int lichen_hal_led_get(struct gpio_dt_spec *_Nonnull spec);
int lichen_hal_button_get(struct gpio_dt_spec *_Nonnull spec);
int lichen_hal_power_snapshot_get(struct lichen_hal_power_snapshot *_Nonnull snapshot);
/*
 * Submit a location sample from any firmware source. The provider keeps one
 * sample per source class and selects the highest-priority fresh usable fix at
 * snapshot time. Priority is manual/static, local client, network, external
 * hardware, then onboard hardware. A fresh 2D/3D fix wins over no-fix/error
 * metadata; stale high-priority fixes fall back to lower-priority fresh fixes.
 *
 * source_name is copied and may be truncated to fit snapshot storage.
 * LICHEN_HAL_LOCATION_FIX_STALE is a derived snapshot state; submitters should
 * provide NONE, NO_FIX, 2D, 3D, or ERROR.
 */
int lichen_hal_location_submit(const struct lichen_hal_location_sample *_Nonnull sample);
int lichen_hal_location_clear_source(
	enum lichen_hal_location_source_class source_class);
void lichen_hal_location_clear(void);
int lichen_hal_location_time_snapshot_get(
	struct lichen_hal_location_time_snapshot *_Nonnull snapshot);
int lichen_hal_time_submit(const struct lichen_hal_time_sample *_Nonnull sample);
void lichen_hal_time_clear(void);
int lichen_hal_time_snapshot_get(struct lichen_hal_time_snapshot *_Nonnull snapshot);
int lichen_hal_time_provision_epoch_set(uint32_t provision_epoch,
					bool authenticated);
void lichen_hal_time_provision_epoch_clear(void);
int lichen_hal_reset_diagnostics_snapshot_get(
	struct lichen_hal_reset_diagnostics_snapshot *_Nonnull snapshot);
int lichen_hal_reset_diagnostics_clear(void);
int lichen_hal_reboot_status(void);
int lichen_hal_reset_request(enum lichen_hal_reset_request request);

enum lichen_duty_cycle_limit { LICHEN_DUTY_CYCLE_DEFAULT_PERMILLE = 10, };
struct lichen_duty_cycle_tracker { uint64_t records[32]; uint32_t durations[32]; uint8_t head; uint8_t len; uint16_t duty_permille; };
void lichen_duty_cycle_tracker_init(struct lichen_duty_cycle_tracker *t, uint16_t permille);
bool lichen_duty_cycle_tracker_record_tx(struct lichen_duty_cycle_tracker *t, uint64_t ts, uint32_t dur);
uint32_t lichen_duty_cycle_tracker_remaining_ms(struct lichen_duty_cycle_tracker *t, uint64_t now);
uint16_t lichen_duty_cycle_tracker_usage_permille(struct lichen_duty_cycle_tracker *t, uint64_t now);
uint64_t lichen_duty_cycle_tracker_next_tx_available_ms(struct lichen_duty_cycle_tracker *t, uint64_t now, uint32_t dur);
bool lichen_duty_cycle_tracker_can_transmit(struct lichen_duty_cycle_tracker *t, uint64_t now, uint32_t dur);

#ifdef CONFIG_ZTEST
void lichen_hal_location_test_set_uptime_ms(int64_t uptime_ms);
void lichen_hal_location_test_use_real_uptime(void);
int64_t lichen_hal_location_test_now_ms(void);
void lichen_hal_location_time_test_set_snapshot(
	const struct lichen_hal_location_time_snapshot *_Nonnull snapshot);
bool lichen_hal_power_test_percent_valid(uint8_t percent);
bool lichen_hal_power_test_charger_status_known(int status);
bool lichen_hal_power_test_charger_status_is_charging(int status);
bool lichen_hal_power_test_charger_online_external_power(int online);
bool lichen_hal_power_test_charger_online_known(int online);
bool lichen_hal_reset_test_last_request_valid(void);
enum lichen_hal_reset_request lichen_hal_reset_test_last_request(void);
void lichen_hal_reset_test_clear_request(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_HAL_H_ */
