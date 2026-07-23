/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_INTERFACE_H_
#define LICHEN_APP_INTERFACE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct lichen_app_text_event {
	uint32_t from;
	/*
	 * Legacy/app-surface destination. When has_to_iid is true, to_iid is
	 * the authoritative LICHEN destination and consumers MUST ignore to.
	 */
	uint32_t to;
	uint32_t id;
	uint8_t to_iid[8];
	const uint8_t *payload;
	size_t payload_len;
	bool has_id;
	bool has_to_iid;
};

struct lichen_app_status_event {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_id;
	bool has_error_reason;
};

struct lichen_app_interface_stats {
	uint32_t text_emit_count;
	uint32_t status_emit_count;
	uint32_t text_submit_count;
	uint32_t text_delivery_count;
	uint32_t status_delivery_count;
	uint32_t text_submit_delivery_count;
	uint32_t no_subscriber_count;
	uint32_t backpressure_count;
	uint32_t subscriber_error_count;
	uint32_t invalid_count;
};

struct lichen_app_power_snapshot {
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

enum lichen_app_fix_source {
	LICHEN_APP_FIX_SOURCE_NONE,
	LICHEN_APP_FIX_SOURCE_GNSS,
};

enum lichen_app_location_source_class {
	LICHEN_APP_LOCATION_SOURCE_NONE,
	LICHEN_APP_LOCATION_SOURCE_ONBOARD_HARDWARE,
	LICHEN_APP_LOCATION_SOURCE_EXTERNAL_HARDWARE,
	LICHEN_APP_LOCATION_SOURCE_NETWORK,
	LICHEN_APP_LOCATION_SOURCE_LOCAL_CLIENT,
	LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC,
};

enum lichen_app_location_fix_state {
	LICHEN_APP_LOCATION_FIX_NONE,
	LICHEN_APP_LOCATION_FIX_NO_FIX,
	LICHEN_APP_LOCATION_FIX_2D,
	LICHEN_APP_LOCATION_FIX_3D,
	LICHEN_APP_LOCATION_FIX_STALE,
	LICHEN_APP_LOCATION_FIX_ERROR,
};

enum lichen_app_time_source_class {
	LICHEN_APP_TIME_SOURCE_NONE,
	LICHEN_APP_TIME_SOURCE_MONOTONIC_INTERNAL,
	LICHEN_APP_TIME_SOURCE_INTERNAL_RTC,
	LICHEN_APP_TIME_SOURCE_GNSS,
	LICHEN_APP_TIME_SOURCE_NETWORK,
	LICHEN_APP_TIME_SOURCE_LOCAL_CLIENT,
	LICHEN_APP_TIME_SOURCE_MANUAL_STATIC,
};

enum lichen_app_time_rejection_reason {
	LICHEN_APP_TIME_REJECT_NONE,
	LICHEN_APP_TIME_REJECT_INVALID_SOURCE,
	LICHEN_APP_TIME_REJECT_MISSING_TIMESTAMP,
	LICHEN_APP_TIME_REJECT_BELOW_EPOCH_FLOOR,
	LICHEN_APP_TIME_REJECT_STALE,
	LICHEN_APP_TIME_REJECT_LOWER_TRUST,
	LICHEN_APP_TIME_REJECT_PROVISION_UNAUTHENTICATED,
	LICHEN_APP_TIME_REJECT_PROVISION_INVALID,
	LICHEN_APP_TIME_REJECT_PROVISION_FUTURE,
};

struct lichen_app_location_time_snapshot {
	bool location_provider_available;
	bool time_provider_available;
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool fix_time_unix_valid;
	int64_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
	bool fix_source_valid;
	enum lichen_app_fix_source fix_source;
	bool source_class_valid;
	enum lichen_app_location_source_class source_class;
	char source_name[24];
	bool fix_state_valid;
	enum lichen_app_location_fix_state fix_state;
	bool age_seconds_valid;
	uint32_t age_seconds;
	bool horizontal_accuracy_mm_valid;
	uint32_t horizontal_accuracy_mm;
	bool vertical_accuracy_mm_valid;
	uint32_t vertical_accuracy_mm;
};

struct lichen_app_time_snapshot {
	bool provider_available;
	bool wall_clock_valid;
	bool source_class_valid;
	enum lichen_app_time_source_class source_class;
	char source_name[24];
	bool unix_time_valid;
	int64_t unix_time;
	bool age_seconds_valid;
	uint32_t age_seconds;
	bool accuracy_ms_valid;
	uint32_t accuracy_ms;
	bool quality_valid;
	uint8_t quality;
	bool passed_epoch_floor;
	enum lichen_app_time_rejection_reason last_rejection;
	bool rejection_source_class_valid;
	enum lichen_app_time_source_class rejection_source_class;
	char rejection_source_name[24];
	bool rejection_passed_epoch_floor;
	uint32_t effective_epoch_floor;
	uint32_t build_epoch;
	bool provision_epoch_valid;
	uint32_t provision_epoch;
};

struct lichen_app_status_snapshot {
	uint16_t rank;
	uint32_t uptime_seconds;
	char role[24];
	bool rpl_capable;
	struct lichen_app_power_snapshot power;
	struct lichen_app_location_time_snapshot location_time;
	struct lichen_app_time_snapshot time;
};

struct lichen_app_config_snapshot {
	int8_t tx_power_dbm;
	bool has_tx_power_dbm;
};

typedef int (*lichen_app_interface_text_fn)(
	const struct lichen_app_text_event *_Nonnull event, void *_Nullable user_data);
typedef int (*lichen_app_interface_status_fn)(
	const struct lichen_app_status_event *_Nonnull event, void *_Nullable user_data);
typedef int (*lichen_app_interface_get_status_fn)(
	struct lichen_app_status_snapshot *_Nonnull status, void *_Nullable user_data);
typedef int (*lichen_app_interface_get_config_fn)(
	struct lichen_app_config_snapshot *_Nonnull config, void *_Nullable user_data);
typedef int (*lichen_app_interface_set_config_fn)(
	const struct lichen_app_config_snapshot *_Nonnull config, void *_Nullable user_data);

struct lichen_app_interface_sink {
	lichen_app_interface_text_fn emit_text;
	lichen_app_interface_status_fn emit_status;
	lichen_app_interface_text_fn submit_text;
	lichen_app_interface_get_status_fn get_status;
	lichen_app_interface_get_config_fn get_config;
	lichen_app_interface_set_config_fn set_config;
	void *user_data;
};

/*
 * Unregistering removes the sink from future snapshots but does not quiesce
 * callbacks that already captured a snapshot. Keep callback code and user_data
 * storage valid until the caller has externally excluded concurrent emits.
 */
int lichen_app_interface_register_sink(
	const struct lichen_app_interface_sink *_Nonnull sink, uint8_t *_Nonnull out_id);
int lichen_app_interface_unregister_sink(uint8_t sink_id);

int lichen_app_interface_emit_text(
	const struct lichen_app_text_event *_Nonnull event);
int lichen_app_interface_submit_text(
	const struct lichen_app_text_event *_Nonnull event);
int lichen_app_interface_emit_status(
	const struct lichen_app_status_event *_Nonnull event);

int lichen_app_interface_get_status(
	struct lichen_app_status_snapshot *_Nonnull status);
int lichen_app_interface_get_config(
	struct lichen_app_config_snapshot *_Nonnull config);
int lichen_app_interface_set_config(
	const struct lichen_app_config_snapshot *_Nonnull config);
/*
 * Submit app/local-client location metadata into the firmware-wide location
 * provider. Omitted source_class defaults to LOCAL_CLIENT.
 */
int lichen_app_interface_submit_location(
	const struct lichen_app_location_time_snapshot *_Nonnull location);
int lichen_app_interface_submit_network_location(
	const struct lichen_app_location_time_snapshot *_Nonnull location);
int lichen_app_interface_clear_network_location(void);
int lichen_app_interface_submit_manual_location(
	const struct lichen_app_location_time_snapshot *_Nonnull location);
int lichen_app_interface_submit_time(
	const struct lichen_app_time_snapshot *_Nonnull time);
int lichen_app_interface_submit_network_time(
	const struct lichen_app_time_snapshot *_Nonnull time);
int lichen_app_interface_submit_manual_time(
	const struct lichen_app_time_snapshot *_Nonnull time);

int lichen_app_interface_copy_stats(
	struct lichen_app_interface_stats *_Nonnull stats);

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
void lichen_app_interface_test_reset(void);
void lichen_app_interface_test_fail_next_location_submit(int ret);
void lichen_app_interface_test_fail_next_clear_network(int ret);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_INTERFACE_H_ */
