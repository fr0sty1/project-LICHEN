/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "meshtastic_adapter.h"

#include "ble_meshtastic.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/kernel_version.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
#include <lichen/app_identity/app_identity.h>
#endif
#include <lichen/hal.h>
#include <lichen/app_interface/app_interface.h>
#if IS_ENABLED(CONFIG_LICHEN_L2)
#include "lora_l2.h"
#endif
#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/codec.h>

LOG_MODULE_REGISTER(gateway_meshtastic_adapter, LOG_LEVEL_INF);

BUILD_ASSERT(CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD ==
	     LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX,
	     "CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD must match "
	     "LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX");

#define ADAPTER_STACK_SIZE 4096
#define ADAPTER_PRIORITY 7
#define ADAPTER_IDLE_SLEEP K_MSEC(20)
#define MESHTASTIC_LOC_SOURCE_MANUAL 1U
#define MESHTASTIC_LOC_SOURCE_INTERNAL 2U
#define MESHTASTIC_LOC_SOURCE_EXTERNAL 3U
#define MESHTASTIC_ALT_SOURCE_BAROMETRIC 4U

static struct lichen_meshtastic_adapter s_adapter;
static uint8_t s_to_radio[LICHEN_MESHTASTIC_TO_RADIO_MAX];
#ifndef CONFIG_ZTEST
static struct k_thread s_thread;
static K_THREAD_STACK_DEFINE(s_stack, ADAPTER_STACK_SIZE);
#endif
static K_MUTEX_DEFINE(s_init_mutex);
static K_MUTEX_DEFINE(s_adapter_mutex);
static bool s_started;
static uint32_t s_dispatch_epoch;
static char s_long_name[32];
static char s_pio_env[48];
static char s_firmware_version[48];
static uint8_t s_device_id[8];
#ifdef CONFIG_ZTEST
static struct lichen_hal_power_snapshot s_test_power_snapshot;
static bool s_has_test_power_snapshot;
static struct lichen_hal_location_time_snapshot s_test_location_time_snapshot;
static bool s_has_test_location_time_snapshot;
static struct lichen_hal_time_snapshot s_test_time_snapshot;
static bool s_has_test_time_snapshot;
#endif

static int enqueue_from_radio(const uint8_t *from_radio, size_t len,
			      void *user_data);
static int handle_text(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data);
static int handle_location(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data);
static uint32_t queue_free(void *user_data);
static int get_local_info(struct lichen_meshtastic_local_info *info,
			  void *user_data);
static size_t get_peers(struct lichen_meshtastic_peer_snapshot *peers,
			size_t peer_cap, void *user_data);
static int process_once_internal(void);
static const char *position_source_name(
	const struct lichen_meshtastic_position_snapshot *position);
#ifndef CONFIG_ZTEST
static void adapter_thread(void *a, void *b, void *c);
#endif

static struct lichen_meshtastic_adapter_ops adapter_ops(void)
{
	return (struct lichen_meshtastic_adapter_ops){
		.enqueue_from_radio = enqueue_from_radio,
		.handle_text = handle_text,
		.handle_location = handle_location,
		.queue_free = queue_free,
		.get_local_info = get_local_info,
		.get_peers = get_peers,
		.queue_maxlen = ble_meshtastic_from_radio_capacity(),
		.heartbeat_queue_status = true,
	};
}

static int enqueue_from_radio(const uint8_t *from_radio, size_t len, void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshtastic_enqueue_from_radio_if_session(s_dispatch_epoch,
							   from_radio, len);
}

static int handle_text(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct lichen_app_text_event event;

	ARG_UNUSED(user_data);

	if (packet == NULL) {
		return -EINVAL;
	}
	if (!ble_meshtastic_session_epoch_current(s_dispatch_epoch)) {
		return -ESTALE;
	}

	event = (struct lichen_app_text_event){
		.from = packet->has_from ? packet->from : 0U,
		.to = packet->has_to_peer ? UINT32_MAX :
		      packet->has_to ? packet->to : UINT32_MAX,
		.id = packet->has_id ? packet->id : 0U,
		.payload = packet->payload,
		.payload_len = packet->payload_len,
		.has_id = packet->has_id,
		.has_to_iid = packet->has_to_peer,
	};
	if (packet->has_to_peer) {
		memcpy(event.to_iid, packet->to_iid, sizeof(event.to_iid));
	}

	return lichen_app_interface_submit_text(&event);
}

static int handle_location(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data)
{
	struct lichen_app_location_time_snapshot location;
	const char *source_name;

	ARG_UNUSED(user_data);

	if (packet == NULL) {
		return -EINVAL;
	}
	if (!ble_meshtastic_session_epoch_current(s_dispatch_epoch)) {
		return -ESTALE;
	}

	location = (struct lichen_app_location_time_snapshot){
		.latitude_e7_valid = packet->position.latitude_e7_valid,
		.latitude_e7 = packet->position.latitude_e7,
		.longitude_e7_valid = packet->position.longitude_e7_valid,
		.longitude_e7 = packet->position.longitude_e7,
		.altitude_m_valid = packet->position.altitude_m_valid,
		.altitude_m = packet->position.altitude_m,
		.fix_time_unix_valid = packet->position.fix_time_unix_valid,
		.fix_time_unix = packet->position.fix_time_unix,
		.satellites_valid = packet->position.satellites_valid,
		.satellites = packet->position.satellites,
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_LOCAL_CLIENT,
		.age_seconds_valid = false,
		.fix_state_valid = true,
		.fix_state = packet->position.altitude_m_valid ?
			     LICHEN_APP_LOCATION_FIX_3D :
			     LICHEN_APP_LOCATION_FIX_2D,
	};
	source_name = position_source_name(&packet->position);
	strncpy(location.source_name, source_name,
		sizeof(location.source_name) - 1U);
	location.source_name[sizeof(location.source_name) - 1U] = '\0';

	return lichen_app_interface_submit_location(&location);
}

static uint32_t queue_free(void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshtastic_from_radio_free();
}

static void read_power_snapshot(struct lichen_hal_power_snapshot *power)
{
#ifdef CONFIG_ZTEST
	if (s_has_test_power_snapshot) {
		*power = s_test_power_snapshot;
		return;
	}
#endif
	(void)lichen_hal_power_snapshot_get(power);
}

static void read_location_time_snapshot(
	struct lichen_hal_location_time_snapshot *location_time)
{
#ifdef CONFIG_ZTEST
	if (s_has_test_location_time_snapshot) {
		*location_time = s_test_location_time_snapshot;
		return;
	}
#endif
	(void)lichen_hal_location_time_snapshot_get(location_time);
}

static void read_time_snapshot(struct lichen_hal_time_snapshot *time)
{
#ifdef CONFIG_ZTEST
	if (s_has_test_time_snapshot) {
		*time = s_test_time_snapshot;
		return;
	}
#endif
	(void)lichen_hal_time_snapshot_get(time);
}

static int get_local_info(struct lichen_meshtastic_local_info *info,
			  void *user_data)
{
	struct lichen_hal_identity identity;
	struct lichen_hal_power_snapshot power;
	struct lichen_hal_location_time_snapshot location_time;
	struct lichen_hal_time_snapshot time;
	uint8_t eui64[8] = { 0 };
	int ret = -ENODEV;

	ARG_UNUSED(user_data);

	if (info == NULL) {
		return -EINVAL;
	}

	lichen_hal_identity_get(&identity);
	(void)snprintf(s_long_name, sizeof(s_long_name), "LICHEN %s", identity.board_name);
	(void)snprintf(s_pio_env, sizeof(s_pio_env), "zephyr-%s", identity.zephyr_board);
	(void)snprintf(s_firmware_version, sizeof(s_firmware_version),
		       "LICHEN compat 0.0.0+zephyr.%u.%u.%u",
		       SYS_KERNEL_VER_MAJOR(sys_kernel_version_get()),
		       SYS_KERNEL_VER_MINOR(sys_kernel_version_get()),
		       SYS_KERNEL_VER_PATCHLEVEL(sys_kernel_version_get()));

#if IS_ENABLED(CONFIG_LICHEN_L2)
	ret = lichen_lora_l2_copy_eui64(eui64);
#endif
	if (ret == 0) {
		memcpy(s_device_id, eui64, sizeof(s_device_id));
		info->device_id = s_device_id;
		info->device_id_len = sizeof(s_device_id);
		info->node_num = ((uint32_t)eui64[4] << 24) |
				 ((uint32_t)eui64[5] << 16) |
				 ((uint32_t)eui64[6] << 8) |
				 (uint32_t)eui64[7];
	}

	info->long_name = s_long_name;
	info->short_name = "LICH";
	info->firmware_version = s_firmware_version;
	info->pio_env = s_pio_env;
	info->uptime_seconds = (uint32_t)(k_uptime_get() / 1000);
	info->has_bluetooth = true;
	read_power_snapshot(&power);
	info->has_battery = power.battery_provider_available;
	info->has_battery_percent = power.battery_percent_valid;
	info->battery_percent = power.battery_percent;
	info->has_battery_voltage_mv = power.battery_voltage_mv_valid;
	info->battery_voltage_mv = power.battery_voltage_mv;
	info->has_charging = power.charging_valid;
	info->charging = power.charging;
	info->has_external_power = power.external_power_valid;
	info->external_power = power.external_power;
	read_location_time_snapshot(&location_time);
	read_time_snapshot(&time);
	info->has_gnss = lichen_hal_has_capability(LICHEN_HAL_CAP_GNSS);
	info->has_latitude_e7 = location_time.latitude_e7_valid;
	info->latitude_e7 = location_time.latitude_e7;
	info->has_longitude_e7 = location_time.longitude_e7_valid;
	info->longitude_e7 = location_time.longitude_e7;
	info->has_altitude_m = location_time.altitude_m_valid;
	info->altitude_m = location_time.altitude_m;
	info->has_fix_time_unix = location_time.fix_time_unix_valid;
	info->fix_time_unix = location_time.fix_time_unix;
	if (!info->has_fix_time_unix && time.wall_clock_valid &&
	    time.unix_time_valid) {
		info->has_fix_time_unix = true;
		info->fix_time_unix = time.unix_time;
	}
	info->has_satellites = location_time.satellites_valid;
	info->satellites = location_time.satellites;
	info->has_gnss_fix = location_time.fix_source_valid &&
			     location_time.fix_source == LICHEN_HAL_FIX_SOURCE_GNSS;
	info->has_lora = lichen_hal_has_capability(LICHEN_HAL_CAP_LORA);
	info->has_tx_power_dbm = true;
	info->tx_power_dbm = 14;
	info->nodedb_count = 1U;

	return 0;
}

static size_t get_peers(struct lichen_meshtastic_peer_snapshot *peers,
			size_t peer_cap, void *user_data)
{
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	struct lichen_app_identity_peer
		identities[CONFIG_LICHEN_MESHTASTIC_NODEDB_MAX_PEERS];
	size_t count;
	size_t out_len;

	ARG_UNUSED(user_data);
	if (peers == NULL || peer_cap == 0U) {
		return 0U;
	}

	out_len = MIN(peer_cap, ARRAY_SIZE(identities));
	count = lichen_app_identity_copy_peers(identities, out_len);
	count = MIN(count, out_len);
	for (size_t i = 0U; i < count; i++) {
		memset(&peers[i], 0, sizeof(peers[i]));
		memcpy(peers[i].eui64, identities[i].eui64,
		       sizeof(peers[i].eui64));
		if (identities[i].display_name[0] != '\0') {
			memcpy(peers[i].long_name, identities[i].display_name,
			       sizeof(peers[i].long_name));
			peers[i].has_long_name = true;
		}
		peers[i].last_heard_seconds_ago =
			identities[i].last_heard_seconds_ago;
		peers[i].rssi_dbm = identities[i].rssi_dbm;
		peers[i].snr_db = identities[i].snr_db;
		peers[i].hop_distance = identities[i].hop_distance;
		peers[i].has_last_heard_seconds_ago =
			identities[i].has_last_heard_seconds_ago;
		peers[i].has_rssi_dbm = identities[i].has_rssi_dbm;
		peers[i].has_snr_db = identities[i].has_snr_db;
		peers[i].has_hop_distance = identities[i].has_hop_distance;
	}
	return count;
#else
	ARG_UNUSED(peers);
	ARG_UNUSED(peer_cap);
	ARG_UNUSED(user_data);
	return 0U;
#endif
}

static const char *position_source_name(
	const struct lichen_meshtastic_position_snapshot *position)
{
	if (position == NULL || !position->location_source_valid) {
		return "meshtastic-position";
	}

	switch (position->location_source) {
	case MESHTASTIC_LOC_SOURCE_MANUAL:
		return "mt-pos-manual";
	case MESHTASTIC_LOC_SOURCE_INTERNAL:
		return "mt-pos-internal";
	case MESHTASTIC_LOC_SOURCE_EXTERNAL:
		return "mt-pos-external";
	default:
		if (position->altitude_source_valid &&
		    position->altitude_source == MESHTASTIC_ALT_SOURCE_BAROMETRIC) {
			return "mt-pos-baro-alt";
		}
		return "mt-position";
	}
}

int gateway_meshtastic_adapter_init(void)
{
	struct lichen_meshtastic_adapter_ops ops = adapter_ops();

	k_mutex_lock(&s_init_mutex, K_FOREVER);
	if (s_started) {
		k_mutex_unlock(&s_init_mutex);
		return 0;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	lichen_meshtastic_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);
#ifndef CONFIG_ZTEST
	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack),
			adapter_thread, NULL, NULL, NULL,
			ADAPTER_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "meshapp");
#endif
	s_started = true;
	k_mutex_unlock(&s_init_mutex);
	LOG_INF("Meshtastic app adapter ready");

	return 0;
}

#ifndef CONFIG_ZTEST
static void adapter_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		int ret = process_once_internal();

		if (ret <= 0) {
			k_sleep(ADAPTER_IDLE_SLEEP);
		}
	}
}
#endif

int gateway_meshtastic_adapter_emit_text(
	const struct lichen_meshtastic_incoming_text *event)
{
	int ret;

	if (event == NULL) {
		return -EINVAL;
	}
	ret = gateway_meshtastic_adapter_init();
	if (ret < 0) {
		return ret;
	}
	if (!ble_meshtastic_session_active()) {
		return -ENOTCONN;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = ble_meshtastic_session_epoch();
	ret = lichen_meshtastic_adapter_emit_text(&s_adapter, event);
	k_mutex_unlock(&s_adapter_mutex);

	return ret;
}

#ifdef CONFIG_ZTEST
void gateway_meshtastic_adapter_test_reset(void)
{
	struct lichen_meshtastic_adapter_ops ops = adapter_ops();

	s_has_test_power_snapshot = false;
	memset(&s_test_power_snapshot, 0, sizeof(s_test_power_snapshot));
	s_has_test_location_time_snapshot = false;
	memset(&s_test_location_time_snapshot, 0,
	       sizeof(s_test_location_time_snapshot));
	s_has_test_time_snapshot = false;
	memset(&s_test_time_snapshot, 0, sizeof(s_test_time_snapshot));
	(void)gateway_meshtastic_adapter_init();
	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = ble_meshtastic_session_epoch();
	lichen_meshtastic_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);
}

void gateway_meshtastic_adapter_test_set_power_snapshot(
	const struct lichen_hal_power_snapshot *snapshot)
{
	if (snapshot == NULL) {
		s_has_test_power_snapshot = false;
		memset(&s_test_power_snapshot, 0, sizeof(s_test_power_snapshot));
		return;
	}

	s_test_power_snapshot = *snapshot;
	s_has_test_power_snapshot = true;
}

void gateway_meshtastic_adapter_test_set_location_time_snapshot(
	const struct lichen_hal_location_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		s_has_test_location_time_snapshot = false;
		memset(&s_test_location_time_snapshot, 0,
		       sizeof(s_test_location_time_snapshot));
		return;
	}

	s_test_location_time_snapshot = *snapshot;
	s_has_test_location_time_snapshot = true;
}

void gateway_meshtastic_adapter_test_set_time_snapshot(
	const struct lichen_hal_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		s_has_test_time_snapshot = false;
		memset(&s_test_time_snapshot, 0, sizeof(s_test_time_snapshot));
		return;
	}

	s_test_time_snapshot = *snapshot;
	s_has_test_time_snapshot = true;
}

int gateway_meshtastic_adapter_test_process_once(void)
{
	return process_once_internal();
}
#endif

static int process_once_internal(void)
{
	size_t to_radio_len = 0U;
	uint32_t session_epoch = 0U;
	int ret = ble_meshtastic_dequeue_to_radio(s_to_radio, sizeof(s_to_radio),
						  &to_radio_len, &session_epoch);

	if (ret <= 0) {
		if (ret < 0) {
			LOG_WRN("Meshtastic ToRadio dequeue failed: %d", ret);
		}
		return ret;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = session_epoch;
	if (!ble_meshtastic_session_epoch_current(session_epoch)) {
		lichen_meshtastic_adapter_reset(&s_adapter);
		k_mutex_unlock(&s_adapter_mutex);
		return -ESTALE;
	}
	ret = lichen_meshtastic_adapter_process_raw(&s_adapter, s_to_radio,
						    to_radio_len);
	if (ret < 0) {
		LOG_WRN("Meshtastic ToRadio dispatch failed: %d", ret);
	}

	if (lichen_meshtastic_adapter_disconnected(&s_adapter)) {
		(void)ble_meshtastic_reset_session_if_epoch(session_epoch);
		lichen_meshtastic_adapter_reset(&s_adapter);
	}
	k_mutex_unlock(&s_adapter_mutex);

	return ret < 0 ? ret : 1;
}

int gateway_meshtastic_adapter_emit_status(
	const struct lichen_meshtastic_incoming_status *event)
{
	int ret;

	if (event == NULL) {
		return -EINVAL;
	}
	ret = gateway_meshtastic_adapter_init();
	if (ret < 0) {
		return ret;
	}
	if (!ble_meshtastic_session_active()) {
		return -ENOTCONN;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = ble_meshtastic_session_epoch();
	ret = lichen_meshtastic_adapter_emit_status(&s_adapter, event);
	k_mutex_unlock(&s_adapter_mutex);

	return ret;
}
