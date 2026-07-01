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

#include <lichen/hal.h>
#if IS_ENABLED(CONFIG_LICHEN_L2)
#include "lora_l2.h"
#endif
#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/codec.h>

LOG_MODULE_REGISTER(gateway_meshtastic_adapter, LOG_LEVEL_INF);

#define ADAPTER_STACK_SIZE 2048
#define ADAPTER_PRIORITY 7
#define ADAPTER_IDLE_SLEEP K_MSEC(20)

static struct lichen_meshtastic_adapter s_adapter;
static uint8_t s_to_radio[LICHEN_MESHTASTIC_TO_RADIO_MAX];
static struct k_thread s_thread;
static K_THREAD_STACK_DEFINE(s_stack, ADAPTER_STACK_SIZE);
static bool s_started;
static uint32_t s_dispatch_epoch;
static char s_long_name[32];
static char s_pio_env[48];
static char s_firmware_version[48];
static uint8_t s_device_id[8];

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
	ARG_UNUSED(user_data);

	if (packet == NULL) {
		return -EINVAL;
	}
	if (!ble_meshtastic_session_epoch_current(s_dispatch_epoch)) {
		return -ESTALE;
	}

	/*
	 * Full ingress into the LICHEN local message contract belongs to
	 * project-LICHEN-t2hn.7. Until then, accept the packet at the app
	 * boundary and return local queueStatus without emitting RF packets.
	 */
	LOG_INF("Meshtastic TEXT_MESSAGE_APP ingress staged: id=%u len=%u",
		packet->has_id ? packet->id : 0U, (uint32_t)packet->payload_len);
	return 0;
}

static uint32_t queue_free(void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshtastic_from_radio_free();
}

static int get_local_info(struct lichen_meshtastic_local_info *info,
			  void *user_data)
{
	struct lichen_hal_identity identity;
	uint8_t eui64[8] = { 0 };
	int ret = -ENODEV;

	ARG_UNUSED(user_data);

	if (info == NULL) {
		return -EINVAL;
	}

	lichen_hal_identity_get(&identity);
	(void)snprintf(s_long_name, sizeof(s_long_name), "LICHEN %s",
		       identity.board_name != NULL ? identity.board_name :
							     CONFIG_BOARD);
	(void)snprintf(s_pio_env, sizeof(s_pio_env), "zephyr-%s",
		       identity.zephyr_board != NULL ? identity.zephyr_board :
							       CONFIG_BOARD);
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
	info->has_battery = false;
	info->has_gnss = lichen_hal_has_capability(LICHEN_HAL_CAP_GNSS);
	info->has_lora = lichen_hal_has_capability(LICHEN_HAL_CAP_LORA);
	info->has_tx_power_dbm = true;
	info->tx_power_dbm = 14;
	info->nodedb_count = 1U;

	return 0;
}

static void adapter_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		size_t to_radio_len = 0U;
		uint32_t session_epoch = 0U;
		int ret = ble_meshtastic_dequeue_to_radio(s_to_radio,
							  sizeof(s_to_radio),
							  &to_radio_len,
							  &session_epoch);

		if (ret == 0) {
			k_sleep(ADAPTER_IDLE_SLEEP);
			continue;
		}
		if (ret < 0) {
			LOG_WRN("Meshtastic ToRadio dequeue failed: %d", ret);
			k_sleep(ADAPTER_IDLE_SLEEP);
			continue;
		}

		s_dispatch_epoch = session_epoch;
		if (!ble_meshtastic_session_epoch_current(session_epoch)) {
			lichen_meshtastic_adapter_reset(&s_adapter);
			continue;
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
	}
}

int gateway_meshtastic_adapter_init(void)
{
	struct lichen_meshtastic_adapter_ops ops = {
		.enqueue_from_radio = enqueue_from_radio,
		.handle_text = handle_text,
		.queue_free = queue_free,
		.get_local_info = get_local_info,
		.queue_maxlen = ble_meshtastic_from_radio_capacity(),
		.heartbeat_queue_status = true,
	};

	if (s_started) {
		return 0;
	}

	lichen_meshtastic_adapter_init(&s_adapter, &ops);
	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack),
			adapter_thread, NULL, NULL, NULL,
			ADAPTER_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "meshapp");
	s_started = true;
	LOG_INF("Meshtastic app adapter ready");

	return 0;
}
