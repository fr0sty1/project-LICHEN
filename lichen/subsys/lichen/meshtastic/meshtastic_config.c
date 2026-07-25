/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "meshtastic_pb.h"

int write_user(uint8_t *buf, size_t buflen, size_t *pos,
	       const struct lichen_meshtastic_local_info *info)
{
	char id[10];
	uint32_t node_num = info_node_num(info);

	id[0] = '!';
	for (size_t i = 0U; i < 8U; i++) {
		uint8_t nibble = (uint8_t)((node_num >> ((7U - i) * 4U)) & 0x0fU);

		id[i + 1U] = (char)(nibble < 10U ? '0' + nibble :
				     'a' + (nibble - 10));
	}
	id[9] = '\0';

	if (pb_write_string_field(buf, buflen, pos, USER_ID_FIELD, id) < 0 ||
	    pb_write_string_field(buf, buflen, pos, USER_LONG_NAME_FIELD,
				  info_long_name(info)) < 0 ||
	    pb_write_string_field(buf, buflen, pos, USER_SHORT_NAME_FIELD,
				  info_short_name(info)) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, USER_HW_MODEL_FIELD,
				  MESHTASTIC_HW_MODEL_PRIVATE) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, USER_IS_LICENSED_FIELD, 0U) <
		    0 ||
	    pb_write_varint_field(buf, buflen, pos, USER_ROLE_FIELD,
				  MESHTASTIC_ROLE_CLIENT) < 0 ||
	    pb_write_len_field(buf, buflen, pos, USER_PUBLIC_KEY_FIELD, NULL,
			       0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, USER_IS_UNMESSAGABLE_FIELD,
				  0U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_lora_config(uint8_t *buf, size_t buflen, size_t *pos,
		      const struct lichen_meshtastic_local_info *info)
{
	int32_t tx_power = (info != NULL && info->has_tx_power_dbm) ?
				   info->tx_power_dbm :
				   MESHTASTIC_DEFAULT_TX_POWER_DBM;

	if (tx_power < 0) {
		tx_power = 0;
	}

	if (pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_USE_PRESET_FIELD,
				  1U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_MODEM_PRESET_FIELD,
				  MESHTASTIC_MODEM_LONG_FAST) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_REGION_FIELD,
				  MESHTASTIC_REGION_US) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_HOP_LIMIT_FIELD,
				  3U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_TX_ENABLED_FIELD,
				  (info == NULL || info->has_lora) ? 1U : 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_TX_POWER_FIELD,
				  (uint64_t)tx_power) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_CHANNEL_NUM_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_IGNORE_MQTT_FIELD,
				  1U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_device_config(uint8_t *buf, size_t buflen, size_t *pos,
			const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos, DEVICE_CONFIG_ROLE_FIELD,
				  MESHTASTIC_ROLE_CLIENT) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  DEVICE_CONFIG_NODE_INFO_BROADCAST_SECS_FIELD,
				  MESHTASTIC_NODE_INFO_BROADCAST_SECS) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_position_config(uint8_t *buf, size_t buflen, size_t *pos,
			  const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  POSITION_CONFIG_FIXED_POSITION_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  POSITION_CONFIG_GPS_UPDATE_INTERVAL_FIELD, 0U) <
		    0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  POSITION_CONFIG_POSITION_FLAGS_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  POSITION_CONFIG_GPS_MODE_FIELD,
				  POSITION_CONFIG_GPS_MODE_NOT_PRESENT) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_power_config(uint8_t *buf, size_t buflen, size_t *pos,
		       const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  POWER_CONFIG_POWER_SAVING_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  POWER_CONFIG_WAIT_BLUETOOTH_SECS_FIELD, 0U) <
		    0) {
		return -ENOMEM;
	}
	return 0;
}

int write_network_config(uint8_t *buf, size_t buflen, size_t *pos,
			 const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  NETWORK_CONFIG_WIFI_ENABLED_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  NETWORK_CONFIG_ETH_ENABLED_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  NETWORK_CONFIG_IPV6_ENABLED_FIELD, 0U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_display_config(uint8_t *buf, size_t buflen, size_t *pos,
			 const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  DISPLAY_CONFIG_SCREEN_ON_SECS_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  DISPLAY_CONFIG_UNITS_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  DISPLAY_CONFIG_DISPLAYMODE_FIELD, 0U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_bluetooth_config(uint8_t *buf, size_t buflen, size_t *pos,
			   const struct lichen_meshtastic_local_info *info)
{
	uint32_t enabled = (info != NULL && info->has_bluetooth) ? 1U : 0U;

	if (pb_write_varint_field(buf, buflen, pos,
				  BLUETOOTH_CONFIG_ENABLED_FIELD, enabled) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, BLUETOOTH_CONFIG_MODE_FIELD,
				  BLUETOOTH_CONFIG_PAIRING_MODE_NO_PIN) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_security_config(uint8_t *buf, size_t buflen, size_t *pos,
			  const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  SECURITY_CONFIG_SERIAL_ENABLED_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  SECURITY_CONFIG_DEBUG_LOG_API_ENABLED_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  SECURITY_CONFIG_ADMIN_CHANNEL_ENABLED_FIELD,
				  0U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

int write_device_ui_config(uint8_t *buf, size_t buflen, size_t *pos,
			   const struct lichen_meshtastic_local_info *info)
{
	(void)info;

	if (pb_write_varint_field(buf, buflen, pos,
				  DEVICE_UI_CONFIG_VERSION_FIELD, 0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  DEVICE_UI_CONFIG_SCREEN_BRIGHTNESS_FIELD, 1U) <
		    0 ||
	    pb_write_varint_field(buf, buflen, pos,
				  DEVICE_UI_CONFIG_SCREEN_TIMEOUT_FIELD, 0U) < 0) {
		return -ENOMEM;
	}
	return 0;
}
