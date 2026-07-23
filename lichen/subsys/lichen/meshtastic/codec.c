/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include <lichen/meshtastic/codec.h>

BUILD_ASSERT(LICHEN_MESHTASTIC_FROM_RADIO_MAX <= INT_MAX,
	     "max must fit in int");

BUILD_ASSERT(sizeof(float) == sizeof(uint32_t),
	     "float must be 32-bit (IEEE 754 binary32 assumed for float32_bits)");

/* Protobuf wire types per https://protobuf.dev/programming-guides/encoding/ */
#define PB_WT_VARINT 0U
#define PB_WT_64BIT 1U
#define PB_WT_LEN 2U
#define PB_WT_SGROUP 3U  /* Deprecated: proto2 start group marker */
#define PB_WT_EGROUP 4U  /* Deprecated: proto2 end group marker */
#define PB_WT_32BIT 5U
/* Wire types 6 and 7 are reserved/undefined per protobuf spec */

#define PB_MAX_FIELD_NUMBER 536870911ULL
#define LICHEN_BRAND "LICHEN"
#define MESHTASTIC_BRAND "meshtastic"

#define TORADIO_PACKET_FIELD 1U
#define TORADIO_WANT_CONFIG_ID_FIELD 3U
#define TORADIO_DISCONNECT_FIELD 4U
#define TORADIO_HEARTBEAT_FIELD 7U

#define FROMRADIO_ID_FIELD 1U
#define FROMRADIO_PACKET_FIELD 2U
#define FROMRADIO_MY_INFO_FIELD 3U
#define FROMRADIO_NODE_INFO_FIELD 4U
#define FROMRADIO_CONFIG_FIELD 5U
#define FROMRADIO_CONFIG_COMPLETE_ID_FIELD 7U
#define FROMRADIO_MODULE_CONFIG_FIELD 9U
#define FROMRADIO_CHANNEL_FIELD 10U
#define FROMRADIO_QUEUE_STATUS_FIELD 11U
#define FROMRADIO_METADATA_FIELD 13U
#define FROMRADIO_CLIENT_NOTIFICATION_FIELD 16U
#define FROMRADIO_REGION_PRESETS_FIELD 19U

#define QUEUE_STATUS_RES_FIELD 1U
#define QUEUE_STATUS_FREE_FIELD 2U
#define QUEUE_STATUS_MAXLEN_FIELD 3U
#define QUEUE_STATUS_MESH_PACKET_ID_FIELD 4U

#define MESH_PACKET_FROM_FIELD 1U
#define MESH_PACKET_TO_FIELD 2U
#define MESH_PACKET_CHANNEL_FIELD 3U
#define MESH_PACKET_DECODED_FIELD 4U
#define MESH_PACKET_ID_FIELD 6U
#define MESH_PACKET_WANT_ACK_FIELD 10U

#define DATA_PORTNUM_FIELD 1U
#define DATA_PAYLOAD_FIELD 2U
#define DATA_REQUEST_ID_FIELD 6U
#define MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP 1U
#define MESHTASTIC_PORTNUM_ROUTING_APP 5U

#define ROUTING_ERROR_REASON_FIELD 3U

#define MESHTASTIC_HW_MODEL_PRIVATE 255U
#define MESHTASTIC_ROLE_CLIENT 0U
#define MESHTASTIC_CHANNEL_PRIMARY 1U
#define MESHTASTIC_REGION_US 1U
#define MESHTASTIC_MODEM_LONG_FAST 0U
#define MESHTASTIC_DEFAULT_TX_POWER_DBM 14
#define MESHTASTIC_NODE_INFO_BROADCAST_SECS 900U

#define MY_INFO_NODE_NUM_FIELD 1U
#define MY_INFO_REBOOT_COUNT_FIELD 8U
#define MY_INFO_MIN_APP_VERSION_FIELD 11U
#define MY_INFO_DEVICE_ID_FIELD 12U
#define MY_INFO_PIO_ENV_FIELD 13U
#define MY_INFO_FIRMWARE_EDITION_FIELD 14U
#define MY_INFO_NODEDB_COUNT_FIELD 15U

#define USER_ID_FIELD 1U
#define USER_LONG_NAME_FIELD 2U
#define USER_SHORT_NAME_FIELD 3U
#define USER_HW_MODEL_FIELD 5U
#define USER_IS_LICENSED_FIELD 6U
#define USER_ROLE_FIELD 7U
#define USER_PUBLIC_KEY_FIELD 8U
#define USER_IS_UNMESSAGABLE_FIELD 9U

#define NODE_INFO_NUM_FIELD 1U
#define NODE_INFO_USER_FIELD 2U
#define NODE_INFO_POSITION_FIELD 3U
#define NODE_INFO_DEVICE_METRICS_FIELD 6U
#define NODE_INFO_CHANNEL_FIELD 7U
#define NODE_INFO_HOPS_AWAY_FIELD 9U

#define POSITION_LATITUDE_I_FIELD 1U
#define POSITION_LONGITUDE_I_FIELD 2U
#define POSITION_ALTITUDE_FIELD 3U
#define POSITION_TIME_FIELD 4U
#define POSITION_LOCATION_SOURCE_FIELD 5U
#define POSITION_ALTITUDE_SOURCE_FIELD 6U
#define POSITION_TIMESTAMP_FIELD 7U
#define POSITION_SATS_IN_VIEW_FIELD 19U
#define POSITION_LOC_SOURCE_INTERNAL 2U
#define POSITION_ALT_SOURCE_INTERNAL 2U

#define DEVICE_METRICS_BATTERY_LEVEL_FIELD 1U
#define DEVICE_METRICS_VOLTAGE_FIELD 2U
#define DEVICE_METRICS_UPTIME_SECONDS_FIELD 5U

#define METADATA_FIRMWARE_VERSION_FIELD 1U
#define METADATA_DEVICE_STATE_VERSION_FIELD 2U
#define METADATA_CAN_SHUTDOWN_FIELD 3U
#define METADATA_HAS_WIFI_FIELD 4U
#define METADATA_HAS_BLUETOOTH_FIELD 5U
#define METADATA_HAS_ETHERNET_FIELD 6U
#define METADATA_ROLE_FIELD 7U
#define METADATA_POSITION_FLAGS_FIELD 8U
#define METADATA_HW_MODEL_FIELD 9U
#define METADATA_HAS_REMOTE_HARDWARE_FIELD 10U
#define METADATA_HAS_PKC_FIELD 11U
#define METADATA_EXCLUDED_MODULES_FIELD 12U

#define EXCLUDED_MQTT_CONFIG (1U << 0)
#define EXCLUDED_SERIAL_CONFIG (1U << 1)
#define EXCLUDED_EXTNOTIF_CONFIG (1U << 2)
#define EXCLUDED_STOREFORWARD_CONFIG (1U << 3)
#define EXCLUDED_RANGETEST_CONFIG (1U << 4)
#define EXCLUDED_TELEMETRY_CONFIG (1U << 5)
#define EXCLUDED_CANNEDMSG_CONFIG (1U << 6)
#define EXCLUDED_AUDIO_CONFIG (1U << 7)
#define EXCLUDED_REMOTEHARDWARE_CONFIG (1U << 8)
#define EXCLUDED_NEIGHBORINFO_CONFIG (1U << 9)
#define EXCLUDED_AMBIENTLIGHTING_CONFIG (1U << 10)
#define EXCLUDED_DETECTIONSENSOR_CONFIG (1U << 11)
#define EXCLUDED_PAXCOUNTER_CONFIG (1U << 12)
#define EXCLUDED_BLUETOOTH_CONFIG (1U << 13)
#define EXCLUDED_NETWORK_CONFIG (1U << 14)

#define EXCLUDED_MODULES_MVP \
	(EXCLUDED_MQTT_CONFIG | EXCLUDED_SERIAL_CONFIG | \
	 EXCLUDED_EXTNOTIF_CONFIG | EXCLUDED_STOREFORWARD_CONFIG | \
	 EXCLUDED_RANGETEST_CONFIG | EXCLUDED_TELEMETRY_CONFIG | \
	 EXCLUDED_CANNEDMSG_CONFIG | EXCLUDED_AUDIO_CONFIG | \
	 EXCLUDED_REMOTEHARDWARE_CONFIG | EXCLUDED_NEIGHBORINFO_CONFIG | \
	 EXCLUDED_AMBIENTLIGHTING_CONFIG | EXCLUDED_DETECTIONSENSOR_CONFIG | \
	 EXCLUDED_PAXCOUNTER_CONFIG | EXCLUDED_NETWORK_CONFIG)

#define CONFIG_DEVICE_FIELD 1U
#define CONFIG_POSITION_FIELD 2U
#define CONFIG_POWER_FIELD 3U
#define CONFIG_NETWORK_FIELD 4U
#define CONFIG_DISPLAY_FIELD 5U
#define CONFIG_LORA_FIELD 6U
#define CONFIG_BLUETOOTH_FIELD 7U
#define CONFIG_SECURITY_FIELD 8U
#define CONFIG_DEVICE_UI_FIELD 10U

#define DEVICE_CONFIG_ROLE_FIELD 1U
#define DEVICE_CONFIG_NODE_INFO_BROADCAST_SECS_FIELD 7U

#define POSITION_CONFIG_FIXED_POSITION_FIELD 3U
#define POSITION_CONFIG_GPS_UPDATE_INTERVAL_FIELD 5U
#define POSITION_CONFIG_POSITION_FLAGS_FIELD 7U
#define POSITION_CONFIG_GPS_MODE_FIELD 13U
#define POSITION_CONFIG_GPS_MODE_NOT_PRESENT 2U

#define POWER_CONFIG_POWER_SAVING_FIELD 1U
#define POWER_CONFIG_WAIT_BLUETOOTH_SECS_FIELD 4U

#define LORA_CONFIG_USE_PRESET_FIELD 1U
#define LORA_CONFIG_MODEM_PRESET_FIELD 2U
#define LORA_CONFIG_BANDWIDTH_FIELD 3U
#define LORA_CONFIG_SPREAD_FACTOR_FIELD 4U
#define LORA_CONFIG_CODING_RATE_FIELD 5U
#define LORA_CONFIG_REGION_FIELD 7U
#define LORA_CONFIG_HOP_LIMIT_FIELD 8U
#define LORA_CONFIG_TX_ENABLED_FIELD 9U
#define LORA_CONFIG_TX_POWER_FIELD 10U
#define LORA_CONFIG_CHANNEL_NUM_FIELD 11U
#define LORA_CONFIG_IGNORE_MQTT_FIELD 104U

#define BLUETOOTH_CONFIG_ENABLED_FIELD 1U
#define BLUETOOTH_CONFIG_MODE_FIELD 2U
#define BLUETOOTH_CONFIG_PAIRING_MODE_NO_PIN 2U

#define NETWORK_CONFIG_WIFI_ENABLED_FIELD 1U
#define NETWORK_CONFIG_ETH_ENABLED_FIELD 6U
#define NETWORK_CONFIG_IPV6_ENABLED_FIELD 11U

#define DISPLAY_CONFIG_SCREEN_ON_SECS_FIELD 1U
#define DISPLAY_CONFIG_UNITS_FIELD 6U
#define DISPLAY_CONFIG_DISPLAYMODE_FIELD 8U

#define SECURITY_CONFIG_SERIAL_ENABLED_FIELD 5U
#define SECURITY_CONFIG_DEBUG_LOG_API_ENABLED_FIELD 6U
#define SECURITY_CONFIG_ADMIN_CHANNEL_ENABLED_FIELD 8U

#define DEVICE_UI_CONFIG_VERSION_FIELD 1U
#define DEVICE_UI_CONFIG_SCREEN_BRIGHTNESS_FIELD 2U
#define DEVICE_UI_CONFIG_SCREEN_TIMEOUT_FIELD 3U

#define MODULE_CONFIG_TELEMETRY_FIELD 6U
#define TELEMETRY_CONFIG_DEVICE_UPDATE_INTERVAL_FIELD 1U
#define TELEMETRY_CONFIG_ENVIRONMENT_UPDATE_INTERVAL_FIELD 2U
#define TELEMETRY_CONFIG_DEVICE_TELEMETRY_ENABLED_FIELD 14U

#define CHANNEL_INDEX_FIELD 1U
#define CHANNEL_SETTINGS_FIELD 2U
#define CHANNEL_ROLE_FIELD 3U
#define CHANNEL_SETTINGS_PSK_FIELD 2U
#define CHANNEL_SETTINGS_NAME_FIELD 3U
#define CHANNEL_SETTINGS_ID_FIELD 4U
#define CHANNEL_SETTINGS_UPLINK_ENABLED_FIELD 5U
#define CHANNEL_SETTINGS_DOWNLINK_ENABLED_FIELD 6U

#define REGION_PRESET_GROUPS_FIELD 1U
#define REGION_PRESET_REGION_GROUPS_FIELD 2U
#define PRESET_GROUP_PRESETS_FIELD 1U
#define PRESET_GROUP_DEFAULT_PRESET_FIELD 2U
#define PRESET_REGION_REGION_FIELD 1U
#define PRESET_REGION_GROUP_INDEX_FIELD 2U

struct pb_cursor {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static int pb_read_varint(struct pb_cursor *cur, uint64_t *value)
{
	uint64_t out = 0U;
	uint8_t shift = 0U;

	if (cur == NULL || value == NULL) {
		return -EINVAL;
	}

	while (cur->pos < cur->len && shift < 64U) {
		uint8_t byte = cur->buf[cur->pos++];

		if (shift == 63U && (byte & 0x7eU) != 0U) {
			return -EINVAL;
		}
		out |= ((uint64_t)(byte & 0x7fU)) << shift;
		if ((byte & 0x80U) == 0U) {
			*value = out;
			return 0;
		}
		shift += 7U;
	}

	return -EINVAL;
}

static int pb_read_key(struct pb_cursor *cur, uint32_t *field, uint32_t *wire_type)
{
	uint64_t key;
	uint64_t field64;
	int ret = pb_read_varint(cur, &key);

	if (ret < 0) {
		return ret;
	}

	field64 = key >> 3;
	*wire_type = (uint32_t)(key & 0x07U);
	if (field64 == 0U || field64 > PB_MAX_FIELD_NUMBER) {
		return -EINVAL;
	}
	*field = (uint32_t)field64;

	return 0;
}

static int pb_skip_value(struct pb_cursor *cur, uint32_t wire_type)
{
	uint64_t len;

	switch (wire_type) {
	case PB_WT_VARINT:
		return pb_read_varint(cur, &len);
	case PB_WT_LEN:
		if (pb_read_varint(cur, &len) < 0 || len > SIZE_MAX - cur->pos ||
		    cur->pos + (size_t)len > cur->len) {
			return -EINVAL;
		}
		cur->pos += (size_t)len;
		return 0;
	case PB_WT_64BIT:
		if (cur->len - cur->pos < 8U) {
			return -EINVAL;
		}
		cur->pos += 8U;
		return 0;
	case PB_WT_32BIT:
		if (cur->len - cur->pos < 4U) {
			return -EINVAL;
		}
		cur->pos += 4U;
		return 0;
	case PB_WT_SGROUP:
	case PB_WT_EGROUP:
		/*
		 * SECURITY: Deprecated proto2 group markers. Groups were removed
		 * in proto3 and have no length prefix, making them impossible to
		 * skip without schema knowledge. Reject to prevent parse confusion.
		 */
		return -EINVAL;
	default:
		/*
		 * SECURITY: Wire types 6 and 7 are reserved/undefined per the
		 * protobuf spec. Reject unknown wire types to prevent undefined
		 * behavior from malformed or malicious input.
		 */
		return -EINVAL;
	}
}

static int pb_read_len_value(struct pb_cursor *cur, const uint8_t **data, size_t *len)
{
	uint64_t n;

	if (pb_read_varint(cur, &n) < 0 || n > SIZE_MAX - cur->pos ||
	    cur->pos + (size_t)n > cur->len) {
		return -EINVAL;
	}

	*data = &cur->buf[cur->pos];
	*len = (size_t)n;
	cur->pos += (size_t)n;
	return 0;
}

static int pb_put_byte(uint8_t *buf, size_t buflen, size_t *pos, uint8_t byte)
{
	if (*pos >= buflen) {
		return -ENOMEM;
	}
	buf[(*pos)++] = byte;
	return 0;
}

static size_t pb_varint_size(uint64_t value)
{
	size_t len = 1U;

	while (value > 0x7fU) {
		value >>= 7;
		len++;
	}

	return len;
}

static size_t pb_key_size(uint32_t field, uint32_t wire_type)
{
	return pb_varint_size(((uint64_t)field << 3) | wire_type);
}

static int pb_write_varint_raw(uint8_t *buf, size_t buflen, size_t *pos,
			       uint64_t value)
{
	do {
		uint8_t byte = (uint8_t)(value & 0x7fU);

		value >>= 7;
		if (value != 0U) {
			byte |= 0x80U;
		}
		if (pb_put_byte(buf, buflen, pos, byte) < 0) {
			return -ENOMEM;
		}
	} while (value != 0U);

	return 0;
}

static int pb_write_key(uint8_t *buf, size_t buflen, size_t *pos,
			uint32_t field, uint32_t wire_type)
{
	return pb_write_varint_raw(buf, buflen, pos,
				   ((uint64_t)field << 3) | wire_type);
}

static int pb_write_varint_field(uint8_t *buf, size_t buflen, size_t *pos,
				 uint32_t field, uint64_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_VARINT) < 0) {
		return -ENOMEM;
	}
	return pb_write_varint_raw(buf, buflen, pos, value);
}

static int pb_write_fixed32_field(uint8_t *buf, size_t buflen, size_t *pos,
				  uint32_t field, uint32_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_32BIT) < 0 ||
	    buflen - *pos < sizeof(uint32_t)) {
		return -ENOMEM;
	}

	buf[(*pos)++] = (uint8_t)(value & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 8) & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 16) & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 24) & 0xffU);
	return 0;
}

static uint32_t float32_bits(float value)
{
	/* Returns the IEEE 754 binary32 bit pattern (as uint32_t) of `value`.
	 * The BUILD_ASSERT above and Zephyr target support (ARM/RISC-V/x86)
	 * guarantee the memcpy type-pun is valid. No NaN/inf special cases
	 * are needed for battery voltage encoding.
	 */
	uint32_t bits;

	memcpy(&bits, &value, sizeof(bits));
	return bits;
}

static int pb_write_len_field(uint8_t *buf, size_t buflen, size_t *pos,
			      uint32_t field, const uint8_t *data, size_t len)
{
	if (data == NULL && len > 0U) {
		return -EINVAL;
	}
	if (pb_write_key(buf, buflen, pos, field, PB_WT_LEN) < 0 ||
	    pb_write_varint_raw(buf, buflen, pos, len) < 0) {
		return -ENOMEM;
	}
	if (buflen - *pos < len) {
		return -ENOMEM;
	}
	if (len > 0U) {
		memcpy(&buf[*pos], data, len);
	}
	*pos += len;
	return 0;
}

static int pb_write_string_field(uint8_t *buf, size_t buflen, size_t *pos,
				 uint32_t field, const char *value)
{
	if (value == NULL) {
		value = "";
	}
	return pb_write_len_field(buf, buflen, pos, field,
				  (const uint8_t *)value, strlen(value));
}

static int copy_tmp_payload(const uint8_t *tmp, size_t len,
			    uint8_t *buf, size_t buflen)
{
	if (buf == NULL) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < len) {
		return -ENOMEM;
	}
	if (len > 0U) {
		memcpy(buf, tmp, len);
	}
	return (int)len;
}

static bool from_radio_len_field_supported(uint32_t field)
{
	switch (field) {
	case FROMRADIO_MY_INFO_FIELD:
	case FROMRADIO_NODE_INFO_FIELD:
	case FROMRADIO_CONFIG_FIELD:
	case FROMRADIO_MODULE_CONFIG_FIELD:
	case FROMRADIO_CHANNEL_FIELD:
	case FROMRADIO_METADATA_FIELD:
	case FROMRADIO_CLIENT_NOTIFICATION_FIELD:
	case FROMRADIO_REGION_PRESETS_FIELD:
		return true;
	default:
		return false;
	}
}

static const char *info_long_name(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->long_name != NULL &&
		info->long_name[0] != '\0') ? info->long_name : "LICHEN Node";
}

static const char *info_short_name(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->short_name != NULL &&
		info->short_name[0] != '\0') ? info->short_name : "LICH";
}

/*
 * SECURITY: The returned pointer is only valid while the info struct and its
 * firmware_version string remain allocated and unmodified. Callers must encode
 * or copy the result before freeing or reusing the info struct.
 */
static const char *info_firmware_version(
	const struct lichen_meshtastic_local_info *info)
{
	const char *version = (info != NULL) ? info->firmware_version : NULL;
	size_t meshtastic_pos = 0U;
	size_t brand_len = strlen(LICHEN_BRAND);
	char next;

	if (version == NULL || strncmp(version, LICHEN_BRAND, brand_len) != 0) {
		return "LICHEN Zephyr compat 0.0.0+unknown";
	}

	next = version[brand_len];
	if (next != '\0' && next != ' ' && next != '-' && next != '+') {
		return "LICHEN Zephyr compat 0.0.0+unknown";
	}

	for (const char *p = version; *p != '\0'; p++) {
		char c = *p;

		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
		if (c == MESHTASTIC_BRAND[meshtastic_pos]) {
			meshtastic_pos++;
			if (MESHTASTIC_BRAND[meshtastic_pos] == '\0') {
				return "LICHEN Zephyr compat 0.0.0+unknown";
			}
		} else {
			meshtastic_pos = (c == MESHTASTIC_BRAND[0]) ? 1U : 0U;
		}
	}

	return info->firmware_version;
}

static const char *info_pio_env(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->pio_env != NULL &&
		info->pio_env[0] != '\0') ? info->pio_env : "zephyr";
}

static uint32_t info_node_num(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->node_num != 0U) ? info->node_num :
							0x4c494348U;
}

static uint32_t info_min_app_version(
	const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->min_app_version != 0U) ?
		       info->min_app_version :
		       30200U;
}

static uint32_t info_nodedb_count(
	const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->nodedb_count != 0U) ?
		       info->nodedb_count :
		       1U;
}

static uint32_t info_hops_away(const struct lichen_meshtastic_local_info *info)
{
	return (info != NULL && info->has_hops_away) ? info->hops_away : 0U;
}

static uint32_t info_excluded_modules(
	const struct lichen_meshtastic_local_info *info)
{
	uint32_t excluded = EXCLUDED_MODULES_MVP;

	if (info == NULL || !info->has_bluetooth) {
		excluded |= EXCLUDED_BLUETOOTH_CONFIG;
	}

	return excluded;
}

static bool info_has_position(const struct lichen_meshtastic_local_info *info)
{
	/* Meshtastic Position is location-bearing. Do not emit a partial
	 * Position for time-only, altitude-only, or satellites-only metadata:
	 * many clients interpret the message as map-ready once present.
	 */
	return info != NULL && info->has_latitude_e7 && info->has_longitude_e7;
}

static int write_user(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_lora_config(uint8_t *buf, size_t buflen, size_t *pos,
			     const struct lichen_meshtastic_local_info *info)
{
	int32_t tx_power = (info != NULL && info->has_tx_power_dbm) ?
				   info->tx_power_dbm :
				   MESHTASTIC_DEFAULT_TX_POWER_DBM;

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
				  (uint64_t)(int64_t)tx_power) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_CHANNEL_NUM_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(buf, buflen, pos, LORA_CONFIG_IGNORE_MQTT_FIELD,
				  1U) < 0) {
		return -ENOMEM;
	}
	return 0;
}

static int write_device_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_position_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_power_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_network_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_display_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_bluetooth_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_security_config(uint8_t *buf, size_t buflen, size_t *pos,
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

static int write_device_ui_config(uint8_t *buf, size_t buflen, size_t *pos,
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

int lichen_meshtastic_decode_to_radio(const uint8_t *buf, size_t len,
				      struct lichen_meshtastic_to_radio *out)
{
	struct pb_cursor cur = { .buf = buf, .len = len };

	if (buf == NULL || out == NULL) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_TO_RADIO_MAX) {
		return -EMSGSIZE;
	}

	memset(out, 0, sizeof(*out));

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;
		const uint8_t *data;
		size_t data_len;
		enum lichen_meshtastic_to_radio_type type =
			LICHEN_MESHTASTIC_TO_RADIO_UNSET;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return -EINVAL;
		}

		switch (field) {
		case TORADIO_PACKET_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_PACKET;
			out->value.packet.data = data;
			out->value.packet.len = data_len;
			break;
		case TORADIO_WANT_CONFIG_ID_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID;
			out->value.want_config_id = (uint32_t)v;
			break;
		case TORADIO_DISCONNECT_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_DISCONNECT;
			out->value.disconnect = (v != 0U);
			break;
		case TORADIO_HEARTBEAT_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT;
			break;
		default:
			if (pb_skip_value(&cur, wt) < 0) {
				return -EINVAL;
			}
			continue;
		}

		out->type = type;
	}

	return out->type != LICHEN_MESHTASTIC_TO_RADIO_UNSET ? 0 : -ENODATA;
}

int lichen_meshtastic_encode_my_info_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	size_t pos = 0U;

	if (pb_write_varint_field(tmp, sizeof(tmp), &pos, MY_INFO_NODE_NUM_FIELD,
				  info_node_num(info)) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, MY_INFO_REBOOT_COUNT_FIELD,
				  info != NULL ? info->reboot_count : 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  MY_INFO_MIN_APP_VERSION_FIELD,
				  info_min_app_version(info)) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos, MY_INFO_DEVICE_ID_FIELD,
			       info != NULL ? info->device_id : NULL,
			       info != NULL ? info->device_id_len : 0U) < 0 ||
	    pb_write_string_field(tmp, sizeof(tmp), &pos, MY_INFO_PIO_ENV_FIELD,
				  info_pio_env(info)) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  MY_INFO_FIRMWARE_EDITION_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  MY_INFO_NODEDB_COUNT_FIELD,
				  info_nodedb_count(info)) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_metadata_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	size_t pos = 0U;

	if (pb_write_string_field(tmp, sizeof(tmp), &pos,
				  METADATA_FIRMWARE_VERSION_FIELD,
				  info_firmware_version(info)) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_DEVICE_STATE_VERSION_FIELD, 1U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_CAN_SHUTDOWN_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_HAS_WIFI_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_HAS_BLUETOOTH_FIELD,
				  (info != NULL && info->has_bluetooth) ? 1U :
									   0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_HAS_ETHERNET_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, METADATA_ROLE_FIELD,
				  MESHTASTIC_ROLE_CLIENT) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_POSITION_FLAGS_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, METADATA_HW_MODEL_FIELD,
				  MESHTASTIC_HW_MODEL_PRIVATE) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_HAS_REMOTE_HARDWARE_FIELD, 0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, METADATA_HAS_PKC_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  METADATA_EXCLUDED_MODULES_FIELD,
				  info_excluded_modules(info)) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_config_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	return lichen_meshtastic_encode_config_section_payload(
		LICHEN_MESHTASTIC_CONFIG_LORA, info, buf, buflen);
}

int lichen_meshtastic_encode_config_section_payload(
	enum lichen_meshtastic_config_section section,
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t inner[96];
	size_t pos = 0U;
	size_t inner_pos = 0U;
	uint32_t field;

	switch (section) {
	case LICHEN_MESHTASTIC_CONFIG_DEVICE:
		field = CONFIG_DEVICE_FIELD;
		if (write_device_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_POSITION:
		field = CONFIG_POSITION_FIELD;
		if (write_position_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_POWER:
		field = CONFIG_POWER_FIELD;
		if (write_power_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_NETWORK:
		field = CONFIG_NETWORK_FIELD;
		if (write_network_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_DISPLAY:
		field = CONFIG_DISPLAY_FIELD;
		if (write_display_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_LORA:
		field = CONFIG_LORA_FIELD;
		if (write_lora_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_BLUETOOTH:
		field = CONFIG_BLUETOOTH_FIELD;
		if (write_bluetooth_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_SECURITY:
		field = CONFIG_SECURITY_FIELD;
		if (write_security_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	case LICHEN_MESHTASTIC_CONFIG_DEVICE_UI:
		field = CONFIG_DEVICE_UI_FIELD;
		if (write_device_ui_config(inner, sizeof(inner), &inner_pos, info) < 0) {
			return -EMSGSIZE;
		}
		break;
	default:
		return -EINVAL;
	}

	if (pb_write_len_field(tmp, sizeof(tmp), &pos, field, inner, inner_pos) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_module_config_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t telemetry[16];
	size_t pos = 0U;
	size_t telemetry_pos = 0U;

	(void)info;

	if (pb_write_varint_field(telemetry, sizeof(telemetry), &telemetry_pos,
				  TELEMETRY_CONFIG_DEVICE_UPDATE_INTERVAL_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(telemetry, sizeof(telemetry), &telemetry_pos,
				  TELEMETRY_CONFIG_ENVIRONMENT_UPDATE_INTERVAL_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(telemetry, sizeof(telemetry), &telemetry_pos,
				  TELEMETRY_CONFIG_DEVICE_TELEMETRY_ENABLED_FIELD,
				  0U) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos, MODULE_CONFIG_TELEMETRY_FIELD,
			       telemetry, telemetry_pos) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_channel_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t settings[64];
	size_t pos = 0U;
	size_t settings_pos = 0U;

	if (pb_write_len_field(settings, sizeof(settings), &settings_pos,
			       CHANNEL_SETTINGS_PSK_FIELD, NULL, 0U) < 0 ||
	    pb_write_string_field(settings, sizeof(settings), &settings_pos,
				  CHANNEL_SETTINGS_NAME_FIELD, "LICHEN") < 0 ||
	    pb_write_fixed32_field(settings, sizeof(settings), &settings_pos,
				   CHANNEL_SETTINGS_ID_FIELD,
				   info_node_num(info)) < 0 ||
	    pb_write_varint_field(settings, sizeof(settings), &settings_pos,
				  CHANNEL_SETTINGS_UPLINK_ENABLED_FIELD, 0U) < 0 ||
	    pb_write_varint_field(settings, sizeof(settings), &settings_pos,
				  CHANNEL_SETTINGS_DOWNLINK_ENABLED_FIELD, 0U) < 0) {
		return -EMSGSIZE;
	}

	if (pb_write_varint_field(tmp, sizeof(tmp), &pos, CHANNEL_INDEX_FIELD,
				  0U) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos, CHANNEL_SETTINGS_FIELD,
			       settings, settings_pos) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, CHANNEL_ROLE_FIELD,
				  MESHTASTIC_CHANNEL_PRIMARY) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_region_presets_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t group[24];
	uint8_t region[8];
	size_t pos = 0U;
	size_t group_pos = 0U;
	size_t region_pos = 0U;

	(void)info;

	if (pb_write_varint_field(group, sizeof(group), &group_pos,
				  PRESET_GROUP_PRESETS_FIELD,
				  MESHTASTIC_MODEM_LONG_FAST) < 0 ||
	    pb_write_varint_field(group, sizeof(group), &group_pos,
				  PRESET_GROUP_DEFAULT_PRESET_FIELD,
				  MESHTASTIC_MODEM_LONG_FAST) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos, REGION_PRESET_GROUPS_FIELD,
			       group, group_pos) < 0) {
		return -EMSGSIZE;
	}

	if (pb_write_varint_field(region, sizeof(region), &region_pos,
				  PRESET_REGION_REGION_FIELD,
				  MESHTASTIC_REGION_US) < 0 ||
	    pb_write_varint_field(region, sizeof(region), &region_pos,
				  PRESET_REGION_GROUP_INDEX_FIELD, 0U) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos,
			       REGION_PRESET_REGION_GROUPS_FIELD, region,
			       region_pos) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_node_info_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen)
{
	uint8_t tmp[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t user[160];
	uint8_t position[48];
	uint8_t metrics[32];
	size_t pos = 0U;
	size_t user_pos = 0U;
	size_t position_pos = 0U;
	size_t metrics_pos = 0U;

	if (write_user(user, sizeof(user), &user_pos, info) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, NODE_INFO_NUM_FIELD,
				  info_node_num(info)) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos, NODE_INFO_USER_FIELD,
			       user, user_pos) < 0) {
		return -EMSGSIZE;
	}

	if (info_has_position(info)) {
		if (pb_write_fixed32_field(position, sizeof(position),
					   &position_pos,
					   POSITION_LATITUDE_I_FIELD,
					   (uint32_t)info->latitude_e7) < 0 ||
		    pb_write_fixed32_field(position, sizeof(position),
					   &position_pos,
					   POSITION_LONGITUDE_I_FIELD,
					   (uint32_t)info->longitude_e7) < 0) {
			return -EMSGSIZE;
		}
		if (info->has_altitude_m &&
		    pb_write_varint_field(position, sizeof(position),
					  &position_pos, POSITION_ALTITUDE_FIELD,
					  (uint64_t)(int64_t)info->altitude_m) < 0) {
			return -EMSGSIZE;
		}
		if (info->has_fix_time_unix &&
		    (pb_write_fixed32_field(position, sizeof(position),
					    &position_pos, POSITION_TIME_FIELD,
					    info->fix_time_unix) < 0 ||
		     pb_write_fixed32_field(position, sizeof(position),
					    &position_pos, POSITION_TIMESTAMP_FIELD,
					    info->fix_time_unix) < 0)) {
			return -EMSGSIZE;
		}
		if (info->has_gnss_fix &&
		    pb_write_varint_field(position, sizeof(position),
					  &position_pos,
					  POSITION_LOCATION_SOURCE_FIELD,
					  POSITION_LOC_SOURCE_INTERNAL) < 0) {
			return -EMSGSIZE;
		}
		if (info->has_altitude_m &&
		    pb_write_varint_field(position, sizeof(position),
					  &position_pos,
					  POSITION_ALTITUDE_SOURCE_FIELD,
					  POSITION_ALT_SOURCE_INTERNAL) < 0) {
			return -EMSGSIZE;
		}
		if (info->has_satellites &&
		    pb_write_varint_field(position, sizeof(position),
					  &position_pos,
					  POSITION_SATS_IN_VIEW_FIELD,
					  info->satellites) < 0) {
			return -EMSGSIZE;
		}
		if (pb_write_len_field(tmp, sizeof(tmp), &pos,
				       NODE_INFO_POSITION_FIELD, position,
				       position_pos) < 0) {
			return -EMSGSIZE;
		}
	}

	if (info != NULL && info->has_external_power && info->external_power &&
	    pb_write_varint_field(metrics, sizeof(metrics), &metrics_pos,
				  DEVICE_METRICS_BATTERY_LEVEL_FIELD, 101U) < 0) {
		return -EMSGSIZE;
	}
	if (info != NULL && (!info->has_external_power || !info->external_power) &&
	    info->has_battery_percent && info->battery_percent <= 100U &&
	    pb_write_varint_field(metrics, sizeof(metrics), &metrics_pos,
				  DEVICE_METRICS_BATTERY_LEVEL_FIELD,
				  info->battery_percent) < 0) {
		return -EMSGSIZE;
	}
	if (info != NULL && info->has_battery_voltage_mv) {
		float volts = (float)info->battery_voltage_mv / 1000.0f;

		if (pb_write_fixed32_field(metrics, sizeof(metrics), &metrics_pos,
					   DEVICE_METRICS_VOLTAGE_FIELD,
					   float32_bits(volts)) < 0) {
			return -EMSGSIZE;
		}
	}
	if (pb_write_varint_field(metrics, sizeof(metrics), &metrics_pos,
				  DEVICE_METRICS_UPTIME_SECONDS_FIELD,
				  info != NULL ? info->uptime_seconds : 0U) < 0 ||
	    pb_write_len_field(tmp, sizeof(tmp), &pos,
			       NODE_INFO_DEVICE_METRICS_FIELD, metrics,
			       metrics_pos) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos, NODE_INFO_CHANNEL_FIELD,
				  0U) < 0 ||
	    pb_write_varint_field(tmp, sizeof(tmp), &pos,
				  NODE_INFO_HOPS_AWAY_FIELD,
				  info_hops_away(info)) < 0) {
		return -EMSGSIZE;
	}

	return copy_tmp_payload(tmp, pos, buf, buflen);
}

int lichen_meshtastic_encode_from_radio_config_complete(uint32_t nonce,
							uint8_t *buf,
							size_t buflen)
{
	size_t pos = 0U;
	size_t encoded_len = pb_key_size(FROMRADIO_CONFIG_COMPLETE_ID_FIELD,
					 PB_WT_VARINT) +
			     pb_varint_size(nonce);

	if (buf == NULL) {
		return -EINVAL;
	}
	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}
	if (pb_write_varint_field(buf, buflen, &pos,
				  FROMRADIO_CONFIG_COMPLETE_ID_FIELD, nonce) < 0) {
		return -ENOMEM;
	}
	return (int)pos;
}

int lichen_meshtastic_encode_from_radio_queue_status(
	const struct lichen_meshtastic_queue_status *status,
	uint8_t *buf, size_t buflen)
{
	uint8_t inner[32];
	size_t inner_pos = 0U;
	size_t pos = 0U;

	if (status == NULL || buf == NULL) {
		return -EINVAL;
	}

	if (status->has_res &&
	    pb_write_varint_field(inner, sizeof(inner), &inner_pos,
				  QUEUE_STATUS_RES_FIELD, status->res) < 0) {
		return -ENOMEM;
	}
	if (pb_write_varint_field(inner, sizeof(inner), &inner_pos,
				  QUEUE_STATUS_FREE_FIELD, status->free) < 0 ||
	    pb_write_varint_field(inner, sizeof(inner), &inner_pos,
				  QUEUE_STATUS_MAXLEN_FIELD, status->maxlen) < 0) {
		return -ENOMEM;
	}
	if (status->has_mesh_packet_id &&
	    pb_write_varint_field(inner, sizeof(inner), &inner_pos,
				  QUEUE_STATUS_MESH_PACKET_ID_FIELD,
				  status->mesh_packet_id) < 0) {
		return -ENOMEM;
	}

	size_t encoded_len = pb_key_size(FROMRADIO_QUEUE_STATUS_FIELD, PB_WT_LEN) +
			     pb_varint_size(inner_pos) + inner_pos;

	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}

	if (pb_write_len_field(buf, buflen, &pos, FROMRADIO_QUEUE_STATUS_FIELD,
			       inner, inner_pos) < 0) {
		return -ENOMEM;
	}

	return (int)pos;
}

int lichen_meshtastic_encode_from_radio_packet(uint32_t from_radio_id,
					       const uint8_t *packet,
					       size_t packet_len,
					       uint8_t *buf,
					       size_t buflen)
{
	size_t pos = 0U;
	size_t encoded_len;

	if (buf == NULL || (packet == NULL && packet_len > 0U)) {
		return -EINVAL;
	}

	if (packet_len > SIZE_MAX - pb_key_size(FROMRADIO_ID_FIELD, PB_WT_VARINT) -
				 pb_varint_size(from_radio_id) -
				 pb_key_size(FROMRADIO_PACKET_FIELD, PB_WT_LEN) -
				 pb_varint_size(packet_len)) {
		return -EMSGSIZE;
	}

	encoded_len = pb_key_size(FROMRADIO_ID_FIELD, PB_WT_VARINT) +
		      pb_varint_size(from_radio_id) +
		      pb_key_size(FROMRADIO_PACKET_FIELD, PB_WT_LEN) +
		      pb_varint_size(packet_len) + packet_len;
	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}

	if (pb_write_varint_field(buf, buflen, &pos, FROMRADIO_ID_FIELD,
				  from_radio_id) < 0 ||
	    pb_write_len_field(buf, buflen, &pos, FROMRADIO_PACKET_FIELD,
			       packet, packet_len) < 0) {
		return -ENOMEM;
	}

	return (int)pos;
}

int lichen_meshtastic_encode_text_packet(
	const struct lichen_meshtastic_text_packet *packet,
	uint8_t *buf, size_t buflen)
{
	uint8_t data[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 8U];
	size_t data_pos = 0U;
	size_t encoded_len;
	size_t pos = 0U;

	if (packet == NULL || buf == NULL ||
	    (packet->payload == NULL && packet->payload_len > 0U)) {
		return -EINVAL;
	}
	if (packet->payload_len == 0U ||
	    packet->payload_len > LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX) {
		return -EMSGSIZE;
	}

	if (pb_write_varint_field(data, sizeof(data), &data_pos,
				  DATA_PORTNUM_FIELD,
				  MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP) < 0 ||
	    pb_write_len_field(data, sizeof(data), &data_pos,
			       DATA_PAYLOAD_FIELD, packet->payload,
			       packet->payload_len) < 0) {
		return -ENOMEM;
	}

	encoded_len = pb_key_size(MESH_PACKET_FROM_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t) +
		      pb_key_size(MESH_PACKET_TO_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t) +
		      pb_key_size(MESH_PACKET_DECODED_FIELD, PB_WT_LEN) +
		      pb_varint_size(data_pos) + data_pos +
		      pb_key_size(MESH_PACKET_ID_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t);
	if (packet->has_channel) {
		encoded_len += pb_key_size(MESH_PACKET_CHANNEL_FIELD, PB_WT_VARINT) +
			       pb_varint_size(packet->channel);
	}
	if (packet->want_ack) {
		encoded_len += pb_key_size(MESH_PACKET_WANT_ACK_FIELD, PB_WT_VARINT) +
			       1U;
	}
	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}

	if (pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_FROM_FIELD,
				   packet->from) < 0 ||
	    pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_TO_FIELD,
				   packet->to) < 0) {
		return -ENOMEM;
	}
	if (packet->has_channel &&
	    pb_write_varint_field(buf, buflen, &pos, MESH_PACKET_CHANNEL_FIELD,
				  packet->channel) < 0) {
		return -ENOMEM;
	}
	if (pb_write_len_field(buf, buflen, &pos, MESH_PACKET_DECODED_FIELD,
			       data, data_pos) < 0 ||
	    pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_ID_FIELD,
				   packet->id) < 0) {
		return -ENOMEM;
	}
	if (packet->want_ack &&
	    pb_write_varint_field(buf, buflen, &pos, MESH_PACKET_WANT_ACK_FIELD,
				  1U) < 0) {
		return -ENOMEM;
	}

	return (int)pos;
}

int lichen_meshtastic_encode_routing_packet(
	const struct lichen_meshtastic_routing_packet *packet,
	uint8_t *buf, size_t buflen)
{
	uint8_t routing[8];
	uint8_t data[32];
	size_t routing_pos = 0U;
	size_t data_pos = 0U;
	size_t encoded_len;
	size_t pos = 0U;

	if (packet == NULL || buf == NULL) {
		return -EINVAL;
	}

	if (packet->has_error_reason &&
	    pb_write_varint_field(routing, sizeof(routing), &routing_pos,
				  ROUTING_ERROR_REASON_FIELD,
				  packet->error_reason) < 0) {
		return -ENOMEM;
	}
	if (pb_write_varint_field(data, sizeof(data), &data_pos,
				  DATA_PORTNUM_FIELD,
				  MESHTASTIC_PORTNUM_ROUTING_APP) < 0) {
		return -ENOMEM;
	}
	if (packet->has_error_reason &&
	    pb_write_len_field(data, sizeof(data), &data_pos,
			       DATA_PAYLOAD_FIELD, routing, routing_pos) < 0) {
		return -ENOMEM;
	}
	if (pb_write_fixed32_field(data, sizeof(data), &data_pos,
				   DATA_REQUEST_ID_FIELD,
				   packet->request_id) < 0) {
		return -ENOMEM;
	}

	encoded_len = pb_key_size(MESH_PACKET_FROM_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t) +
		      pb_key_size(MESH_PACKET_TO_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t) +
		      pb_key_size(MESH_PACKET_DECODED_FIELD, PB_WT_LEN) +
		      pb_varint_size(data_pos) + data_pos +
		      pb_key_size(MESH_PACKET_ID_FIELD, PB_WT_32BIT) +
		      sizeof(uint32_t);
	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}

	if (pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_FROM_FIELD,
				   packet->from) < 0 ||
	    pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_TO_FIELD,
				   packet->to) < 0 ||
	    pb_write_len_field(buf, buflen, &pos, MESH_PACKET_DECODED_FIELD,
			       data, data_pos) < 0 ||
	    pb_write_fixed32_field(buf, buflen, &pos, MESH_PACKET_ID_FIELD,
				   packet->id) < 0) {
		return -ENOMEM;
	}

	return (int)pos;
}

int lichen_meshtastic_encode_from_radio_message(
	enum lichen_meshtastic_from_radio_message message,
	const uint8_t *payload, size_t payload_len,
	uint8_t *buf, size_t buflen)
{
	uint32_t field = (uint32_t)message;
	size_t encoded_len;
	size_t pos = 0U;

	if (buf == NULL || (payload == NULL && payload_len > 0U)) {
		return -EINVAL;
	}
	if (!from_radio_len_field_supported(field)) {
		return -EINVAL;
	}
	if (payload_len > SIZE_MAX - pb_key_size(field, PB_WT_LEN) -
				  pb_varint_size(payload_len)) {
		return -EMSGSIZE;
	}

	encoded_len = pb_key_size(field, PB_WT_LEN) +
		      pb_varint_size(payload_len) + payload_len;
	if (encoded_len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < encoded_len) {
		return -ENOMEM;
	}

	if (pb_write_len_field(buf, buflen, &pos, field, payload, payload_len) < 0) {
		return -ENOMEM;
	}

	return (int)pos;
}
