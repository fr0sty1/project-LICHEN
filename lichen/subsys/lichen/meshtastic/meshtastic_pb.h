/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Internal protobuf helpers for Meshtastic codec.
 * This header is not part of the public API.
 */

#ifndef LICHEN_MESHTASTIC_PB_H_
#define LICHEN_MESHTASTIC_PB_H_

#include <stddef.h>
#include <stdint.h>

#include <lichen/meshtastic/codec.h>

/* Protobuf wire types per https://protobuf.dev/programming-guides/encoding/ */
#define PB_WT_VARINT 0U
#define PB_WT_64BIT 1U
#define PB_WT_LEN 2U
#define PB_WT_SGROUP 3U  /* Deprecated: proto2 start group marker */
#define PB_WT_EGROUP 4U  /* Deprecated: proto2 end group marker */
#define PB_WT_32BIT 5U
/* Wire types 6 and 7 are reserved/undefined per protobuf spec */

#define PB_MAX_FIELD_NUMBER 536870911ULL

/* Meshtastic protocol constants */
#define MESHTASTIC_HW_MODEL_PRIVATE 255U
#define MESHTASTIC_ROLE_CLIENT 0U
#define MESHTASTIC_CHANNEL_PRIMARY 1U
#define MESHTASTIC_REGION_US 1U
#define MESHTASTIC_MODEM_LONG_FAST 0U
#define MESHTASTIC_DEFAULT_TX_POWER_DBM 14
#define MESHTASTIC_NODE_INFO_BROADCAST_SECS 900U

/* ToRadio field numbers */
#define TORADIO_PACKET_FIELD 1U
#define TORADIO_WANT_CONFIG_ID_FIELD 3U
#define TORADIO_DISCONNECT_FIELD 4U
#define TORADIO_HEARTBEAT_FIELD 7U

/* FromRadio field numbers */
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

/* QueueStatus field numbers */
#define QUEUE_STATUS_RES_FIELD 1U
#define QUEUE_STATUS_FREE_FIELD 2U
#define QUEUE_STATUS_MAXLEN_FIELD 3U
#define QUEUE_STATUS_MESH_PACKET_ID_FIELD 4U

/* MeshPacket field numbers */
#define MESH_PACKET_FROM_FIELD 1U
#define MESH_PACKET_TO_FIELD 2U
#define MESH_PACKET_CHANNEL_FIELD 3U
#define MESH_PACKET_DECODED_FIELD 4U
#define MESH_PACKET_ID_FIELD 6U
#define MESH_PACKET_WANT_ACK_FIELD 10U

/* Data field numbers */
#define DATA_PORTNUM_FIELD 1U
#define DATA_PAYLOAD_FIELD 2U
#define DATA_REQUEST_ID_FIELD 6U
#define MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP 1U
#define MESHTASTIC_PORTNUM_ROUTING_APP 5U

/* Routing field numbers */
#define ROUTING_ERROR_REASON_FIELD 3U

/* MyInfo field numbers */
#define MY_INFO_NODE_NUM_FIELD 1U
#define MY_INFO_REBOOT_COUNT_FIELD 8U
#define MY_INFO_MIN_APP_VERSION_FIELD 11U
#define MY_INFO_DEVICE_ID_FIELD 12U
#define MY_INFO_PIO_ENV_FIELD 13U
#define MY_INFO_FIRMWARE_EDITION_FIELD 14U
#define MY_INFO_NODEDB_COUNT_FIELD 15U

/* User field numbers */
#define USER_ID_FIELD 1U
#define USER_LONG_NAME_FIELD 2U
#define USER_SHORT_NAME_FIELD 3U
#define USER_HW_MODEL_FIELD 5U
#define USER_IS_LICENSED_FIELD 6U
#define USER_ROLE_FIELD 7U
#define USER_PUBLIC_KEY_FIELD 8U
#define USER_IS_UNMESSAGABLE_FIELD 9U

/* NodeInfo field numbers */
#define NODE_INFO_NUM_FIELD 1U
#define NODE_INFO_USER_FIELD 2U
#define NODE_INFO_POSITION_FIELD 3U
#define NODE_INFO_DEVICE_METRICS_FIELD 6U
#define NODE_INFO_CHANNEL_FIELD 7U
#define NODE_INFO_HOPS_AWAY_FIELD 9U

/* Position field numbers */
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

/* DeviceMetrics field numbers */
#define DEVICE_METRICS_BATTERY_LEVEL_FIELD 1U
#define DEVICE_METRICS_VOLTAGE_FIELD 2U
#define DEVICE_METRICS_UPTIME_SECONDS_FIELD 5U

/* Metadata field numbers */
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

/* Excluded modules bitmask */
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

/* Config field numbers */
#define CONFIG_DEVICE_FIELD 1U
#define CONFIG_POSITION_FIELD 2U
#define CONFIG_POWER_FIELD 3U
#define CONFIG_NETWORK_FIELD 4U
#define CONFIG_DISPLAY_FIELD 5U
#define CONFIG_LORA_FIELD 6U
#define CONFIG_BLUETOOTH_FIELD 7U
#define CONFIG_SECURITY_FIELD 8U
#define CONFIG_DEVICE_UI_FIELD 10U

/* DeviceConfig field numbers */
#define DEVICE_CONFIG_ROLE_FIELD 1U
#define DEVICE_CONFIG_NODE_INFO_BROADCAST_SECS_FIELD 7U

/* PositionConfig field numbers */
#define POSITION_CONFIG_FIXED_POSITION_FIELD 3U
#define POSITION_CONFIG_GPS_UPDATE_INTERVAL_FIELD 5U
#define POSITION_CONFIG_POSITION_FLAGS_FIELD 7U
#define POSITION_CONFIG_GPS_MODE_FIELD 13U
#define POSITION_CONFIG_GPS_MODE_NOT_PRESENT 2U

/* PowerConfig field numbers */
#define POWER_CONFIG_POWER_SAVING_FIELD 1U
#define POWER_CONFIG_WAIT_BLUETOOTH_SECS_FIELD 4U

/* LoRaConfig field numbers */
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

/* BluetoothConfig field numbers */
#define BLUETOOTH_CONFIG_ENABLED_FIELD 1U
#define BLUETOOTH_CONFIG_MODE_FIELD 2U
#define BLUETOOTH_CONFIG_PAIRING_MODE_NO_PIN 2U

/* NetworkConfig field numbers */
#define NETWORK_CONFIG_WIFI_ENABLED_FIELD 1U
#define NETWORK_CONFIG_ETH_ENABLED_FIELD 6U
#define NETWORK_CONFIG_IPV6_ENABLED_FIELD 11U

/* DisplayConfig field numbers */
#define DISPLAY_CONFIG_SCREEN_ON_SECS_FIELD 1U
#define DISPLAY_CONFIG_UNITS_FIELD 6U
#define DISPLAY_CONFIG_DISPLAYMODE_FIELD 8U

/* SecurityConfig field numbers */
#define SECURITY_CONFIG_SERIAL_ENABLED_FIELD 5U
#define SECURITY_CONFIG_DEBUG_LOG_API_ENABLED_FIELD 6U
#define SECURITY_CONFIG_ADMIN_CHANNEL_ENABLED_FIELD 8U

/* DeviceUIConfig field numbers */
#define DEVICE_UI_CONFIG_VERSION_FIELD 1U
#define DEVICE_UI_CONFIG_SCREEN_BRIGHTNESS_FIELD 2U
#define DEVICE_UI_CONFIG_SCREEN_TIMEOUT_FIELD 3U

/* ModuleConfig field numbers */
#define MODULE_CONFIG_TELEMETRY_FIELD 6U
#define TELEMETRY_CONFIG_DEVICE_UPDATE_INTERVAL_FIELD 1U
#define TELEMETRY_CONFIG_ENVIRONMENT_UPDATE_INTERVAL_FIELD 2U
#define TELEMETRY_CONFIG_DEVICE_TELEMETRY_ENABLED_FIELD 14U

/* Channel field numbers */
#define CHANNEL_INDEX_FIELD 1U
#define CHANNEL_SETTINGS_FIELD 2U
#define CHANNEL_ROLE_FIELD 3U
#define CHANNEL_SETTINGS_PSK_FIELD 2U
#define CHANNEL_SETTINGS_NAME_FIELD 3U
#define CHANNEL_SETTINGS_ID_FIELD 4U
#define CHANNEL_SETTINGS_UPLINK_ENABLED_FIELD 5U
#define CHANNEL_SETTINGS_DOWNLINK_ENABLED_FIELD 6U

/* RegionPresets field numbers */
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

/* Protobuf read functions */
int pb_read_varint(struct pb_cursor *cur, uint64_t *value);
int pb_read_key(struct pb_cursor *cur, uint32_t *field, uint32_t *wire_type);
int pb_skip_value(struct pb_cursor *cur, uint32_t wire_type);
int pb_read_len_value(struct pb_cursor *cur, const uint8_t **data, size_t *len);

/* Protobuf write functions */
int pb_put_byte(uint8_t *buf, size_t buflen, size_t *pos, uint8_t byte);
size_t pb_varint_size(uint64_t value);
size_t pb_key_size(uint32_t field, uint32_t wire_type);
int pb_write_varint_raw(uint8_t *buf, size_t buflen, size_t *pos, uint64_t value);
int pb_write_key(uint8_t *buf, size_t buflen, size_t *pos,
		 uint32_t field, uint32_t wire_type);
int pb_write_varint_field(uint8_t *buf, size_t buflen, size_t *pos,
			  uint32_t field, uint64_t value);
int pb_write_fixed32_field(uint8_t *buf, size_t buflen, size_t *pos,
			   uint32_t field, uint32_t value);
uint32_t float32_bits(float value);
int pb_write_len_field(uint8_t *buf, size_t buflen, size_t *pos,
		       uint32_t field, const uint8_t *data, size_t len);
int pb_write_string_field(uint8_t *buf, size_t buflen, size_t *pos,
			  uint32_t field, const char *value);
int copy_tmp_payload(const uint8_t *tmp, size_t len,
		     uint8_t *buf, size_t buflen);

/* Info helper functions */
const char *info_long_name(const struct lichen_meshtastic_local_info *info);
const char *info_short_name(const struct lichen_meshtastic_local_info *info);
const char *info_firmware_version(const struct lichen_meshtastic_local_info *info);
const char *info_pio_env(const struct lichen_meshtastic_local_info *info);
uint32_t info_node_num(const struct lichen_meshtastic_local_info *info);
uint32_t info_min_app_version(const struct lichen_meshtastic_local_info *info);
uint32_t info_nodedb_count(const struct lichen_meshtastic_local_info *info);
uint32_t info_hops_away(const struct lichen_meshtastic_local_info *info);
uint32_t info_excluded_modules(const struct lichen_meshtastic_local_info *info);
bool info_has_position(const struct lichen_meshtastic_local_info *info);

/* Config writer functions */
int write_user(uint8_t *buf, size_t buflen, size_t *pos,
	       const struct lichen_meshtastic_local_info *info);
int write_lora_config(uint8_t *buf, size_t buflen, size_t *pos,
		      const struct lichen_meshtastic_local_info *info);
int write_device_config(uint8_t *buf, size_t buflen, size_t *pos,
			const struct lichen_meshtastic_local_info *info);
int write_position_config(uint8_t *buf, size_t buflen, size_t *pos,
			  const struct lichen_meshtastic_local_info *info);
int write_power_config(uint8_t *buf, size_t buflen, size_t *pos,
		       const struct lichen_meshtastic_local_info *info);
int write_network_config(uint8_t *buf, size_t buflen, size_t *pos,
			 const struct lichen_meshtastic_local_info *info);
int write_display_config(uint8_t *buf, size_t buflen, size_t *pos,
			 const struct lichen_meshtastic_local_info *info);
int write_bluetooth_config(uint8_t *buf, size_t buflen, size_t *pos,
			   const struct lichen_meshtastic_local_info *info);
int write_security_config(uint8_t *buf, size_t buflen, size_t *pos,
			  const struct lichen_meshtastic_local_info *info);
int write_device_ui_config(uint8_t *buf, size_t buflen, size_t *pos,
			   const struct lichen_meshtastic_local_info *info);

/* Decode helper */
bool from_radio_len_field_supported(uint32_t field);

#endif /* LICHEN_MESHTASTIC_PB_H_ */
