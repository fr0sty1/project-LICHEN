/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "meshtastic_pb.h"

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
