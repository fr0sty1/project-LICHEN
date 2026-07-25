/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/pb_internal.h>

#include "adapter_internal.h"

#define POSITION_LATITUDE_I_FIELD 1U
#define POSITION_LONGITUDE_I_FIELD 2U
#define POSITION_ALTITUDE_FIELD 3U
#define POSITION_TIME_FIELD 4U
#define POSITION_LOCATION_SOURCE_FIELD 5U
#define POSITION_ALTITUDE_SOURCE_FIELD 6U
#define POSITION_TIMESTAMP_FIELD 7U
#define POSITION_GPS_ACCURACY_FIELD 14U
#define POSITION_SATS_IN_VIEW_FIELD 19U
#define POSITION_PRECISION_BITS_FIELD 23U

#define ADMIN_GET_OWNER_REQUEST_FIELD 3U
#define ADMIN_GET_DEVICE_METADATA_REQUEST_FIELD 12U
#define ADMIN_GET_DEVICE_METADATA_RESPONSE_FIELD 13U
#define ADMIN_SET_OWNER_FIELD 32U
#define ADMIN_SESSION_PASSKEY_FIELD 101U
#define ADMIN_OTA_REQUEST_FIELD 102U
#define ADMIN_SENSOR_CONFIG_FIELD 103U
#define ADMIN_LOCKDOWN_AUTH_FIELD 104U

int32_t adapter_read_le_i32_twos_complement(const uint8_t bytes[4])
{
	uint32_t raw = sys_get_le32(bytes);

	if ((raw & BIT(31)) == 0U) {
		return (int32_t)raw;
	}

	return -1 - (int32_t)(UINT32_MAX - raw);
}

static int int32_from_pb_varint(uint64_t raw, int32_t *out)
{
	if (out == NULL) {
		return -EINVAL;
	}
	if (raw <= (uint64_t)INT32_MAX) {
		*out = (int32_t)raw;
		return 0;
	}
	if (raw >= UINT64_MAX - (uint64_t)INT32_MAX) {
		*out = -1 - (int32_t)(UINT64_MAX - raw);
		return 0;
	}

	return -ERANGE;
}

static bool valid_position_e7(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

static void set_position_fix_time(
	struct lichen_meshtastic_position_snapshot *position, uint32_t unix_time)
{
	position->effective_epoch_floor =
		(uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_EPOCH_FLOOR_UNIX;
	uint32_t max_ts = position->effective_epoch_floor +
			  (uint32_t)CONFIG_LICHEN_MESHTASTIC_POSITION_MAX_FUTURE_SKEW;
	if (unix_time < position->effective_epoch_floor) {
		position->fix_time_rejected_below_epoch_floor = true;
		position->fix_time_rejected_future = false;
		position->fix_time_unix_valid = false;
		position->fix_time_unix = 0U;
		return;
	}
	if (unix_time > max_ts) {
		position->fix_time_rejected_below_epoch_floor = false;
		position->fix_time_rejected_future = true;
		position->fix_time_unix_valid = false;
		position->fix_time_unix = 0U;
		return;
	}

	position->fix_time_rejected_below_epoch_floor = false;
	position->fix_time_rejected_future = false;
	position->fix_time_unix = unix_time;
	position->fix_time_unix_valid = true;
}

static int parse_position_payload(
	const uint8_t *payload, size_t len,
	struct lichen_meshtastic_position_snapshot *position)
{
	struct pb_cursor cur = { .buf = payload, .len = len };

	if (position == NULL || (payload == NULL && len > 0U)) {
		return -EINVAL;
	}
	memset(position, 0, sizeof(*position));

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return -EINVAL;
		}

		switch (field) {
		case POSITION_LATITUDE_I_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			position->latitude_e7 =
				adapter_read_le_i32_twos_complement(&cur.buf[cur.pos]);
			position->latitude_e7_valid = true;
			cur.pos += sizeof(uint32_t);
			break;
		case POSITION_LONGITUDE_I_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			position->longitude_e7 =
				adapter_read_le_i32_twos_complement(&cur.buf[cur.pos]);
			position->longitude_e7_valid = true;
			cur.pos += sizeof(uint32_t);
			break;
		case POSITION_ALTITUDE_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    int32_from_pb_varint(v, &position->altitude_m) < 0) {
				return -EINVAL;
			}
			position->altitude_m_valid = true;
			break;
		case POSITION_TIME_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			if (!position->timestamp_field_valid) {
				set_position_fix_time(
					position, sys_get_le32(&cur.buf[cur.pos]));
			}
			cur.pos += sizeof(uint32_t);
			break;
		case POSITION_LOCATION_SOURCE_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			position->location_source = (uint32_t)v;
			position->location_source_valid = true;
			break;
		case POSITION_ALTITUDE_SOURCE_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			position->altitude_source = (uint32_t)v;
			position->altitude_source_valid = true;
			break;
		case POSITION_TIMESTAMP_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			position->timestamp_field_valid = true;
			set_position_fix_time(position, sys_get_le32(&cur.buf[cur.pos]));
			cur.pos += sizeof(uint32_t);
			break;
		case POSITION_GPS_ACCURACY_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			position->gps_accuracy_mm = (uint32_t)v;
			position->gps_accuracy_mm_valid = true;
			break;
		case POSITION_SATS_IN_VIEW_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT8_MAX) {
				return -EINVAL;
			}
			position->satellites = (uint8_t)v;
			position->satellites_valid = true;
			break;
		case POSITION_PRECISION_BITS_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT8_MAX) {
				return -EINVAL;
			}
			position->precision_bits = (uint8_t)v;
			position->precision_bits_valid = true;
			break;
		default:
			if (pb_skip_value(&cur, wt) < 0) {
				return -EINVAL;
			}
			break;
		}
	}

	if (!position->latitude_e7_valid || !position->longitude_e7_valid ||
	    !valid_position_e7(position->latitude_e7, position->longitude_e7)) {
		return -EINVAL;
	}

	return 0;
}

static bool admin_payload_variant_field(uint32_t field)
{
	/* Ranges for Meshtastic AdminMessage.payload_variant oneof (admin.proto)
	 * pinned at LICHEN_MESHTASTIC_PROTOBUF_COMMIT
	 * 032b7dfd68e875c4323e6ac67590c6fc616b1714 (see codec.h:28).
	 * Field 101 (session_passkey) is context not a oneof arm.
	 * Unknown future fields must be skipped (do not override prior oneof).
	 */
	return (field >= 0U && field <= 8U) ||
	       (field >= 10U && field <= 27U) ||
	       (field >= 32U && field <= 49U) ||
	       (field >= 64U && field <= 67U) ||
	       (field >= 94U && field <= 100U) ||
	       (field >= ADMIN_OTA_REQUEST_FIELD &&
		field <= ADMIN_LOCKDOWN_AUTH_FIELD);
}

static bool parse_admin_payload(const uint8_t *payload, size_t len,
				enum lichen_meshtastic_adapter_packet_kind *kind)
{
	if (kind == NULL || payload == NULL || len == 0U) {
		if (kind != NULL) {
			*kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED;
		}
		return false;
	}

	struct pb_cursor cur = { .buf = payload, .len = len };

	*kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return false;
		}

		switch (field) {
		case ADMIN_GET_DEVICE_METADATA_REQUEST_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0) {
				return false;
			}
			*kind = (v != 0U) ?
				LICHEN_MESHTASTIC_ADAPTER_PACKET_ADMIN_GET_DEVICE_METADATA :
				LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
			break;
		case ADMIN_SESSION_PASSKEY_FIELD:
			if (pb_skip_value(&cur, wt) < 0) {
				return false;
			}
			break;
		case ADMIN_GET_OWNER_REQUEST_FIELD:
		case ADMIN_SET_OWNER_FIELD:
			*kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
			if (pb_skip_value(&cur, wt) < 0) {
				return false;
			}
			break;
		default:
			if (admin_payload_variant_field(field)) {
				*kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
			}
			if (pb_skip_value(&cur, wt) < 0) {
				return false;
			}
			break;
		}
	}

	return true;
}

static int parse_data(const uint8_t *data, size_t len,
		      struct lichen_meshtastic_adapter_packet_info *info)
{
	struct pb_cursor cur = { .buf = data, .len = len };

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;
		const uint8_t *payload;
		size_t payload_len;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return -EINVAL;
		}

		switch (field) {
		case DATA_PORTNUM_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			info->portnum = (uint32_t)v;
			info->has_portnum = true;
			break;
		case DATA_PAYLOAD_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &payload, &payload_len) < 0) {
				return -EINVAL;
			}
			info->payload = payload;
			info->payload_len = payload_len;
			if (payload_len > 0U && payload_len <= LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX) {
				memcpy(info->payload_buf, payload, payload_len);
				info->payload_buf[payload_len] = '\0';
				info->payload = info->payload_buf;
			} else if (payload_len > 0U) {
				info->payload = NULL;
				info->payload_len = 0U;
			}
			break;
		default:
			if (pb_skip_value(&cur, wt) < 0) {
				return -EINVAL;
			}
			break;
		}
	}

	if (info->has_portnum) {
		if (info->portnum == MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP) {
			if (info->payload == NULL || info->payload_len == 0U) {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED;
			} else {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP;
			}
		} else if (info->portnum == MESHTASTIC_PORTNUM_POSITION_APP) {
			if (info->payload == NULL ||
			    parse_position_payload(info->payload,
						   info->payload_len,
						   &info->position) < 0) {
				info->kind =
					LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED;
			} else {
				info->kind =
					LICHEN_MESHTASTIC_ADAPTER_PACKET_POSITION_APP;
			}
		} else if (info->portnum == MESHTASTIC_PORTNUM_ADMIN_APP) {
			if (info->payload == NULL || info->payload_len == 0U || !parse_admin_payload(info->payload, info->payload_len,
						 &info->kind)) {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED;
			}
		} else {
			info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
		}
	}

	return 0;
}

int adapter_parse_packet(const uint8_t *packet, size_t len,
			 struct lichen_meshtastic_adapter_packet_info *info)
{
	struct pb_cursor cur = { .buf = packet, .len = len };
	bool seen_payload_variant = false;

	memset(info, 0, sizeof(*info));

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;
		const uint8_t *data;
		size_t data_len;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return -EINVAL;
		}

		switch (field) {
		case MESH_PACKET_FROM_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			info->from = sys_get_le32(&cur.buf[cur.pos]);
			info->has_from = true;
			cur.pos += sizeof(uint32_t);
			break;
		case MESH_PACKET_TO_FIELD:
			if (wt != PB_WT_32BIT ||
			    cur.len - cur.pos < sizeof(uint32_t)) {
				return -EINVAL;
			}
			info->to = sys_get_le32(&cur.buf[cur.pos]);
			info->has_to = true;
			cur.pos += sizeof(uint32_t);
			break;
		case MESH_PACKET_ID_FIELD:
			if (wt == PB_WT_32BIT) {
				if (cur.len - cur.pos < sizeof(uint32_t)) {
					return -EINVAL;
				}
				info->id = sys_get_le32(&cur.buf[cur.pos]);
				info->has_id = true;
				cur.pos += sizeof(uint32_t);
			} else if (wt == PB_WT_VARINT) {
				if (pb_read_varint(&cur, &v) < 0 || v > UINT32_MAX) {
					return -EINVAL;
				}
				info->id = (uint32_t)v;
				info->has_id = true;
			} else {
				return -EINVAL;
			}
			break;
		case MESH_PACKET_CHANNEL_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			info->channel = (uint32_t)v;
			info->has_channel = true;
			break;
		case MESH_PACKET_WANT_ACK_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0) {
				return -EINVAL;
			}
			info->want_ack = (v != 0U);
			break;
		case MESH_PACKET_DECODED_FIELD:
			if (seen_payload_variant) {
				return -EINVAL;
			}
			seen_payload_variant = true;
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			if (parse_data(data, data_len, info) < 0) {
				return -EINVAL;
			}
			break;
		case MESH_PACKET_ENCRYPTED_FIELD:
			if (seen_payload_variant) {
				return -EINVAL;
			}
			seen_payload_variant = true;
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
			info->portnum = 0U;
			info->payload = NULL;
			info->payload_len = 0U;
			break;
		default:
			if (pb_skip_value(&cur, wt) < 0) {
				return -EINVAL;
			}
			break;
		}
	}

	return 0;
}

bool adapter_utf8_is_valid(const uint8_t *data, size_t len)
{
	size_t pos = 0U;

	while (pos < len) {
		uint8_t c = data[pos++];
		size_t need;
		uint32_t cp;

		if (c <= 0x7fU) {
			continue;
		}
		if (c >= 0xc2U && c <= 0xdfU) {
			need = 1U;
			cp = c & 0x1fU;
		} else if (c >= 0xe0U && c <= 0xefU) {
			need = 2U;
			cp = c & 0x0fU;
		} else if (c >= 0xf0U && c <= 0xf4U) {
			need = 3U;
			cp = c & 0x07U;
		} else {
			return false;
		}

		if (len - pos < need) {
			return false;
		}
		for (size_t i = 0U; i < need; i++) {
			uint8_t cc = data[pos++];

			if ((cc & 0xc0U) != 0x80U) {
				return false;
			}
			cp = (cp << 6) | (uint32_t)(cc & 0x3fU);
		}

		if ((need == 2U && cp < 0x800U) ||
		    (need == 3U && cp < 0x10000U) ||
		    (cp >= 0xd800U && cp <= 0xdfffU) ||
		    cp > 0x10ffffU) {
			return false;
		}
	}

	return true;
}
