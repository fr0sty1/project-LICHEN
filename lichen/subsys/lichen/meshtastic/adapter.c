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

#define MESHTASTIC_STREAM_MAGIC0 0x94U
#define MESHTASTIC_STREAM_MAGIC1 0xc3U

#define MESH_PACKET_FROM_FIELD 1U
#define MESH_PACKET_TO_FIELD 2U
#define MESH_PACKET_CHANNEL_FIELD 3U
#define MESH_PACKET_DECODED_FIELD 4U
#define MESH_PACKET_ENCRYPTED_FIELD 5U
#define MESH_PACKET_ID_FIELD 6U
#define MESH_PACKET_WANT_ACK_FIELD 10U

#define DATA_PORTNUM_FIELD 1U
#define DATA_PAYLOAD_FIELD 2U
#define DATA_REQUEST_ID_FIELD 6U

#define ADMIN_GET_OWNER_REQUEST_FIELD 3U
#define ADMIN_GET_DEVICE_METADATA_REQUEST_FIELD 12U
#define ADMIN_GET_DEVICE_METADATA_RESPONSE_FIELD 13U
#define ADMIN_SET_OWNER_FIELD 32U
#define ADMIN_SESSION_PASSKEY_FIELD 101U
#define ADMIN_OTA_REQUEST_FIELD 102U
#define ADMIN_SENSOR_CONFIG_FIELD 103U
#define ADMIN_LOCKDOWN_AUTH_FIELD 104U

#define MESHTASTIC_PORTNUM_UNKNOWN_APP 0U
#define MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP 1U
#define MESHTASTIC_PORTNUM_REMOTE_HARDWARE_APP 2U
#define MESHTASTIC_PORTNUM_POSITION_APP 3U
#define MESHTASTIC_PORTNUM_NODEINFO_APP 4U
#define MESHTASTIC_PORTNUM_ROUTING_APP 5U
#define MESHTASTIC_PORTNUM_ADMIN_APP 6U
#define MESHTASTIC_PORTNUM_TEXT_MESSAGE_COMPRESSED_APP 7U
#define MESHTASTIC_PORTNUM_WAYPOINT_APP 8U
#define MESHTASTIC_PORTNUM_AUDIO_APP 9U
#define MESHTASTIC_PORTNUM_DETECTION_SENSOR_APP 10U
#define MESHTASTIC_PORTNUM_REPLY_APP 32U
#define MESHTASTIC_PORTNUM_IP_TUNNEL_APP 33U
#define MESHTASTIC_PORTNUM_PAXCOUNTER_APP 34U
#define MESHTASTIC_PORTNUM_SERIAL_APP 64U
#define MESHTASTIC_PORTNUM_STORE_FORWARD_APP 65U
#define MESHTASTIC_PORTNUM_RANGE_TEST_APP 66U
#define MESHTASTIC_PORTNUM_TELEMETRY_APP 67U
#define MESHTASTIC_PORTNUM_ZPS_APP 68U
#define MESHTASTIC_PORTNUM_SIMULATOR_APP 69U
#define MESHTASTIC_PORTNUM_TRACEROUTE_APP 70U
#define MESHTASTIC_PORTNUM_NEIGHBORINFO_APP 71U
#define MESHTASTIC_PORTNUM_ATAK_PLUGIN 72U
#define MESHTASTIC_PORTNUM_MAP_REPORT_APP 73U
#define MESHTASTIC_PORTNUM_PRIVATE_APP 256U
#define MESHTASTIC_PORTNUM_ATAK_FORWARDER 257U
#define MESHTASTIC_PORTNUM_MAX_SENTINEL 511U
#define MESHTASTIC_BROADCAST_NODE 0xffffffffU
#define MESHTASTIC_PRIMARY_CHANNEL 0U
#define QUEUE_STATUS_OK 0U
#define QUEUE_STATUS_UNSUPPORTED 2U
#define QUEUE_STATUS_MALFORMED 3U

#define MESHTASTIC_CONFIG_STAGE_STATIC 69420U
#define MESHTASTIC_CONFIG_STAGE_NODEDB 69421U
#define LICHEN_BRAND "LICHEN"
#define MESHTASTIC_BRAND "meshtastic"

#define PB_WT_VARINT 0U
#define PB_WT_64BIT 1U
#define PB_WT_LEN 2U
#define PB_WT_32BIT 5U

struct pb_cursor {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static const struct lichen_meshtastic_adapter_unsupported_operation
	unsupported_operations[] = {
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_RADIO_CONFIG_WRITE,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_CHANNEL_CONFIG_WRITE,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_UNKNOWN_APP,
		.portnum = MESHTASTIC_PORTNUM_UNKNOWN_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ADMIN_COMMAND,
		.portnum = MESHTASTIC_PORTNUM_ADMIN_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_NODEINFO_UPDATE,
		.portnum = MESHTASTIC_PORTNUM_NODEINFO_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ROUTING_APP_TO_NODE,
		.portnum = MESHTASTIC_PORTNUM_ROUTING_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_COMPRESSED_TEXT,
		.portnum = MESHTASTIC_PORTNUM_TEXT_MESSAGE_COMPRESSED_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_WAYPOINT,
		.portnum = MESHTASTIC_PORTNUM_WAYPOINT_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_AUDIO,
		.portnum = MESHTASTIC_PORTNUM_AUDIO_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_DETECTION_SENSOR,
		.portnum = MESHTASTIC_PORTNUM_DETECTION_SENSOR_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_REPLY,
		.portnum = MESHTASTIC_PORTNUM_REPLY_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_IP_TUNNEL,
		.portnum = MESHTASTIC_PORTNUM_IP_TUNNEL_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_PAXCOUNTER,
		.portnum = MESHTASTIC_PORTNUM_PAXCOUNTER_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_SERIAL,
		.portnum = MESHTASTIC_PORTNUM_SERIAL_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_HARDWARE,
		.portnum = MESHTASTIC_PORTNUM_REMOTE_HARDWARE_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_POSITION_UPDATE,
		.portnum = MESHTASTIC_PORTNUM_POSITION_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_TELEMETRY_MODULE,
		.portnum = MESHTASTIC_PORTNUM_TELEMETRY_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ZPS,
		.portnum = MESHTASTIC_PORTNUM_ZPS_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_SIMULATOR,
		.portnum = MESHTASTIC_PORTNUM_SIMULATOR_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_NEIGHBORINFO,
		.portnum = MESHTASTIC_PORTNUM_NEIGHBORINFO_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN,
		.portnum = MESHTASTIC_PORTNUM_ATAK_PLUGIN,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_CANNED_MESSAGE_MODULE,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD,
		.portnum = MESHTASTIC_PORTNUM_STORE_FORWARD_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_TRACEROUTE,
		.portnum = MESHTASTIC_PORTNUM_TRACEROUTE_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_RANGE_TEST,
		.portnum = MESHTASTIC_PORTNUM_RANGE_TEST_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_MAP_REPORT,
		.portnum = MESHTASTIC_PORTNUM_MAP_REPORT_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_PRIVATE_APP,
		.portnum = MESHTASTIC_PORTNUM_PRIVATE_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_FORWARDER,
		.portnum = MESHTASTIC_PORTNUM_ATAK_FORWARDER,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_MAX_SENTINEL,
		.portnum = MESHTASTIC_PORTNUM_MAX_SENTINEL,
		.has_portnum = true,
	},
};

static int pb_read_varint(struct pb_cursor *cur, uint64_t *value)
{
	uint64_t out = 0U;
	uint8_t shift = 0U;

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
	int ret = pb_read_varint(cur, &key);

	if (ret < 0 || (key >> 3) == 0U || (key >> 3) > UINT32_MAX) {
		return -EINVAL;
	}

	*field = (uint32_t)(key >> 3);
	*wire_type = (uint32_t)(key & 0x07U);
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
	default:
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

static int pb_write_varint(uint8_t *buf, size_t cap, size_t *pos, uint64_t value)
{
	do {
		uint8_t byte;

		if (*pos >= cap) {
			return -EMSGSIZE;
		}
		byte = (uint8_t)(value & 0x7fU);
		value >>= 7;
		if (value != 0U) {
			byte |= 0x80U;
		}
		buf[(*pos)++] = byte;
	} while (value != 0U);

	return 0;
}

static int pb_write_key(uint8_t *buf, size_t cap, size_t *pos,
			uint32_t field, uint32_t wire_type)
{
	return pb_write_varint(buf, cap, pos,
			       ((uint64_t)field << 3) | (uint64_t)wire_type);
}

static int pb_write_varint_field(uint8_t *buf, size_t cap, size_t *pos,
				 uint32_t field, uint64_t value)
{
	if (pb_write_key(buf, cap, pos, field, PB_WT_VARINT) < 0 ||
	    pb_write_varint(buf, cap, pos, value) < 0) {
		return -EMSGSIZE;
	}
	return 0;
}

static int pb_write_fixed32_field(uint8_t *buf, size_t cap, size_t *pos,
				  uint32_t field, uint32_t value)
{
	if (pb_write_key(buf, cap, pos, field, PB_WT_32BIT) < 0 ||
	    cap - *pos < sizeof(uint32_t)) {
		return -EMSGSIZE;
	}
	sys_put_le32(value, &buf[*pos]);
	*pos += sizeof(uint32_t);
	return 0;
}

static int pb_write_len_field(uint8_t *buf, size_t cap, size_t *pos,
			      uint32_t field, const uint8_t *data, size_t len)
{
	if (pb_write_key(buf, cap, pos, field, PB_WT_LEN) < 0 ||
	    pb_write_varint(buf, cap, pos, len) < 0 ||
	    len > cap - *pos) {
		return -EMSGSIZE;
	}
	if (len > 0U) {
		memcpy(&buf[*pos], data, len);
	}
	*pos += len;
	return 0;
}

static bool admin_payload_variant_field(uint32_t field)
{
	/* Current Meshtastic AdminMessage.payload_variant fields. Field 101 is
	 * session_passkey context, not a oneof arm; unknown future fields must
	 * be skipped rather than overriding a previous known oneof arm.
	 */
	return (field >= 1U && field <= 8U) ||
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
			info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP;
		} else if (info->portnum == MESHTASTIC_PORTNUM_ADMIN_APP &&
			   info->payload != NULL) {
			if (!parse_admin_payload(info->payload, info->payload_len,
						 &info->kind)) {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED;
			}
		} else {
			info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
		}
	}

	return 0;
}

static int parse_packet(const uint8_t *packet, size_t len,
			struct lichen_meshtastic_adapter_packet_info *info)
{
	struct pb_cursor cur = { .buf = packet, .len = len };

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
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			if (parse_data(data, data_len, info) < 0) {
				return -EINVAL;
			}
			break;
		case MESH_PACKET_ENCRYPTED_FIELD:
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

static bool utf8_is_valid(const uint8_t *data, size_t len)
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

static bool text_packet_supported(
	const struct lichen_meshtastic_adapter_packet_info *packet)
{
	if (packet->payload == NULL || packet->payload_len == 0U ||
	    packet->payload_len > LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX ||
	    !utf8_is_valid(packet->payload, packet->payload_len)) {
		return false;
	}

	if (!packet->has_to || packet->to != MESHTASTIC_BROADCAST_NODE) {
		return false;
	}

	if (packet->has_channel &&
	    packet->channel != MESHTASTIC_PRIMARY_CHANNEL) {
		return false;
	}

	return true;
}

static int enqueue(struct lichen_meshtastic_adapter *adapter,
		   const uint8_t *buf, size_t len)
{
	int ret;

	if (adapter->ops.enqueue_from_radio == NULL) {
		return 0;
	}

	ret = adapter->ops.enqueue_from_radio(buf, len, adapter->ops.user_data);
	if (ret < 0) {
		adapter->stats.enqueue_fail_count++;
	}
	return ret;
}

static int queue_status(struct lichen_meshtastic_adapter *adapter, uint32_t res,
			const struct lichen_meshtastic_adapter_packet_info *packet)
{
	struct lichen_meshtastic_queue_status status = {
		.res = res,
		.maxlen = adapter->ops.queue_maxlen,
		.has_res = true,
	};
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	if (packet != NULL && packet->has_id) {
		status.mesh_packet_id = packet->id;
		status.has_mesh_packet_id = true;
	}
	if (adapter->ops.queue_free != NULL) {
		status.free = adapter->ops.queue_free(adapter->ops.user_data);
	} else {
		status.free = adapter->ops.queue_maxlen;
	}
	if (adapter->ops.enqueue_from_radio != NULL && status.free > 0U) {
		status.free--;
	}

	ret = lichen_meshtastic_encode_from_radio_queue_status(&status, buf,
							       sizeof(buf));
	if (ret < 0) {
		return ret;
	}

	return enqueue(adapter, buf, (size_t)ret);
}

static int config_complete(struct lichen_meshtastic_adapter *adapter, uint32_t nonce)
{
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret = lichen_meshtastic_encode_from_radio_config_complete(nonce, buf,
								      sizeof(buf));

	if (ret < 0) {
		return ret;
	}
	return enqueue(adapter, buf, (size_t)ret);
}

static bool starts_with_lichen_brand(const char *value)
{
	size_t brand_len = strlen(LICHEN_BRAND);
	char next;

	if (value == NULL || strncmp(value, LICHEN_BRAND, brand_len) != 0) {
		return false;
	}

	next = value[brand_len];
	return next == '\0' || next == ' ' || next == '-' || next == '+';
}

static bool has_compatible_firmware_brand(const char *value)
{
	size_t meshtastic_pos = 0U;

	if (!starts_with_lichen_brand(value)) {
		return false;
	}

	for (const char *p = value; *p != '\0'; p++) {
		char c = *p;

		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
		if (c == MESHTASTIC_BRAND[meshtastic_pos]) {
			meshtastic_pos++;
			if (MESHTASTIC_BRAND[meshtastic_pos] == '\0') {
				return false;
			}
		} else {
			meshtastic_pos = (c == MESHTASTIC_BRAND[0]) ? 1U : 0U;
		}
	}

	return true;
}

static int local_info(struct lichen_meshtastic_adapter *adapter,
		      struct lichen_meshtastic_local_info *info)
{
	static const char default_name[] = "LICHEN Node";
	static const char default_short_name[] = "LICH";
	static const char default_fw[] = "LICHEN Zephyr compat 0.0.0+unknown";
	static const char default_env[] = "zephyr";

	memset(info, 0, sizeof(*info));
	info->node_num = 0x4c494348U;
	info->min_app_version = 30200U;
	info->nodedb_count = 1U;
	info->long_name = default_name;
	info->short_name = default_short_name;
	info->firmware_version = default_fw;
	info->pio_env = default_env;

	if (adapter->ops.get_local_info != NULL) {
		int ret = adapter->ops.get_local_info(info, adapter->ops.user_data);

		if (ret < 0) {
			return ret;
		}
	}

	if (info->node_num == 0U) {
		info->node_num = 0x4c494348U;
	}
	if (info->min_app_version == 0U) {
		info->min_app_version = 30200U;
	}
	if (info->nodedb_count == 0U) {
		info->nodedb_count = 1U;
	}
	if (info->long_name == NULL || info->long_name[0] == '\0') {
		info->long_name = default_name;
	}
	if (info->short_name == NULL || info->short_name[0] == '\0') {
		info->short_name = default_short_name;
	}
	if (!has_compatible_firmware_brand(info->firmware_version)) {
		info->firmware_version = default_fw;
	}
	if (info->pio_env == NULL || info->pio_env[0] == '\0') {
		info->pio_env = default_env;
	}

	return 0;
}

static int enqueue_payload(struct lichen_meshtastic_adapter *adapter,
			   enum lichen_meshtastic_from_radio_message message,
			   const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret = lichen_meshtastic_encode_from_radio_message(
		message, payload, payload_len, buf, sizeof(buf));

	if (ret < 0) {
		return ret;
	}
	return enqueue(adapter, buf, (size_t)ret);
}

static int enqueue_static_sync(struct lichen_meshtastic_adapter *adapter,
			       const struct lichen_meshtastic_local_info *info)
{
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;

	ret = lichen_meshtastic_encode_my_info_payload(info, payload,
						       sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	ret = lichen_meshtastic_encode_metadata_payload(info, payload,
							sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_METADATA,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	ret = lichen_meshtastic_encode_region_presets_payload(info, payload,
							      sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter,
				       LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	ret = lichen_meshtastic_encode_config_payload(info, payload, sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	ret = lichen_meshtastic_encode_module_config_payload(info, payload,
							     sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter,
				       LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	ret = lichen_meshtastic_encode_channel_payload(info, payload, sizeof(payload));
	if (ret < 0 || enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL,
				       payload, (size_t)ret) < 0) {
		return ret < 0 ? ret : -ENOMEM;
	}

	return 0;
}

static int enqueue_node_sync(struct lichen_meshtastic_adapter *adapter,
			     const struct lichen_meshtastic_local_info *info)
{
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret = lichen_meshtastic_encode_node_info_payload(info, payload,
							     sizeof(payload));

	if (ret < 0) {
		return ret;
	}
	return enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO,
			       payload, (size_t)ret);
}

static int enqueue_admin_metadata_response(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_adapter_packet_info *packet)
{
	struct lichen_meshtastic_local_info info;
	uint8_t metadata[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t admin[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t data[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t mesh_packet[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t from_radio[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint32_t from_radio_id;
	size_t admin_len = 0U;
	size_t data_len = 0U;
	size_t packet_len = 0U;
	int ret;

	ret = local_info(adapter, &info);
	if (ret < 0) {
		return ret;
	}

	ret = lichen_meshtastic_encode_metadata_payload(&info, metadata,
							sizeof(metadata));
	if (ret < 0) {
		return ret;
	}
	if (pb_write_len_field(admin, sizeof(admin), &admin_len,
			       ADMIN_GET_DEVICE_METADATA_RESPONSE_FIELD,
			       metadata, (size_t)ret) < 0 ||
	    pb_write_varint_field(data, sizeof(data), &data_len,
				  DATA_PORTNUM_FIELD,
				  MESHTASTIC_PORTNUM_ADMIN_APP) < 0 ||
	    pb_write_len_field(data, sizeof(data), &data_len,
			       DATA_PAYLOAD_FIELD, admin, admin_len) < 0) {
		return -EMSGSIZE;
	}
	if (packet->has_id &&
	    pb_write_fixed32_field(data, sizeof(data), &data_len,
				   DATA_REQUEST_ID_FIELD, packet->id) < 0) {
		return -EMSGSIZE;
	}

	from_radio_id = adapter->from_radio_id + 1U;
	if (pb_write_fixed32_field(mesh_packet, sizeof(mesh_packet), &packet_len,
				   MESH_PACKET_FROM_FIELD, info.node_num) < 0 ||
	    pb_write_fixed32_field(mesh_packet, sizeof(mesh_packet), &packet_len,
				   MESH_PACKET_TO_FIELD,
				   packet->has_from ? packet->from :
						      MESHTASTIC_BROADCAST_NODE) < 0 ||
	    pb_write_len_field(mesh_packet, sizeof(mesh_packet), &packet_len,
			       MESH_PACKET_DECODED_FIELD, data, data_len) < 0 ||
	    pb_write_fixed32_field(mesh_packet, sizeof(mesh_packet), &packet_len,
				   MESH_PACKET_ID_FIELD, from_radio_id) < 0) {
		return -EMSGSIZE;
	}

	ret = lichen_meshtastic_encode_from_radio_packet(from_radio_id,
							 mesh_packet,
							 packet_len,
							 from_radio,
							 sizeof(from_radio));
	if (ret < 0) {
		return ret;
	}
	ret = enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	adapter->from_radio_id = from_radio_id;
	return 0;
}

static int dispatch_want_config(struct lichen_meshtastic_adapter *adapter,
				uint32_t nonce)
{
	struct lichen_meshtastic_local_info info;
	int ret = local_info(adapter, &info);

	if (ret < 0) {
		return ret;
	}

	if (nonce == MESHTASTIC_CONFIG_STAGE_STATIC) {
		ret = enqueue_static_sync(adapter, &info);
	} else if (nonce == MESHTASTIC_CONFIG_STAGE_NODEDB) {
		ret = enqueue_node_sync(adapter, &info);
	} else {
		ret = enqueue_static_sync(adapter, &info);
		if (ret == 0) {
			ret = enqueue_node_sync(adapter, &info);
		}
	}
	if (ret < 0) {
		return ret;
	}
	return config_complete(adapter, nonce);
}

static int dispatch_packet(struct lichen_meshtastic_adapter *adapter,
			   const struct lichen_meshtastic_to_radio *msg)
{
	struct lichen_meshtastic_adapter_packet_info packet;
	int ret = parse_packet(msg->value.packet.data, msg->value.packet.len, &packet);

	adapter->stats.packet_count++;
	if (ret < 0) {
		adapter->stats.malformed_count++;
		return queue_status(adapter, QUEUE_STATUS_MALFORMED, NULL);
	}

	switch (packet.kind) {
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP:
		adapter->stats.text_packet_count++;
		if (!text_packet_supported(&packet)) {
			adapter->stats.unsupported_packet_count++;
			return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		if (adapter->ops.handle_text == NULL) {
			adapter->stats.unsupported_packet_count++;
			return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		ret = adapter->ops.handle_text(&packet, adapter->ops.user_data);
		if (ret < 0) {
			adapter->stats.unsupported_packet_count++;
			return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		return queue_status(adapter, QUEUE_STATUS_OK, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_ADMIN_GET_DEVICE_METADATA:
		return enqueue_admin_metadata_response(adapter, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED:
		adapter->stats.malformed_count++;
		return queue_status(adapter, QUEUE_STATUS_MALFORMED, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED:
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_UNKNOWN:
	default:
		adapter->stats.unsupported_packet_count++;
		return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
	}
}

void lichen_meshtastic_adapter_init(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_adapter_ops *ops)
{
	if (adapter == NULL) {
		return;
	}

	memset(adapter, 0, sizeof(*adapter));
	if (ops != NULL) {
		adapter->ops = *ops;
	}
}

void lichen_meshtastic_adapter_reset(struct lichen_meshtastic_adapter *adapter)
{
	struct lichen_meshtastic_adapter_ops ops;

	if (adapter == NULL) {
		return;
	}

	ops = adapter->ops;
	lichen_meshtastic_adapter_init(adapter, &ops);
}

int lichen_meshtastic_adapter_emit_text(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_incoming_text *event)
{
	struct lichen_meshtastic_text_packet packet;
	uint8_t mesh_packet[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t from_radio[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint32_t from_radio_id;
	int ret;

	if (adapter == NULL || event == NULL ||
	    (event->payload == NULL && event->payload_len > 0U)) {
		return -EINVAL;
	}
	if (event->payload_len == 0U ||
	    event->payload_len > LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX ||
	    !utf8_is_valid(event->payload, event->payload_len)) {
		return -EMSGSIZE;
	}
	if (adapter->disconnected) {
		return -ENOTCONN;
	}
	if (adapter->ops.enqueue_from_radio == NULL) {
		return -ENOTSUP;
	}

	from_radio_id = adapter->from_radio_id + 1U;
	packet = (struct lichen_meshtastic_text_packet){
		.from = event->from,
		.to = event->to,
		.id = event->has_id ? event->id : from_radio_id,
		.payload = event->payload,
		.payload_len = event->payload_len,
	};

	ret = lichen_meshtastic_encode_text_packet(&packet, mesh_packet,
						   sizeof(mesh_packet));
	if (ret < 0) {
		return ret;
	}
	ret = lichen_meshtastic_encode_from_radio_packet(from_radio_id,
							 mesh_packet,
							 (size_t)ret,
							 from_radio,
							 sizeof(from_radio));
	if (ret < 0) {
		return ret;
	}
	ret = enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	adapter->from_radio_id = from_radio_id;
	adapter->stats.incoming_text_count++;
	return 0;
}

int lichen_meshtastic_adapter_emit_status(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_incoming_status *event)
{
	struct lichen_meshtastic_routing_packet packet;
	uint8_t mesh_packet[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint8_t from_radio[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint32_t from_radio_id;
	int ret;

	if (adapter == NULL || event == NULL) {
		return -EINVAL;
	}
	if (adapter->disconnected) {
		return -ENOTCONN;
	}
	if (adapter->ops.enqueue_from_radio == NULL) {
		return -ENOTSUP;
	}

	from_radio_id = adapter->from_radio_id + 1U;
	packet = (struct lichen_meshtastic_routing_packet){
		.from = event->from,
		.to = event->to,
		.id = event->has_id ? event->id : from_radio_id,
		.request_id = event->request_id,
		.error_reason = event->error_reason,
		.has_error_reason = event->has_error_reason,
	};

	ret = lichen_meshtastic_encode_routing_packet(&packet, mesh_packet,
						      sizeof(mesh_packet));
	if (ret < 0) {
		return ret;
	}
	ret = lichen_meshtastic_encode_from_radio_packet(from_radio_id,
							 mesh_packet,
							 (size_t)ret,
							 from_radio,
							 sizeof(from_radio));
	if (ret < 0) {
		return ret;
	}
	ret = enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	adapter->from_radio_id = from_radio_id;
	adapter->stats.incoming_status_count++;
	return 0;
}

int lichen_meshtastic_adapter_process_raw(
	struct lichen_meshtastic_adapter *adapter,
	const uint8_t *to_radio, size_t len)
{
	struct lichen_meshtastic_to_radio msg;
	int ret;

	if (adapter == NULL || to_radio == NULL) {
		return -EINVAL;
	}

	ret = lichen_meshtastic_decode_to_radio(to_radio, len, &msg);
	if (ret < 0) {
		if (ret == -ENODATA) {
			adapter->stats.unsupported_packet_count++;
			return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, NULL);
		}
		adapter->stats.malformed_count++;
		return ret;
	}

	switch (msg.type) {
	case LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT:
		adapter->stats.heartbeat_count++;
		if (adapter->ops.heartbeat_queue_status) {
			return queue_status(adapter, QUEUE_STATUS_OK, NULL);
		}
		return LICHEN_MESHTASTIC_ADAPTER_DISPATCHED;
	case LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID:
		adapter->stats.want_config_count++;
		return dispatch_want_config(adapter, msg.value.want_config_id);
	case LICHEN_MESHTASTIC_TO_RADIO_DISCONNECT:
		if (msg.value.disconnect) {
			adapter->stats.disconnect_count++;
			adapter->disconnected = true;
			adapter->stream_len = 0U;
			adapter->stream_expected = 0U;
			adapter->stream_header_len = 0U;
			adapter->stream_in_frame = false;
		}
		return LICHEN_MESHTASTIC_ADAPTER_DISPATCHED;
	case LICHEN_MESHTASTIC_TO_RADIO_PACKET:
		return dispatch_packet(adapter, &msg);
	case LICHEN_MESHTASTIC_TO_RADIO_UNSET:
	default:
		adapter->stats.malformed_count++;
		return -ENOTSUP;
	}
}

int lichen_meshtastic_adapter_feed_stream(
	struct lichen_meshtastic_adapter *adapter,
	const uint8_t *data, size_t len)
{
	size_t pos = 0U;
	int last = LICHEN_MESHTASTIC_ADAPTER_NEED_MORE;
	int last_error = 0;
	bool recovered = false;

	if (adapter == NULL || (data == NULL && len > 0U)) {
		return -EINVAL;
	}

	while (pos < len) {
		if (!adapter->stream_in_frame) {
			if (adapter->stream_header_len == 0U) {
				uint8_t byte = data[pos++];

				if (byte == MESHTASTIC_STREAM_MAGIC0) {
					adapter->stream_header[0] = byte;
					adapter->stream_header_len = 1U;
				} else {
					adapter->stats.malformed_count++;
					last_error = -EINVAL;
				}
				continue;
			}

			if (adapter->stream_header_len == 1U) {
				uint8_t byte = data[pos++];

				if (byte != MESHTASTIC_STREAM_MAGIC1) {
					adapter->stats.malformed_count++;
					last_error = -EINVAL;
					if (byte == MESHTASTIC_STREAM_MAGIC0) {
						adapter->stream_header[0] = byte;
						adapter->stream_header_len = 1U;
					} else {
						adapter->stream_header_len = 0U;
					}
					continue;
				}
				adapter->stream_header[1] = byte;
				adapter->stream_header_len = 2U;
				continue;
			}

			while (adapter->stream_header_len <
			       LICHEN_MESHTASTIC_STREAM_HEADER_LEN && pos < len) {
				uint8_t byte = data[pos++];
				adapter->stream_header[adapter->stream_header_len++] = byte;
			}
			if (adapter->stream_header_len <
			    LICHEN_MESHTASTIC_STREAM_HEADER_LEN) {
				break;
			}

			adapter->stream_expected =
				sys_get_be16(&adapter->stream_header[2]);
			adapter->stream_header_len = 0U;
			adapter->stream_len = 0U;
			if (adapter->stream_expected == 0U ||
			    adapter->stream_expected >
			    LICHEN_MESHTASTIC_TO_RADIO_MAX) {
				adapter->stats.malformed_count++;
				last_error = -EMSGSIZE;
				continue;
			}
			adapter->stream_in_frame = true;
		}

		size_t remaining = adapter->stream_expected - adapter->stream_len;
		size_t copy = MIN(remaining, len - pos);

		memcpy(&adapter->stream_buf[adapter->stream_len], &data[pos], copy);
		adapter->stream_len += copy;
		pos += copy;

		if (adapter->stream_len == adapter->stream_expected) {
			last = lichen_meshtastic_adapter_process_raw(
				adapter, adapter->stream_buf, adapter->stream_len);
			adapter->stream_len = 0U;
			adapter->stream_expected = 0U;
			adapter->stream_in_frame = false;
			if (last < 0) {
				last_error = last;
				last = LICHEN_MESHTASTIC_ADAPTER_NEED_MORE;
			} else {
				recovered = true;
			}
		}
	}

	if (recovered) {
		return LICHEN_MESHTASTIC_ADAPTER_DISPATCHED;
	}
	if (adapter->stream_in_frame || adapter->stream_header_len > 0U) {
		return LICHEN_MESHTASTIC_ADAPTER_NEED_MORE;
	}
	return last_error < 0 ? last_error : last;
}

const struct lichen_meshtastic_adapter_stats *
lichen_meshtastic_adapter_get_stats(
	const struct lichen_meshtastic_adapter *adapter)
{
	return adapter == NULL ? NULL : &adapter->stats;
}

bool lichen_meshtastic_adapter_disconnected(
	const struct lichen_meshtastic_adapter *adapter)
{
	return adapter != NULL && adapter->disconnected;
}

size_t lichen_meshtastic_adapter_unsupported_operations(
	const struct lichen_meshtastic_adapter_unsupported_operation **operations)
{
	if (operations != NULL) {
		*operations = unsupported_operations;
	}

	return ARRAY_SIZE(unsupported_operations);
}
