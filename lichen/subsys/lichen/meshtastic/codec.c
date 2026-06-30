/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <lichen/meshtastic/codec.h>

#define PB_WT_VARINT 0U
#define PB_WT_LEN 2U
#define PB_WT_64BIT 1U
#define PB_WT_32BIT 5U

#define PB_MAX_FIELD_NUMBER 536870911ULL

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
