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

#define MESH_PACKET_DECODED_FIELD 4U
#define MESH_PACKET_ID_FIELD 6U

#define DATA_PORTNUM_FIELD 1U
#define DATA_PAYLOAD_FIELD 2U

#define MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP 1U
#define QUEUE_STATUS_OK 0U
#define QUEUE_STATUS_UNSUPPORTED 2U
#define QUEUE_STATUS_MALFORMED 3U

#define PB_WT_VARINT 0U
#define PB_WT_64BIT 1U
#define PB_WT_LEN 2U
#define PB_WT_32BIT 5U

struct pb_cursor {
	const uint8_t *buf;
	size_t len;
	size_t pos;
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
			if (info->portnum == MESHTASTIC_PORTNUM_TEXT_MESSAGE_APP) {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP;
			} else {
				info->kind = LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED;
			}
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
		case MESH_PACKET_DECODED_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			if (parse_data(data, data_len, info) < 0) {
				return -EINVAL;
			}
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
		if (adapter->ops.handle_text != NULL) {
			ret = adapter->ops.handle_text(&packet, adapter->ops.user_data);
			if (ret < 0) {
				return queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
			}
		}
		return queue_status(adapter, QUEUE_STATUS_OK, &packet);
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
		return config_complete(adapter, msg.value.want_config_id);
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
