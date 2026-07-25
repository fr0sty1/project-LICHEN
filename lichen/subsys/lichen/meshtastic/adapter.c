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

static bool resolve_text_destination(
	struct lichen_meshtastic_adapter *adapter,
	struct lichen_meshtastic_adapter_packet_info *packet)
{
	struct lichen_meshtastic_local_info info;
	struct nodedb_peer_state peers;
	int ret;

	packet->has_to_peer = false;

	if (!packet->has_to) {
		return false;
	}
	if (packet->to == MESHTASTIC_BROADCAST_NODE) {
		return true;
	}

	ret = adapter_local_info(adapter, &info);
	if (ret < 0 || packet->to == info.node_num) {
		return false;
	}
	adapter_nodedb_peer_snapshot(adapter, info.node_num, &peers);
	if (adapter_node_num_collided(&peers, packet->to)) {
		return false;
	}
	for (size_t i = 0U; i < peers.emit_count; i++) {
		if (peers.node_nums[i] != packet->to) {
			continue;
		}
		memcpy(packet->to_eui64, peers.peers[i].eui64,
		       sizeof(packet->to_eui64));
		adapter_peer_eui64_to_iid(packet->to_eui64, packet->to_iid);
		packet->has_to_peer = true;
		return true;
	}

	return false;
}

static bool text_packet_supported(
	struct lichen_meshtastic_adapter *adapter,
	struct lichen_meshtastic_adapter_packet_info *packet)
{
	if (packet->payload == NULL || packet->payload_len == 0U ||
	    packet->payload_len > LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX ||
	    !adapter_utf8_is_valid(packet->payload, packet->payload_len)) {
		return false;
	}

	if (!resolve_text_destination(adapter, packet)) {
		return false;
	}

	if (packet->has_channel &&
	    packet->channel != MESHTASTIC_PRIMARY_CHANNEL) {
		return false;
	}

	return true;
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

#define ADMIN_GET_DEVICE_METADATA_RESPONSE_FIELD 13U

	ret = adapter_local_info(adapter, &info);
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

	from_radio_id = adapter_next_from_radio_id(adapter->from_radio_id);
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
	ret = adapter_enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	adapter->from_radio_id = from_radio_id;
	return 0;
}

static int dispatch_packet(struct lichen_meshtastic_adapter *adapter,
			   const struct lichen_meshtastic_to_radio *msg)
{
	struct lichen_meshtastic_adapter_packet_info packet;
	int ret = adapter_parse_packet(msg->value.packet.data, msg->value.packet.len, &packet);

	adapter->stats.packet_count++;
	if (ret < 0) {
		adapter->stats.malformed_count++;
		return adapter_queue_status(adapter, QUEUE_STATUS_MALFORMED, NULL);
	}

	switch (packet.kind) {
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP:
		adapter->stats.text_packet_count++;
		if (!text_packet_supported(adapter, &packet)) {
			adapter->stats.unsupported_packet_count++;
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		if (adapter->ops.handle_text == NULL) {
			adapter->stats.unsupported_packet_count++;
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		ret = adapter->ops.handle_text(&packet, adapter->ops.user_data);
		if (ret < 0) {
			adapter->stats.unsupported_packet_count++;
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
		}
		return adapter_queue_status(adapter, QUEUE_STATUS_OK, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_POSITION_APP:
		adapter->stats.position_packet_count++;
		if (adapter->ops.handle_location == NULL) {
			adapter->stats.unsupported_packet_count++;
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED,
					    &packet);
		}
		ret = adapter->ops.handle_location(&packet,
						   adapter->ops.user_data);
		if (ret < 0) {
			adapter->stats.unsupported_packet_count++;
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED,
					    &packet);
		}
		return adapter_queue_status(adapter, QUEUE_STATUS_OK, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_ADMIN_GET_DEVICE_METADATA:
		return enqueue_admin_metadata_response(adapter, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED:
		adapter->stats.malformed_count++;
		return adapter_queue_status(adapter, QUEUE_STATUS_MALFORMED, &packet);
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED:
	case LICHEN_MESHTASTIC_ADAPTER_PACKET_UNKNOWN:
	default:
		adapter->stats.unsupported_packet_count++;
		return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, &packet);
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
	k_mutex_init(&adapter->lock);
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
	    !adapter_utf8_is_valid(event->payload, event->payload_len)) {
		return -EMSGSIZE;
	}
	if (adapter->disconnected) {
		return -ENOTCONN;
	}
	if (adapter->ops.enqueue_from_radio == NULL) {
		return -ENOTSUP;
	}

	packet = (struct lichen_meshtastic_text_packet){
		.from = event->from,
		.to = event->to,
		.id = event->has_id ?
		      event->id : adapter_next_from_radio_id(adapter->from_radio_id),
		.payload = event->payload,
		.payload_len = event->payload_len,
	};

	if (!event->has_id) {
		from_radio_id = packet.id;
	} else {
		from_radio_id = 0;
	}

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
	ret = adapter_enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	if (!event->has_id) {
		adapter->from_radio_id = from_radio_id;
	}
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

	packet = (struct lichen_meshtastic_routing_packet){
		.from = event->from,
		.to = event->to,
		.id = event->has_id ?
		      event->id : adapter_next_from_radio_id(adapter->from_radio_id),
		.request_id = event->request_id,
		.error_reason = event->error_reason,
		.has_error_reason = event->has_error_reason,
	};

	if (!event->has_id) {
		from_radio_id = packet.id;
	} else {
		from_radio_id = 0;
	}

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
	ret = adapter_enqueue(adapter, from_radio, (size_t)ret);
	if (ret < 0) {
		return ret;
	}

	if (!event->has_id) {
		adapter->from_radio_id = from_radio_id;
	}
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
			return adapter_queue_status(adapter, QUEUE_STATUS_UNSUPPORTED, NULL);
		}
		adapter->stats.malformed_count++;
		return ret;
	}

	switch (msg.type) {
	case LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT:
		adapter->stats.heartbeat_count++;
		if (adapter->ops.heartbeat_queue_status) {
			return adapter_queue_status(adapter, QUEUE_STATUS_OK, NULL);
		}
		return LICHEN_MESHTASTIC_ADAPTER_DISPATCHED;
	case LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID:
	{
		uint32_t now_ms = k_uptime_get_32();
		uint32_t elapsed = now_ms - adapter->want_config_last_ms;

		adapter->stats.want_config_count++;
		if (elapsed < LICHEN_MESHTASTIC_WANT_CONFIG_RATE_LIMIT_MS) {
			adapter->stats.want_config_rate_limited_count++;
			return LICHEN_MESHTASTIC_ADAPTER_DISPATCHED;
		}
		adapter->want_config_last_ms = now_ms;
		return adapter_dispatch_want_config(adapter, msg.value.want_config_id);
	}
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
	return &adapter->stats;
}

bool lichen_meshtastic_adapter_disconnected(
	const struct lichen_meshtastic_adapter *adapter)
{
	__ASSERT_NO_MSG(adapter != NULL);
	return adapter->disconnected;
}
