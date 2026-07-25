/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include <lichen/meshtastic/adapter.h>
#include <lichen/meshtastic/pb_internal.h>

#include "adapter_internal.h"

static const enum lichen_meshtastic_config_section s_config_sections[] = {
	LICHEN_MESHTASTIC_CONFIG_DEVICE,
	LICHEN_MESHTASTIC_CONFIG_POSITION,
	LICHEN_MESHTASTIC_CONFIG_POWER,
	LICHEN_MESHTASTIC_CONFIG_NETWORK,
	LICHEN_MESHTASTIC_CONFIG_DISPLAY,
	LICHEN_MESHTASTIC_CONFIG_LORA,
	LICHEN_MESHTASTIC_CONFIG_BLUETOOTH,
	LICHEN_MESHTASTIC_CONFIG_SECURITY,
	LICHEN_MESHTASTIC_CONFIG_DEVICE_UI,
};

BUILD_ASSERT(ARRAY_SIZE(s_config_sections) ==
	     LICHEN_MESHTASTIC_STATIC_SYNC_CONFIG_SECTIONS);
BUILD_ASSERT(LICHEN_MESHTASTIC_NODE_NAME_MAX >= 1U,
	     "name buffer must have space for terminator");
BUILD_ASSERT(LICHEN_MESHTASTIC_STATIC_SYNC_FIXED_RECORDS == 5U,
	     "update LICHEN_MESHTASTIC_STATIC_SYNC_FIXED_RECORDS to match "
	     "the 5 fixed messages in enqueue_static_sync()");

int adapter_enqueue(struct lichen_meshtastic_adapter *adapter,
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

static uint32_t static_sync_record_count(void)
{
	return LICHEN_MESHTASTIC_STATIC_SYNC_RECORDS;
}

uint32_t adapter_next_from_radio_id(uint32_t current)
{
	uint32_t next = current + 1U;
	return next != 0U ? next : 1U;
}

static uint32_t node_sync_record_count(const struct nodedb_peer_state *state)
{
	return LICHEN_MESHTASTIC_NODE_SYNC_RECORDS((uint32_t)state->emit_count);
}

static uint32_t want_config_record_count(
	uint32_t nonce, const struct nodedb_peer_state *state)
{
	uint32_t records = LICHEN_MESHTASTIC_CONFIG_COMPLETE_RECORDS;

	if (nonce == MESHTASTIC_CONFIG_STAGE_STATIC) {
		records += static_sync_record_count();
	} else if (nonce == MESHTASTIC_CONFIG_STAGE_NODEDB) {
		records += node_sync_record_count(state);
	} else {
		records += static_sync_record_count() +
			   node_sync_record_count(state);
	}

	return records;
}

int adapter_require_queue_space(struct lichen_meshtastic_adapter *adapter,
				uint32_t records)
{
	uint32_t free_slots;

	if (adapter->ops.enqueue_from_radio == NULL ||
	    adapter->ops.queue_free == NULL) {
		return 0;
	}

	free_slots = adapter->ops.queue_free(adapter->ops.user_data);
	if (free_slots < records) {
		adapter->stats.enqueue_fail_count++;
		return -ENOMEM;
	}

	return 0;
}

int adapter_queue_status(struct lichen_meshtastic_adapter *adapter, uint32_t res,
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

	return adapter_enqueue(adapter, buf, (size_t)ret);
}

static int config_complete(struct lichen_meshtastic_adapter *adapter, uint32_t nonce)
{
	uint8_t buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret = lichen_meshtastic_encode_from_radio_config_complete(nonce, buf,
								      sizeof(buf));

	if (ret < 0) {
		return ret;
	}
	return adapter_enqueue(adapter, buf, (size_t)ret);
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
	return adapter_enqueue(adapter, buf, (size_t)ret);
}

int adapter_enqueue_static_sync(struct lichen_meshtastic_adapter *adapter,
				const struct lichen_meshtastic_local_info *info)
{
	uint8_t payload[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	int ret;
	int enqueue_ret;

	ret = lichen_meshtastic_encode_my_info_payload(info, payload,
						       sizeof(payload));
	if (ret < 0) {
		return ret;
	}
	enqueue_ret = enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO,
				       payload, (size_t)ret);
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}

	ret = lichen_meshtastic_encode_metadata_payload(info, payload,
							sizeof(payload));
	if (ret < 0) {
		return ret;
	}
	enqueue_ret = enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_METADATA,
				       payload, (size_t)ret);
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}

	ret = lichen_meshtastic_encode_region_presets_payload(info, payload,
							      sizeof(payload));
	if (ret < 0) {
		return ret;
	}
	enqueue_ret = enqueue_payload(adapter,
				       LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS,
				       payload, (size_t)ret);
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}

	ret = lichen_meshtastic_encode_channel_payload(info, payload, sizeof(payload));
	if (ret < 0) {
		return ret;
	}
	enqueue_ret = enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL,
				       payload, (size_t)ret);
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}

	for (size_t i = 0U; i < ARRAY_SIZE(s_config_sections); i++) {
		ret = lichen_meshtastic_encode_config_section_payload(
			s_config_sections[i], info, payload, sizeof(payload));
		if (ret < 0) {
			return ret;
		}
		enqueue_ret = enqueue_payload(adapter, LICHEN_MESHTASTIC_FROM_RADIO_CONFIG,
				    payload, (size_t)ret);
		if (enqueue_ret < 0) {
			return enqueue_ret;
		}
	}

	ret = lichen_meshtastic_encode_module_config_payload(info, payload,
							     sizeof(payload));
	if (ret < 0) {
		return ret;
	}
	enqueue_ret = enqueue_payload(adapter,
				       LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG,
				       payload, (size_t)ret);
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}

	return 0;
}

static void peer_info_from_snapshot(
	const struct lichen_meshtastic_peer_snapshot *peer, uint32_t node_num,
	const struct lichen_meshtastic_local_info *local,
	struct lichen_meshtastic_local_info *info)
{
	memset(info, 0, sizeof(*info));
	info->node_num = node_num;
	info->min_app_version = local->min_app_version;
	info->nodedb_count = local->nodedb_count;
	info->long_name = peer->has_long_name && peer->long_name[0] != '\0' ?
				  peer->long_name : "LICHEN Peer";
	info->short_name = "PEER";
	info->firmware_version = local->firmware_version;
	info->pio_env = local->pio_env;
	info->device_id = peer->eui64;
	info->device_id_len = sizeof(peer->eui64);
	info->has_lora = true;
	if (peer->has_hop_distance) {
		info->has_hops_away = true;
		info->hops_away = peer->hop_distance;
	}
}

static int enqueue_single_node_info(
	struct lichen_meshtastic_adapter *adapter,
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

int adapter_enqueue_node_sync(struct lichen_meshtastic_adapter *adapter,
			      const struct lichen_meshtastic_local_info *info,
			      const struct nodedb_peer_state *state)
{
	int ret = enqueue_single_node_info(adapter, info);

	if (ret < 0) {
		return ret;
	}

	for (size_t i = 0U; i < state->emit_count; i++) {
		struct lichen_meshtastic_local_info peer_info;

		peer_info_from_snapshot(&state->peers[i], state->node_nums[i],
					info, &peer_info);
		ret = enqueue_single_node_info(adapter, &peer_info);
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}

int adapter_dispatch_want_config(struct lichen_meshtastic_adapter *adapter,
				 uint32_t nonce)
{
	struct lichen_meshtastic_local_info info;
	struct nodedb_peer_state peers;
	int ret;

	ret = adapter_local_info(adapter, &info);
	if (ret < 0) {
		return ret;
	}
	adapter_nodedb_peer_snapshot(adapter, info.node_num, &peers);
	info.nodedb_count = 1U + (uint32_t)peers.emit_count;

	ret = adapter_require_queue_space(adapter, want_config_record_count(nonce, &peers));
	if (ret < 0) {
		return ret;
	}
	adapter->stats.nodedb_peer_collision_count += peers.collision_count;
	adapter->stats.nodedb_peer_omitted_count += peers.omitted_count;

	if (nonce == MESHTASTIC_CONFIG_STAGE_STATIC) {
		ret = adapter_enqueue_static_sync(adapter, &info);
	} else if (nonce == MESHTASTIC_CONFIG_STAGE_NODEDB) {
		ret = adapter_enqueue_node_sync(adapter, &info, &peers);
	} else {
		ret = adapter_enqueue_static_sync(adapter, &info);
		if (ret == 0) {
			ret = adapter_enqueue_node_sync(adapter, &info, &peers);
		}
	}
	if (ret < 0) {
		return ret;
	}
	ret = config_complete(adapter, nonce);
	if (ret < 0) {
		return ret;
	}
	return 0;
}
