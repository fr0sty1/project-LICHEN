/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include <lichen/meshtastic/adapter.h>

#include "adapter_internal.h"

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
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ALERT,
		.portnum = MESHTASTIC_PORTNUM_ALERT_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_KEY_VERIFICATION,
		.portnum = MESHTASTIC_PORTNUM_KEY_VERIFICATION_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_SHELL,
		.portnum = MESHTASTIC_PORTNUM_REMOTE_SHELL_APP,
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
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD_PLUSPLUS,
		.portnum = MESHTASTIC_PORTNUM_STORE_FORWARD_PLUSPLUS_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_NODE_STATUS,
		.portnum = MESHTASTIC_PORTNUM_NODE_STATUS_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_MESH_BEACON,
		.portnum = MESHTASTIC_PORTNUM_MESH_BEACON_APP,
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
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_POWERSTRESS,
		.portnum = MESHTASTIC_PORTNUM_POWERSTRESS_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_LORAWAN_BRIDGE,
		.portnum = MESHTASTIC_PORTNUM_LORAWAN_BRIDGE,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_RETICULUM_TUNNEL,
		.portnum = MESHTASTIC_PORTNUM_RETICULUM_TUNNEL_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_CAYENNE,
		.portnum = MESHTASTIC_PORTNUM_CAYENNE_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN_V2,
		.portnum = MESHTASTIC_PORTNUM_ATAK_PLUGIN_V2,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_LORA_OTA,
		.portnum = MESHTASTIC_PORTNUM_LORA_OTA_APP,
		.has_portnum = true,
	},
	{
		.id = LICHEN_MESHTASTIC_UNSUPPORTED_GROUPALARM,
		.portnum = MESHTASTIC_PORTNUM_GROUPALARM_APP,
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

uint32_t adapter_peer_node_num(const uint8_t eui64[8])
{
	uint32_t node_num = ((uint32_t)eui64[4] << 24) |
			    ((uint32_t)eui64[5] << 16) |
			    ((uint32_t)eui64[6] << 8) |
			    (uint32_t)eui64[7];

	return node_num != 0U ? node_num : 1U;
}

void adapter_peer_eui64_to_iid(const uint8_t eui64[8], uint8_t iid[8])
{
	memcpy(iid, eui64, 8U);
	iid[0] ^= 0x02U;
}

void adapter_sort_peers_by_eui64(struct nodedb_peer_state *state)
{
	for (size_t i = 1U; i < state->peer_count; i++) {
		struct lichen_meshtastic_peer_snapshot peer = state->peers[i];
		size_t j = i;

		while (j > 0U &&
		       memcmp(state->peers[j - 1U].eui64, peer.eui64,
			      sizeof(peer.eui64)) > 0) {
			state->peers[j] = state->peers[j - 1U];
			j--;
		}
		state->peers[j] = peer;
	}
}

static void sanitize_peer_snapshot(struct lichen_meshtastic_peer_snapshot *peer)
{
	if (peer->has_long_name) {
		peer->long_name[sizeof(peer->long_name) - 1U] = '\0';
		if (peer->long_name[0] == '\0') {
			peer->has_long_name = false;
		}
	}
}

static bool node_num_already_used(const struct nodedb_peer_state *state,
				  uint32_t self_node_num, uint32_t node_num)
{
	if (node_num == self_node_num) {
		return true;
	}
	for (size_t i = 0U; i < state->emit_count; i++) {
		if (state->node_nums[i] == node_num) {
			return true;
		}
	}
	return false;
}

static void record_collision_node_num(struct nodedb_peer_state *state,
				      uint32_t node_num)
{
	for (size_t i = 0U; i < state->collision_node_count; i++) {
		if (state->collision_node_nums[i] == node_num) {
			return;
		}
	}
	if (state->collision_node_count < ARRAY_SIZE(state->collision_node_nums)) {
		state->collision_node_nums[state->collision_node_count++] =
			node_num;
	}
}

bool adapter_node_num_collided(const struct nodedb_peer_state *state,
			       uint32_t node_num)
{
	for (size_t i = 0U; i < state->collision_node_count; i++) {
		if (state->collision_node_nums[i] == node_num) {
			return true;
		}
	}
	return false;
}

void adapter_nodedb_peer_snapshot(struct lichen_meshtastic_adapter *adapter,
				  uint32_t self_node_num,
				  struct nodedb_peer_state *state)
{
	memset(state, 0, sizeof(*state));
	if (adapter->ops.get_peers == NULL) {
		return;
	}

	state->peer_count = adapter->ops.get_peers(
		state->peers, ARRAY_SIZE(state->peers), adapter->ops.user_data);
	if (state->peer_count > ARRAY_SIZE(state->peers)) {
		state->peer_count = ARRAY_SIZE(state->peers);
	}
	adapter_sort_peers_by_eui64(state);

	for (size_t i = 0U; i < state->peer_count; i++) {
		uint32_t node_num = adapter_peer_node_num(state->peers[i].eui64);

		sanitize_peer_snapshot(&state->peers[i]);
		if (node_num_already_used(state, self_node_num, node_num)) {
			record_collision_node_num(state, node_num);
			state->collision_count++;
			state->omitted_count++;
			continue;
		}
		if (state->emit_count != i) {
			state->peers[state->emit_count] = state->peers[i];
		}
		state->node_nums[state->emit_count++] = node_num;
	}
}

int adapter_local_info(struct lichen_meshtastic_adapter *adapter,
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
	if (!lichen_meshtastic_has_compatible_firmware_brand(info->firmware_version)) {
		info->firmware_version = default_fw;
	}
	if (info->pio_env == NULL || info->pio_env[0] == '\0') {
		info->pio_env = default_env;
	}

	return 0;
}

size_t lichen_meshtastic_adapter_unsupported_operations(
	const struct lichen_meshtastic_adapter_unsupported_operation **operations)
{
	if (operations != NULL) {
		*operations = unsupported_operations;
	}

	return ARRAY_SIZE(unsupported_operations);
}
