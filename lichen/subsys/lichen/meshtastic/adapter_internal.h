/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHTASTIC_ADAPTER_INTERNAL_H_
#define LICHEN_MESHTASTIC_ADAPTER_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
#define MESHTASTIC_PORTNUM_ALERT_APP 11U
#define MESHTASTIC_PORTNUM_KEY_VERIFICATION_APP 12U
#define MESHTASTIC_PORTNUM_REMOTE_SHELL_APP 13U
#define MESHTASTIC_PORTNUM_REPLY_APP 32U
#define MESHTASTIC_PORTNUM_IP_TUNNEL_APP 33U
#define MESHTASTIC_PORTNUM_PAXCOUNTER_APP 34U
#define MESHTASTIC_PORTNUM_STORE_FORWARD_PLUSPLUS_APP 35U
#define MESHTASTIC_PORTNUM_NODE_STATUS_APP 36U
#define MESHTASTIC_PORTNUM_MESH_BEACON_APP 37U
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
#define MESHTASTIC_PORTNUM_POWERSTRESS_APP 74U
#define MESHTASTIC_PORTNUM_LORAWAN_BRIDGE 75U
#define MESHTASTIC_PORTNUM_RETICULUM_TUNNEL_APP 76U
#define MESHTASTIC_PORTNUM_CAYENNE_APP 77U
#define MESHTASTIC_PORTNUM_ATAK_PLUGIN_V2 78U
#define MESHTASTIC_PORTNUM_LORA_OTA_APP 79U
#define MESHTASTIC_PORTNUM_GROUPALARM_APP 112U
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
#define MESHTASTIC_NODEDB_MAX_PEERS CONFIG_LICHEN_MESHTASTIC_NODEDB_MAX_PEERS

struct nodedb_peer_state {
	struct lichen_meshtastic_peer_snapshot peers[MESHTASTIC_NODEDB_MAX_PEERS];
	uint32_t node_nums[MESHTASTIC_NODEDB_MAX_PEERS];
	uint32_t collision_node_nums[MESHTASTIC_NODEDB_MAX_PEERS];
	size_t peer_count;
	size_t emit_count;
	size_t collision_node_count;
	uint32_t collision_count;
	uint32_t omitted_count;
};

/* adapter_parse.c */
int32_t adapter_read_le_i32_twos_complement(const uint8_t bytes[4]);
bool adapter_utf8_is_valid(const uint8_t *data, size_t len);
int adapter_parse_packet(const uint8_t *packet, size_t len,
			 struct lichen_meshtastic_adapter_packet_info *info);

/* adapter_nodedb.c */
uint32_t adapter_peer_node_num(const uint8_t eui64[8]);
void adapter_peer_eui64_to_iid(const uint8_t eui64[8], uint8_t iid[8]);
void adapter_sort_peers_by_eui64(struct nodedb_peer_state *state);
bool adapter_node_num_collided(const struct nodedb_peer_state *state,
			       uint32_t node_num);
void adapter_nodedb_peer_snapshot(struct lichen_meshtastic_adapter *adapter,
				  uint32_t self_node_num,
				  struct nodedb_peer_state *state);
int adapter_local_info(struct lichen_meshtastic_adapter *adapter,
		       struct lichen_meshtastic_local_info *info);

/* adapter_sync.c */
int adapter_enqueue(struct lichen_meshtastic_adapter *adapter,
		    const uint8_t *buf, size_t len);
int adapter_require_queue_space(struct lichen_meshtastic_adapter *adapter,
				uint32_t records);
int adapter_enqueue_static_sync(struct lichen_meshtastic_adapter *adapter,
				const struct lichen_meshtastic_local_info *info);
int adapter_enqueue_node_sync(struct lichen_meshtastic_adapter *adapter,
			      const struct lichen_meshtastic_local_info *info,
			      const struct nodedb_peer_state *state);
int adapter_dispatch_want_config(struct lichen_meshtastic_adapter *adapter,
				 uint32_t nonce);
int adapter_queue_status(struct lichen_meshtastic_adapter *adapter, uint32_t res,
			 const struct lichen_meshtastic_adapter_packet_info *packet);
uint32_t adapter_next_from_radio_id(uint32_t current);

#endif /* LICHEN_MESHTASTIC_ADAPTER_INTERNAL_H_ */
