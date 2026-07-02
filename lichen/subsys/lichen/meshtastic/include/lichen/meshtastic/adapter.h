/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHTASTIC_ADAPTER_H_
#define LICHEN_MESHTASTIC_ADAPTER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <lichen/meshtastic/codec.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_MESHTASTIC_STREAM_HEADER_LEN 4U

enum lichen_meshtastic_adapter_result {
	LICHEN_MESHTASTIC_ADAPTER_DISPATCHED = 0,
	LICHEN_MESHTASTIC_ADAPTER_NEED_MORE = 1,
};

enum lichen_meshtastic_adapter_packet_kind {
	LICHEN_MESHTASTIC_ADAPTER_PACKET_UNKNOWN = 0,
	LICHEN_MESHTASTIC_ADAPTER_PACKET_TEXT_MESSAGE_APP,
	LICHEN_MESHTASTIC_ADAPTER_PACKET_ADMIN_GET_DEVICE_METADATA,
	LICHEN_MESHTASTIC_ADAPTER_PACKET_MALFORMED,
	LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED,
};

struct lichen_meshtastic_adapter_packet_info {
	enum lichen_meshtastic_adapter_packet_kind kind;
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t channel;
	uint32_t portnum;
	uint8_t to_eui64[8];
	uint8_t to_iid[8];
	/*
	 * Points into the ToRadio buffer passed to process_raw/feed_stream.
	 * The pointer is valid only for the duration of handle_text().
	 */
	const uint8_t *payload;
	size_t payload_len;
	bool has_from;
	bool has_to;
	bool has_id;
	bool has_channel;
	bool has_portnum;
	bool has_to_peer;
	bool want_ack;
};

struct lichen_meshtastic_adapter_stats {
	uint32_t heartbeat_count;
	uint32_t want_config_count;
	uint32_t disconnect_count;
	uint32_t packet_count;
	uint32_t text_packet_count;
	uint32_t unsupported_packet_count;
	uint32_t malformed_count;
	uint32_t enqueue_fail_count;
	uint32_t incoming_text_count;
	uint32_t incoming_status_count;
	uint32_t nodedb_peer_collision_count;
	uint32_t nodedb_peer_omitted_count;
};

enum lichen_meshtastic_adapter_unsupported_operation_id {
	LICHEN_MESHTASTIC_UNSUPPORTED_RADIO_CONFIG_WRITE = 0,
	LICHEN_MESHTASTIC_UNSUPPORTED_CHANNEL_CONFIG_WRITE = 1,
	LICHEN_MESHTASTIC_UNSUPPORTED_UNKNOWN_APP = 2,
	LICHEN_MESHTASTIC_UNSUPPORTED_ADMIN_COMMAND = 3,
	LICHEN_MESHTASTIC_UNSUPPORTED_NODEINFO_UPDATE = 4,
	LICHEN_MESHTASTIC_UNSUPPORTED_ROUTING_APP_TO_NODE = 5,
	LICHEN_MESHTASTIC_UNSUPPORTED_COMPRESSED_TEXT = 6,
	LICHEN_MESHTASTIC_UNSUPPORTED_WAYPOINT = 7,
	LICHEN_MESHTASTIC_UNSUPPORTED_AUDIO = 8,
	LICHEN_MESHTASTIC_UNSUPPORTED_DETECTION_SENSOR = 9,
	LICHEN_MESHTASTIC_UNSUPPORTED_REPLY = 10,
	LICHEN_MESHTASTIC_UNSUPPORTED_IP_TUNNEL = 11,
	LICHEN_MESHTASTIC_UNSUPPORTED_PAXCOUNTER = 12,
	LICHEN_MESHTASTIC_UNSUPPORTED_SERIAL = 13,
	LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_HARDWARE = 14,
	LICHEN_MESHTASTIC_UNSUPPORTED_POSITION_UPDATE = 15,
	LICHEN_MESHTASTIC_UNSUPPORTED_TELEMETRY_MODULE = 16,
	LICHEN_MESHTASTIC_UNSUPPORTED_ZPS = 17,
	LICHEN_MESHTASTIC_UNSUPPORTED_SIMULATOR = 18,
	LICHEN_MESHTASTIC_UNSUPPORTED_NEIGHBORINFO = 19,
	LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN = 20,
	LICHEN_MESHTASTIC_UNSUPPORTED_CANNED_MESSAGE_MODULE = 21,
	LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD = 22,
	LICHEN_MESHTASTIC_UNSUPPORTED_TRACEROUTE = 23,
	LICHEN_MESHTASTIC_UNSUPPORTED_RANGE_TEST = 24,
	LICHEN_MESHTASTIC_UNSUPPORTED_MAP_REPORT = 25,
	LICHEN_MESHTASTIC_UNSUPPORTED_PRIVATE_APP = 26,
	LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_FORWARDER = 27,
	LICHEN_MESHTASTIC_UNSUPPORTED_MAX_SENTINEL = 28,
	LICHEN_MESHTASTIC_UNSUPPORTED_ALERT = 29,
	LICHEN_MESHTASTIC_UNSUPPORTED_KEY_VERIFICATION = 30,
	LICHEN_MESHTASTIC_UNSUPPORTED_REMOTE_SHELL = 31,
	LICHEN_MESHTASTIC_UNSUPPORTED_STORE_FORWARD_PLUSPLUS = 32,
	LICHEN_MESHTASTIC_UNSUPPORTED_NODE_STATUS = 33,
	LICHEN_MESHTASTIC_UNSUPPORTED_MESH_BEACON = 34,
	LICHEN_MESHTASTIC_UNSUPPORTED_POWERSTRESS = 35,
	LICHEN_MESHTASTIC_UNSUPPORTED_LORAWAN_BRIDGE = 36,
	LICHEN_MESHTASTIC_UNSUPPORTED_RETICULUM_TUNNEL = 37,
	LICHEN_MESHTASTIC_UNSUPPORTED_CAYENNE = 38,
	LICHEN_MESHTASTIC_UNSUPPORTED_ATAK_PLUGIN_V2 = 39,
	LICHEN_MESHTASTIC_UNSUPPORTED_LORA_OTA = 40,
	LICHEN_MESHTASTIC_UNSUPPORTED_GROUPALARM = 41,
};

struct lichen_meshtastic_adapter_unsupported_operation {
	enum lichen_meshtastic_adapter_unsupported_operation_id id;
	uint32_t portnum;
	bool has_portnum;
};

struct lichen_meshtastic_incoming_text {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	const uint8_t *payload;
	size_t payload_len;
	bool has_id;
};

struct lichen_meshtastic_incoming_status {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_id;
	bool has_error_reason;
};

typedef int (*lichen_meshtastic_adapter_enqueue_fn)(const uint8_t *from_radio,
						    size_t len, void *user_data);

typedef int (*lichen_meshtastic_adapter_text_fn)(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data);

typedef uint32_t (*lichen_meshtastic_adapter_queue_free_fn)(void *user_data);
typedef int (*lichen_meshtastic_adapter_local_info_fn)(
	struct lichen_meshtastic_local_info *info, void *user_data);

/*
 * Copy up to peer_cap peers into peers and return the number copied. The
 * adapter owns sorting, node number collision handling, queue preflight, and
 * defensive string termination for peer names.
 */
struct lichen_meshtastic_peer_snapshot {
	uint8_t eui64[8];
	char long_name[LICHEN_MESHTASTIC_NODE_NAME_MAX];
	uint32_t last_heard_seconds_ago;
	int16_t rssi_dbm;
	int8_t snr_db;
	uint8_t hop_distance;
	bool has_long_name;
	bool has_last_heard_seconds_ago;
	bool has_rssi_dbm;
	bool has_snr_db;
	bool has_hop_distance;
};

typedef size_t (*lichen_meshtastic_adapter_peer_snapshot_fn)(
	struct lichen_meshtastic_peer_snapshot *peers, size_t peer_cap,
	void *user_data);

struct lichen_meshtastic_adapter_ops {
	lichen_meshtastic_adapter_enqueue_fn enqueue_from_radio;
	lichen_meshtastic_adapter_text_fn handle_text;
	lichen_meshtastic_adapter_queue_free_fn queue_free;
	lichen_meshtastic_adapter_local_info_fn get_local_info;
	lichen_meshtastic_adapter_peer_snapshot_fn get_peers;
	void *user_data;
	uint32_t queue_maxlen;
	bool heartbeat_queue_status;
};

struct lichen_meshtastic_adapter {
	struct lichen_meshtastic_adapter_ops ops;
	struct lichen_meshtastic_adapter_stats stats;
	uint8_t stream_buf[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	size_t stream_len;
	size_t stream_expected;
	uint8_t stream_header[LICHEN_MESHTASTIC_STREAM_HEADER_LEN];
	size_t stream_header_len;
	uint32_t from_radio_id;
	bool stream_in_frame;
	bool disconnected;
};

void lichen_meshtastic_adapter_init(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_adapter_ops *ops);

void lichen_meshtastic_adapter_reset(struct lichen_meshtastic_adapter *adapter);

int lichen_meshtastic_adapter_process_raw(
	struct lichen_meshtastic_adapter *adapter,
	const uint8_t *to_radio, size_t len);

int lichen_meshtastic_adapter_feed_stream(
	struct lichen_meshtastic_adapter *adapter,
	const uint8_t *data, size_t len);

int lichen_meshtastic_adapter_emit_text(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_incoming_text *event);

int lichen_meshtastic_adapter_emit_status(
	struct lichen_meshtastic_adapter *adapter,
	const struct lichen_meshtastic_incoming_status *event);

const struct lichen_meshtastic_adapter_stats *
lichen_meshtastic_adapter_get_stats(
	const struct lichen_meshtastic_adapter *adapter);

bool lichen_meshtastic_adapter_disconnected(
	const struct lichen_meshtastic_adapter *adapter);

size_t lichen_meshtastic_adapter_unsupported_operations(
	const struct lichen_meshtastic_adapter_unsupported_operation **operations);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_MESHTASTIC_ADAPTER_H_ */
