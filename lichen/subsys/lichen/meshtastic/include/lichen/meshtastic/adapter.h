/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHTASTIC_ADAPTER_H_
#define LICHEN_MESHTASTIC_ADAPTER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#include <lichen/meshtastic/codec.h>
#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_MESHTASTIC_STREAM_HEADER_LEN 4U
#define LICHEN_MESHTASTIC_STATIC_SYNC_FIXED_RECORDS 5U
#define LICHEN_MESHTASTIC_STATIC_SYNC_CONFIG_SECTIONS 9U
#define LICHEN_MESHTASTIC_NODE_SYNC_FIXED_RECORDS 1U
#define LICHEN_MESHTASTIC_CONFIG_COMPLETE_RECORDS 1U
#define LICHEN_MESHTASTIC_STATIC_SYNC_RECORDS \
	(LICHEN_MESHTASTIC_STATIC_SYNC_FIXED_RECORDS + \
	 LICHEN_MESHTASTIC_STATIC_SYNC_CONFIG_SECTIONS)
#define LICHEN_MESHTASTIC_NODE_SYNC_RECORDS(peer_count) \
	(LICHEN_MESHTASTIC_NODE_SYNC_FIXED_RECORDS + (peer_count))
#define LICHEN_MESHTASTIC_FULL_SYNC_RECORDS(peer_count) \
	(LICHEN_MESHTASTIC_STATIC_SYNC_RECORDS + \
	 LICHEN_MESHTASTIC_NODE_SYNC_RECORDS(peer_count) + \
	 LICHEN_MESHTASTIC_CONFIG_COMPLETE_RECORDS)

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
	LICHEN_MESHTASTIC_ADAPTER_PACKET_POSITION_APP,
};

struct lichen_meshtastic_position_snapshot {
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool fix_time_unix_valid;
	uint32_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
	bool location_source_valid;
	uint32_t location_source;
	bool altitude_source_valid;
	uint32_t altitude_source;
	bool gps_accuracy_mm_valid;
	uint32_t gps_accuracy_mm;
	bool precision_bits_valid;
	uint8_t precision_bits;
	bool timestamp_field_valid;
	bool fix_time_rejected_below_epoch_floor;
	bool fix_time_rejected_future;
	uint32_t effective_epoch_floor;
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
<<<<<<< HEAD
=======
	/*
	 * payload points into payload_buf[] (a safe copy of the data from the
	 * ToRadio buffer passed to process_raw/feed_stream). The buffer and
	 * pointer are valid for the full duration of the handle_text() or
	 * handle_location() callback. Callers may retain the pointer or copy
	 * the data; strict lifetime discipline is no longer required.
	 */
>>>>>>> origin/integration/worker9-20260722
	const uint8_t *payload;
	uint8_t payload_buf[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX];
	size_t payload_len;
	uint8_t payload_buf[LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U];
	bool has_from;
	bool has_to;
	bool has_id;
	bool has_channel;
	bool has_portnum;
	bool has_to_peer;
	bool want_ack;
	struct lichen_meshtastic_position_snapshot position;
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
	uint32_t position_packet_count;
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

typedef int (*lichen_meshtastic_adapter_enqueue_fn)(const uint8_t *_Nonnull from_radio,
						    size_t len, void *_Nullable user_data);

typedef int (*lichen_meshtastic_adapter_text_fn)(
	const struct lichen_meshtastic_adapter_packet_info *_Nonnull packet,
	void *_Nullable user_data);
typedef int (*lichen_meshtastic_adapter_location_fn)(
	const struct lichen_meshtastic_adapter_packet_info *_Nonnull packet,
	void *_Nullable user_data);

typedef uint32_t (*lichen_meshtastic_adapter_queue_free_fn)(void *_Nullable user_data);
typedef int (*lichen_meshtastic_adapter_local_info_fn)(
	struct lichen_meshtastic_local_info *_Nonnull info, void *_Nullable user_data);

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
	struct lichen_meshtastic_peer_snapshot *_Nonnull peers, size_t peer_cap,
	void *_Nullable user_data);

struct lichen_meshtastic_adapter_ops {
	lichen_meshtastic_adapter_enqueue_fn enqueue_from_radio;
	lichen_meshtastic_adapter_text_fn handle_text;
	/*
	 * Optional current free-slot hook for enqueue_from_radio. When provided,
	 * WantConfig sync bursts are preflighted before the first record is
	 * enqueued. The hook must report the same queue used by
	 * enqueue_from_radio; it is not a reservation or rollback mechanism, so
	 * stale hook values or later enqueue failures can still leave partial
	 * output (see enqueue_static_sync/enqueue_node_sync). When omitted, the
	 * adapter keeps best-effort degraded semantics: records are enqueued
	 * until enqueue_from_radio fails, and the caller may observe a partial
	 * sync. Re-issue WantConfig to recover. (project-LICHEN-k1tb)
	 */
	lichen_meshtastic_adapter_queue_free_fn queue_free;
	lichen_meshtastic_adapter_local_info_fn get_local_info;
	lichen_meshtastic_adapter_peer_snapshot_fn get_peers;
	void *user_data;
	/*
	 * Total FromRadio queue capacity advertised in queueStatus. Set this to
	 * the same queue measured by queue_free when queue_free is provided.
	 */
	uint32_t queue_maxlen;
	bool heartbeat_queue_status;
	lichen_meshtastic_adapter_location_fn handle_location;
};

/*
 * THREAD SAFETY NOTE (project-LICHEN-9jlb):
 * This adapter's mutable state (stats, stream buffers, from_radio_id,
 * disconnected flag, etc.) is accessed from multiple contexts (RX feed_stream
 * from interrupt or thread, TX emit_* from application thread, stats monitoring).
 * No internal synchronization is provided (the k_mutex is initialized but
 * unused by the implementation). Callers MUST serialize access to all
 * mutating functions. get_stats() and disconnected() are safe for concurrent
 * read-only use. Stats increments are not atomic.
 */

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
	struct k_mutex lock;
};

void lichen_meshtastic_adapter_init(
	struct lichen_meshtastic_adapter *_Nonnull adapter,
	const struct lichen_meshtastic_adapter_ops *_Nullable ops);

void lichen_meshtastic_adapter_reset(struct lichen_meshtastic_adapter *_Nonnull adapter);

int lichen_meshtastic_adapter_process_raw(
	struct lichen_meshtastic_adapter *_Nonnull adapter,
	const uint8_t *_Nonnull to_radio, size_t len);

int lichen_meshtastic_adapter_feed_stream(
	struct lichen_meshtastic_adapter *_Nonnull adapter,
	const uint8_t *_Nonnull data, size_t len);

int lichen_meshtastic_adapter_emit_text(
	struct lichen_meshtastic_adapter *_Nonnull adapter,
	const struct lichen_meshtastic_incoming_text *_Nonnull event);

int lichen_meshtastic_adapter_emit_status(
	struct lichen_meshtastic_adapter *_Nonnull adapter,
	const struct lichen_meshtastic_incoming_status *_Nonnull event);

const struct lichen_meshtastic_adapter_stats *_Nonnull
lichen_meshtastic_adapter_get_stats(
	const struct lichen_meshtastic_adapter *_Nonnull adapter);

bool lichen_meshtastic_adapter_disconnected(
	const struct lichen_meshtastic_adapter *_Nonnull adapter);

/*
 * Return the table of unsupported Meshtastic operations.
 *
 * Sets *operations to point to a static array of operation descriptors and
 * returns the array size. If operations is NULL, just returns the count.
 *
 * Each entry describes an unsupported operation. For entries where has_portnum
 * is true, the portnum field identifies the Meshtastic portnum that triggers
 * this operation. Callers must check has_portnum before using portnum; when
 * has_portnum is false, portnum is unset and the operation is not associated
 * with a specific portnum (e.g., config writes that come via admin commands).
 */
size_t lichen_meshtastic_adapter_unsupported_operations(
	const struct lichen_meshtastic_adapter_unsupported_operation *_Nullable *_Nonnull operations);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_MESHTASTIC_ADAPTER_H_ */
