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
	LICHEN_MESHTASTIC_ADAPTER_PACKET_UNSUPPORTED,
};

struct lichen_meshtastic_adapter_packet_info {
	enum lichen_meshtastic_adapter_packet_kind kind;
	uint32_t id;
	uint32_t portnum;
	const uint8_t *payload;
	size_t payload_len;
	bool has_id;
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
};

typedef int (*lichen_meshtastic_adapter_enqueue_fn)(const uint8_t *from_radio,
						    size_t len, void *user_data);

typedef int (*lichen_meshtastic_adapter_text_fn)(
	const struct lichen_meshtastic_adapter_packet_info *packet,
	void *user_data);

typedef uint32_t (*lichen_meshtastic_adapter_queue_free_fn)(void *user_data);

struct lichen_meshtastic_adapter_ops {
	lichen_meshtastic_adapter_enqueue_fn enqueue_from_radio;
	lichen_meshtastic_adapter_text_fn handle_text;
	lichen_meshtastic_adapter_queue_free_fn queue_free;
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

const struct lichen_meshtastic_adapter_stats *
lichen_meshtastic_adapter_get_stats(
	const struct lichen_meshtastic_adapter *adapter);

bool lichen_meshtastic_adapter_disconnected(
	const struct lichen_meshtastic_adapter *adapter);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_MESHTASTIC_ADAPTER_H_ */
