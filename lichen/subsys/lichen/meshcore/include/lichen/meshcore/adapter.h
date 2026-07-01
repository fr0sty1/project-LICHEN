/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHCORE_ADAPTER_H_
#define LICHEN_MESHCORE_ADAPTER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/meshcore/codec.h>

typedef int (*lichen_meshcore_adapter_enqueue_fn)(const uint8_t *frame,
						  size_t len,
						  void *user_data);
typedef uint32_t (*lichen_meshcore_adapter_tx_free_fn)(void *user_data);

struct lichen_meshcore_incoming_text {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	const uint8_t *payload;
	size_t payload_len;
	bool has_id;
};

struct lichen_meshcore_incoming_status {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_id;
	bool has_error_reason;
};

struct lichen_meshcore_adapter_ops {
	lichen_meshcore_adapter_enqueue_fn enqueue_tx;
	/* Required for handlers that emit multiple response frames atomically. */
	lichen_meshcore_adapter_tx_free_fn tx_free;
	void *user_data;
};

struct lichen_meshcore_adapter_stats {
	uint32_t raw_count;
	uint32_t stream_frame_count;
	uint32_t supported_count;
	uint32_t unsupported_count;
	uint32_t malformed_count;
	uint32_t enqueue_fail_count;
	uint32_t incoming_text_count;
	uint32_t incoming_status_count;
	uint32_t pending_full_count;
	uint32_t pending_drop_count;
	uint32_t waiting_push_fail_count;
};

enum lichen_meshcore_pending_kind {
	LICHEN_MESHCORE_PENDING_TEXT = 1,
	LICHEN_MESHCORE_PENDING_STATUS = 2,
};

struct lichen_meshcore_pending_event {
	enum lichen_meshcore_pending_kind kind;
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	uint16_t payload_len;
	bool has_id;
	bool has_error_reason;
	uint8_t payload[LICHEN_MESHCORE_FRAME_MAX];
};

struct lichen_meshcore_adapter {
	struct lichen_meshcore_adapter_ops ops;
	struct lichen_meshcore_adapter_stats stats;
	struct lichen_meshcore_pending_event pending[
		CONFIG_LICHEN_MESHCORE_PENDING_EVENTS];
	uint8_t stream_header[3];
	uint8_t stream_header_len;
	uint8_t stream_buf[LICHEN_MESHCORE_FRAME_MAX];
	uint16_t stream_len;
	uint16_t stream_expected;
	uint8_t pending_head;
	uint8_t pending_tail;
	uint8_t pending_count;
	bool stream_in_frame;
};

void lichen_meshcore_adapter_init(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_adapter_ops *ops);
void lichen_meshcore_adapter_reset(struct lichen_meshcore_adapter *adapter);
int lichen_meshcore_adapter_process_raw(
	struct lichen_meshcore_adapter *adapter,
	const uint8_t *frame, size_t len);
int lichen_meshcore_adapter_feed_stream(
	struct lichen_meshcore_adapter *adapter,
	const uint8_t *data, size_t len);
int lichen_meshcore_adapter_emit_text(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_incoming_text *event);
int lichen_meshcore_adapter_emit_status(
	struct lichen_meshcore_adapter *adapter,
	const struct lichen_meshcore_incoming_status *event);
const struct lichen_meshcore_adapter_stats *
lichen_meshcore_adapter_get_stats(
	const struct lichen_meshcore_adapter *adapter);

#endif /* LICHEN_MESHCORE_ADAPTER_H_ */
