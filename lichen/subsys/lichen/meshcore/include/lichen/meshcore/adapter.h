/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHCORE_ADAPTER_H_
#define LICHEN_MESHCORE_ADAPTER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

#include <lichen/meshcore/codec.h>
#include <lichen/meshcore/limits.h>

/**
 * Thread-safety: All adapter functions must be called from a single thread
 * or protected by external synchronization. The adapter is not reentrant.
 * Internal state (pending queue, stream buffer, statistics) is modified
 * without locks or atomics. feed_stream() may be called from ISR/RX thread;
 * emit_text/emit_status/process_raw from application context. Caller must
 * ensure mutual exclusion.
 */

struct lichen_meshcore_compat_settings;

typedef int (*lichen_meshcore_adapter_enqueue_fn)(const uint8_t *_Nonnull frame,
						  size_t len,
						  void *_Nullable user_data);
typedef uint32_t (*lichen_meshcore_adapter_tx_free_fn)(void *_Nullable user_data);
typedef int (*lichen_meshcore_adapter_submit_text_fn)(
	uint8_t channel, uint8_t text_type, const uint8_t *_Nullable to_iid,
	const uint8_t *_Nonnull payload, size_t payload_len, void *_Nullable user_data);
typedef int (*lichen_meshcore_adapter_apply_pin_fn)(uint32_t pin,
						    void *_Nullable user_data);
typedef int (*lichen_meshcore_adapter_persist_settings_fn)(
	const struct lichen_meshcore_compat_settings *_Nonnull settings,
	void *_Nullable user_data);
/*
 * Resolve a MeshCore 6-byte direct-send public-key prefix to one LICHEN peer
 * IID. Return 0 only for an exact single match. Return a negative errno for
 * no match, collision, unavailable peer table, or malformed arguments.
 */
typedef int (*lichen_meshcore_adapter_resolve_peer_prefix_fn)(
	const uint8_t prefix[_Nonnull 6], uint8_t to_iid[_Nonnull 8], void *_Nullable user_data);

#define LICHEN_MESHCORE_ADVERT_NAME_MAX 32U
#define LICHEN_MESHCORE_CHANNEL_BODY_LEN 49U
#define LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN 31U
#define LICHEN_MESHCORE_DEFAULT_FLOOD_KEY_LEN 16U

BUILD_ASSERT(LICHEN_MESHCORE_FRAME_MAX <= UINT16_MAX,
	     "Frame max exceeds uint16_t limit for length fields");

struct lichen_meshcore_compat_settings {
	bool advert_name_valid;
	uint8_t advert_name_len;
	char advert_name[LICHEN_MESHCORE_ADVERT_NAME_MAX];
	bool channel0_valid;
	uint8_t channel0_body[LICHEN_MESHCORE_CHANNEL_BODY_LEN];
	bool autoadd_config_valid;
	uint8_t autoadd_config[2];
	bool default_flood_scope_valid;
	uint8_t default_flood_name[LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN];
	uint8_t default_flood_key[LICHEN_MESHCORE_DEFAULT_FLOOD_KEY_LEN];
	bool device_pin_valid;
	uint32_t device_pin;
};

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
	lichen_meshcore_adapter_submit_text_fn submit_text;
	lichen_meshcore_adapter_apply_pin_fn apply_pin;
	lichen_meshcore_adapter_resolve_peer_prefix_fn resolve_peer_prefix;
	struct lichen_meshcore_compat_settings *_Nonnull compat_settings;
	void *user_data;
	lichen_meshcore_adapter_persist_settings_fn persist_settings;
};

struct lichen_meshcore_adapter_stats {
	uint64_t raw_count;
	uint64_t stream_frame_count;
	uint64_t supported_count;
	uint64_t unsupported_count;
	uint64_t malformed_count;
	uint64_t enqueue_fail_count;
	uint64_t incoming_text_count;
	uint64_t incoming_status_count;
	uint64_t submitted_text_count;
	uint64_t pending_full_count;
	uint64_t pending_drop_count;
	uint64_t waiting_push_fail_count;
};

enum lichen_meshcore_pending_kind {
	LICHEN_MESHCORE_PENDING_TEXT = 1,
	LICHEN_MESHCORE_PENDING_STATUS = 2,
	LICHEN_MESHCORE_PENDING_MAX,
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
	uint8_t tx_buf[LICHEN_MESHCORE_FRAME_MAX];
	uint16_t stream_len;
	uint16_t stream_expected;
	uint8_t pending_head;
	uint8_t pending_tail;
	uint8_t pending_count;
	bool stream_in_frame;
};

void lichen_meshcore_adapter_init(
	struct lichen_meshcore_adapter *_Nonnull adapter,
	const struct lichen_meshcore_adapter_ops *_Nullable ops);
void lichen_meshcore_adapter_reset(struct lichen_meshcore_adapter *_Nonnull adapter);
int lichen_meshcore_adapter_process_raw(
	struct lichen_meshcore_adapter *_Nonnull adapter,
	const uint8_t *_Nonnull frame, size_t len);
int lichen_meshcore_adapter_feed_stream(
	struct lichen_meshcore_adapter *_Nonnull adapter,
	const uint8_t *_Nullable data, size_t len);
int lichen_meshcore_adapter_emit_text(
	struct lichen_meshcore_adapter *_Nonnull adapter,
	const struct lichen_meshcore_incoming_text *_Nonnull event);
int lichen_meshcore_adapter_emit_status(
	struct lichen_meshcore_adapter *_Nonnull adapter,
	const struct lichen_meshcore_incoming_status *_Nonnull event);
const struct lichen_meshcore_adapter_stats *_Nonnull
lichen_meshcore_adapter_get_stats(
	const struct lichen_meshcore_adapter *_Nonnull adapter);
void lichen_meshcore_compat_settings_reset(
	struct lichen_meshcore_compat_settings *_Nonnull settings);

#endif /* LICHEN_MESHCORE_ADAPTER_H_ */
