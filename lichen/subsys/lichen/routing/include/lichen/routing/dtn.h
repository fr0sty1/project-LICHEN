/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dtn.h
 * @brief DTN store-and-forward buffer (spec section 9.8)
 *
 * Border routers MAY buffer messages for unreachable destinations,
 * delivering when a path appears. Uses absolute TTL (Unix timestamp)
 * and oldest-first eviction when buffer is full.
 *
 * Per spec 9.8:
 * - Max buffer: 64 KB per router
 * - Eviction: Oldest-first when full
 * - Default TTL: 24 hours
 * - Max TTL: 7 days
 */

#ifndef LICHEN_ROUTING_DTN_H
#define LICHEN_ROUTING_DTN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default maximum buffer size in bytes (64 KB per spec 9.8) */
#ifndef CONFIG_LICHEN_DTN_MAX_BYTES
#define CONFIG_LICHEN_DTN_MAX_BYTES 65536
#endif

/** Maximum number of messages in buffer */
#ifndef CONFIG_LICHEN_DTN_MAX_MESSAGES
#define CONFIG_LICHEN_DTN_MAX_MESSAGES 32
#endif

/** Maximum packet size (IPv6 MTU for mesh) */
#ifndef CONFIG_LICHEN_DTN_MAX_PACKET_SIZE
#define CONFIG_LICHEN_DTN_MAX_PACKET_SIZE 1280
#endif

/** Default TTL in seconds (24 hours) */
#define LICHEN_DTN_DEFAULT_TTL_SEC (24 * 60 * 60)

/** Maximum TTL in seconds (7 days) */
#define LICHEN_DTN_MAX_TTL_SEC (7 * 24 * 60 * 60)

/**
 * A message buffered for DTN store-and-forward.
 */
struct lichen_dtn_message {
	/** Packet data buffer */
	uint8_t packet[CONFIG_LICHEN_DTN_MAX_PACKET_SIZE];
	/** Actual packet length */
	uint16_t packet_len;
	/** 8-byte IID of destination */
	uint8_t destination_iid[8];
	/** Unix timestamp when message expires */
	uint32_t expiry_unix;
	/** When message was buffered (monotonic ms for eviction ordering) */
	uint32_t buffered_at_ms;
	/** Entry is valid/in-use */
	bool valid;
};

/**
 * DTN store-and-forward buffer.
 */
struct lichen_dtn_buffer {
	/** Message storage */
	struct lichen_dtn_message messages[CONFIG_LICHEN_DTN_MAX_MESSAGES];
	/** Maximum buffer size in bytes */
	uint32_t max_bytes;
	/** Current buffer usage in bytes */
	uint32_t current_bytes;
	/** Number of valid messages */
	uint16_t count;
};

/**
 * Initialize a DTN buffer.
 *
 * @param buf     Buffer to initialize
 * @return 0 on success, -EINVAL if buf is NULL
 */
int lichen_dtn_init(struct lichen_dtn_buffer *buf);

/**
 * Initialize a DTN buffer with custom max size.
 *
 * @param buf        Buffer to initialize
 * @param max_bytes  Maximum buffer size in bytes
 * @return 0 on success, -EINVAL if buf is NULL
 */
int lichen_dtn_init_with_size(struct lichen_dtn_buffer *buf, uint32_t max_bytes);

/**
 * Buffer a message for DTN store-and-forward.
 *
 * @param buf             DTN buffer
 * @param packet          Packet data to buffer
 * @param packet_len      Length of packet data
 * @param destination_iid 8-byte destination IID
 * @param expiry_unix     Unix timestamp when message expires
 * @param now_unix        Current Unix timestamp
 * @param now_ms          Current monotonic time in ms
 * @return true if buffered, false if rejected (expired, oversized, or buffer full)
 */
bool lichen_dtn_buffer_message(struct lichen_dtn_buffer *buf,
			       const uint8_t *packet,
			       uint16_t packet_len,
			       const uint8_t destination_iid[8],
			       uint32_t expiry_unix,
			       uint32_t now_unix,
			       uint32_t now_ms);

/**
 * Get count of unique destination IIDs with pending messages.
 *
 * @param buf  DTN buffer
 * @return Number of unique destinations
 */
uint16_t lichen_dtn_pending_count(const struct lichen_dtn_buffer *buf);

/**
 * Get list of destination IIDs with pending messages.
 *
 * @param buf      DTN buffer
 * @param iids     Output array for IIDs (8 bytes each)
 * @param max_iids Maximum number of IIDs to return
 * @return Number of IIDs written to array
 */
uint16_t lichen_dtn_get_pending_iids(const struct lichen_dtn_buffer *buf,
				     uint8_t iids[][8],
				     uint16_t max_iids);

/**
 * Check if there are messages pending for a destination.
 *
 * @param buf             DTN buffer
 * @param destination_iid 8-byte destination IID
 * @return true if messages exist for this destination
 */
bool lichen_dtn_has_messages_for(const struct lichen_dtn_buffer *buf,
				 const uint8_t destination_iid[8]);

/**
 * Callback for retrieving messages.
 *
 * @param packet      Packet data
 * @param packet_len  Length of packet
 * @param user_data   User-provided context
 * @return true to continue iteration, false to stop
 */
typedef bool (*lichen_dtn_retrieve_cb)(const uint8_t *packet,
				       uint16_t packet_len,
				       void *user_data);

/**
 * Retrieve and remove all messages for a destination IID.
 *
 * Calls callback for each message, then removes them from buffer.
 *
 * @param buf             DTN buffer
 * @param destination_iid 8-byte destination IID
 * @param callback        Function to call for each message
 * @param user_data       Context passed to callback
 * @return Number of messages retrieved
 */
uint16_t lichen_dtn_retrieve_for(struct lichen_dtn_buffer *buf,
				 const uint8_t destination_iid[8],
				 lichen_dtn_retrieve_cb callback,
				 void *user_data);

/**
 * Remove expired messages from buffer.
 *
 * @param buf       DTN buffer
 * @param now_unix  Current Unix timestamp
 * @return Number of messages expired
 */
uint16_t lichen_dtn_expire_old(struct lichen_dtn_buffer *buf, uint32_t now_unix);

/**
 * Get current buffer size in bytes.
 *
 * @param buf  DTN buffer
 * @return Current usage in bytes
 */
uint32_t lichen_dtn_current_size(const struct lichen_dtn_buffer *buf);

/**
 * Get number of messages in buffer.
 *
 * @param buf  DTN buffer
 * @return Number of valid messages
 */
uint16_t lichen_dtn_len(const struct lichen_dtn_buffer *buf);

/**
 * Check if buffer is empty.
 *
 * @param buf  DTN buffer
 * @return true if no messages are buffered
 */
bool lichen_dtn_is_empty(const struct lichen_dtn_buffer *buf);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_DTN_H */
