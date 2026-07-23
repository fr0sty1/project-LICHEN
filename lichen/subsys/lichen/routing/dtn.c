/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dtn.c
 * @brief DTN store-and-forward buffer implementation (spec section 9.8)
 */

#include <lichen/routing/dtn.h>

#include <errno.h>
#include <string.h>

static uint32_t message_size(const struct lichen_dtn_message *msg)
{
	return sizeof(*msg);
}

/**
 * Find the oldest valid message (for eviction).
 */
static int find_oldest(const struct lichen_dtn_buffer *buf)
{
	int oldest_idx = -1;

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		if (!buf->messages[i].valid) {
			continue;
		}
		if (oldest_idx == -1) {
			oldest_idx = i;
			continue;
		}
		/* Wraparound-safe signed diff (assumes <2^31ms span). Smaller = older. */
		int32_t diff = (int32_t)(buf->messages[i].buffered_at_ms -
					 buf->messages[oldest_idx].buffered_at_ms);
		if (diff < 0) {
			oldest_idx = i;
		}
	}

	return oldest_idx;
}

/**
 * Find a free slot for a new message.
 */
static int find_free_slot(const struct lichen_dtn_buffer *buf)
{
	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		if (!buf->messages[i].valid) {
			return i;
		}
	}
	return -1;
}

/**
 * Evict oldest messages to make room for new_size bytes.
 * Returns number of messages evicted.
 * Safety counter prevents any possible infinite loop (e.g. if find_oldest
 * or valid flags are corrupted).
 */
static uint16_t evict_if_needed(struct lichen_dtn_buffer *buf, uint32_t new_size)
{
	uint16_t evicted = 0;
	uint16_t iterations = 0;
	const uint16_t max_iterations = CONFIG_LICHEN_DTN_MAX_MESSAGES + 1;

	while (buf->current_bytes + new_size > buf->max_bytes) {
		if (++iterations > max_iterations) {
			break;
		}
		int oldest = find_oldest(buf);
		if (oldest < 0) {
			break;
		}

		buf->current_bytes -= message_size(&buf->messages[oldest]);
		buf->messages[oldest].valid = false;
		buf->count--;
		evicted++;
	}

	return evicted;
}

int lichen_dtn_init(struct lichen_dtn_buffer *buf)
{
	return lichen_dtn_init_with_size(buf, CONFIG_LICHEN_DTN_MAX_BYTES);
}

int lichen_dtn_init_with_size(struct lichen_dtn_buffer *buf, uint32_t max_bytes)
{
	if (buf == NULL) {
		return -EINVAL;
	}

	memset(buf, 0, sizeof(*buf));
	buf->max_bytes = max_bytes;

	return 0;
}

bool lichen_dtn_buffer_message(struct lichen_dtn_buffer *buf,
			       const uint8_t *packet,
			       uint16_t packet_len,
			       const uint8_t destination_iid[8],
			       uint32_t expiry_unix,
			       uint32_t now_unix,
			       uint32_t now_ms)
{
	if (buf == NULL || packet == NULL || destination_iid == NULL) {
		return false;
	}

	/* Reject already-expired messages */
	if (expiry_unix <= now_unix) {
		return false;
	}

	/* Reject packets that are too large */
	if (packet_len > CONFIG_LICHEN_DTN_MAX_PACKET_SIZE) {
		return false;
	}

	uint32_t msg_size = sizeof(struct lichen_dtn_message);

	/* SECURITY: This check is essential - evict_if_needed() assumes
	 * new_size <= max_bytes. Without this, a message larger than max_bytes
	 * would cause evict_if_needed() to evict all messages and still fail
	 * to make room, wasting buffer contents. */
	if (msg_size > buf->max_bytes) {
		return false;
	}

	/* Evict oldest messages until we have space */
	evict_if_needed(buf, msg_size);

	/* Find a free slot */
	int slot = find_free_slot(buf);
	if (slot < 0) {
		/* No free slots even after eviction - buffer is full of
		 * messages that together fit but no single slot is free.
		 * This shouldn't happen if MAX_MESSAGES is sized correctly. */
		return false;
	}

	/* Store the message */
	struct lichen_dtn_message *msg = &buf->messages[slot];
	memcpy(msg->packet, packet, packet_len);
	msg->packet_len = packet_len;
	memcpy(msg->destination_iid, destination_iid, 8);
	msg->expiry_unix = expiry_unix;
	msg->buffered_at_ms = now_ms;
	msg->valid = true;

	buf->current_bytes += msg_size;
	buf->count++;

	return true;
}

uint16_t lichen_dtn_pending_count(const struct lichen_dtn_buffer *buf)
{
	if (buf == NULL) {
		return 0;
	}

	/* Count unique IIDs - simple O(n^2) since n is small */
	uint16_t count = 0;

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		if (!buf->messages[i].valid) {
			continue;
		}

		/* Check if we've seen this IID before */
		bool seen = false;
		for (int j = 0; j < i; j++) {
			if (buf->messages[j].valid &&
			    memcmp(buf->messages[i].destination_iid,
				   buf->messages[j].destination_iid, 8) == 0) {
				seen = true;
				break;
			}
		}

		if (!seen) {
			count++;
		}
	}

	return count;
}

uint16_t lichen_dtn_get_pending_iids(const struct lichen_dtn_buffer *buf,
				     uint8_t iids[][8],
				     uint16_t max_iids)
{
	if (buf == NULL || iids == NULL || max_iids == 0) {
		return 0;
	}

	uint16_t count = 0;

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES && count < max_iids; i++) {
		if (!buf->messages[i].valid) {
			continue;
		}

		/* Check if we've already added this IID */
		bool seen = false;
		for (uint16_t j = 0; j < count; j++) {
			if (memcmp(buf->messages[i].destination_iid, iids[j], 8) == 0) {
				seen = true;
				break;
			}
		}

		if (!seen) {
			memcpy(iids[count], buf->messages[i].destination_iid, 8);
			count++;
		}
	}

	return count;
}

bool lichen_dtn_has_messages_for(const struct lichen_dtn_buffer *buf,
				 const uint8_t destination_iid[8])
{
	if (buf == NULL || destination_iid == NULL) {
		return false;
	}

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		if (buf->messages[i].valid &&
		    memcmp(buf->messages[i].destination_iid, destination_iid, 8) == 0) {
			return true;
		}
	}

	return false;
}

uint16_t lichen_dtn_retrieve_for(struct lichen_dtn_buffer *buf,
				 const uint8_t destination_iid[8],
				 lichen_dtn_retrieve_cb callback,
				 void *user_data)
{
	if (buf == NULL || destination_iid == NULL) {
		return 0;
	}

	uint16_t retrieved = 0;

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		struct lichen_dtn_message *msg = &buf->messages[i];

		if (!msg->valid) {
			continue;
		}

		if (memcmp(msg->destination_iid, destination_iid, 8) != 0) {
			continue;
		}

		/* Call callback if provided. Callback returns true to continue,
		 * false to stop after this message (per doc in dtn.h:156).
		 * Removal always happens (message is retrieved). */
		bool should_continue = true;
		if (callback != NULL) {
			should_continue = callback(msg->packet,
						   msg->packet_len,
						   user_data);
		}

		/* Remove from buffer */
		buf->current_bytes -= message_size(msg);
		msg->valid = false;
		buf->count--;
		retrieved++;

		if (!should_continue) {
			break; /* stop after processing current (resolves nsw1) */
		}
	}

	return retrieved;
}

uint16_t lichen_dtn_expire_old(struct lichen_dtn_buffer *buf, uint32_t now_unix)
{
	if (buf == NULL) {
		return 0;
	}

	uint16_t expired = 0;

	for (int i = 0; i < CONFIG_LICHEN_DTN_MAX_MESSAGES; i++) {
		struct lichen_dtn_message *msg = &buf->messages[i];

		if (!msg->valid) {
			continue;
		}

		if (msg->expiry_unix <= now_unix) {
			buf->current_bytes -= message_size(msg);
			msg->valid = false;
			buf->count--;
			expired++;
		}
	}

	return expired;
}

uint32_t lichen_dtn_current_size(const struct lichen_dtn_buffer *buf)
{
	if (buf == NULL) {
		return 0;
	}
	return buf->current_bytes;
}

uint16_t lichen_dtn_len(const struct lichen_dtn_buffer *buf)
{
	if (buf == NULL) {
		return 0;
	}
	return buf->count;
}

bool lichen_dtn_is_empty(const struct lichen_dtn_buffer *buf)
{
	if (buf == NULL) {
		return true;
	}
	return buf->count == 0;
}
